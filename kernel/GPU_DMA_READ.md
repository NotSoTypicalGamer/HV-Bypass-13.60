# GPU DMA → kernel .text READ primitive (GPUVM bypass of the XOM / "xotext" bit)

**Status:** design + buildable payload written; **NOT yet executed on hardware** (the
build toolchain / LLVM is not present in the analysis environment, so the `.elf` has not
been compiled or run). This is the **READ-direction** sibling of the proven WRITE primitive
in [`GPU_DMA_WRITE.md`](GPU_DMA_WRITE.md) — read that first for the mechanism, constants,
and page-table layout that this document reuses.

**Hypothesis being tested:** the GPU translates its memory accesses through its **own**
page tables (the per-VMID `gvmspace` GPUVM — PDB2/PML4 + PDEs, guest-controllable), **not**
the CPU's NPT/SLAT. The CPU NPT sets the AMD "nda" (no-data-access) bit — **PTE bit 58**,
enabled by `EFER.NDA` bit 16 — on the slid kernel `.text`, so a CPU *data* read of `.text`
faults/panics (and etaHEN `kernel_copyout` returns `−1` zero-fill, no panic — mapped but
unreadable). The same GPUVM path that already bypasses the `.data` **write** protection
should therefore also bypass the `.text` **read** protection: retarget a GPU PTE at the
physical page of kernel `.text`, then issue a PM4 `PACKET3_DMA_DATA` copy with
`src=victim` (PTE → `.text` PA), `dst=staging` (GPU-visible buffer), and read `staging`
back from the CPU.

**Key result up front:** `PACKET3_DMA_DATA` (opcode **`0x50`**) is a symmetric memcpy in
GPU address space. **The READ needs NO different packet** — it is the WRITE path with
`src_va`/`dst_va` swapped. `PACKET3_COPY_DATA` / a compute shader are **not** required.

---

## 1. Why this should work (and the one risk)

- WRITE is proven: on 6.00+ a CPU write to kernel `.data` panics, but a GPU DMA write
  through a retargeted GPU PTE lands cleanly (psdevwiki "Patched: No as of FW 12.00.
  Probably unpatchable"; confirmed 9.00–12.70). The GPUVM is guest/kernel-controlled and
  the HV's CPU-side NPT write-protection does not gate GPU DMA.
- The GPU PTE format (below) has **no "xotext"/nda bit** — only `VALID`/`IS_PTE`/`TF`/
  `BLOCK_FRAG`/address. If the GPU MMU consulted the CPU NPT for `.text`, the READ would
  fault; but the WRITE primitive proves it does not consult the NPT write-protection for
  `.data`. By symmetry it should not consult the NPT nda bit for `.text`.
- **The risk:** if the HV *does* gate GPU DMA reads of `.text` (e.g. via a GPU-side
  protection or the AMD-Vi/IOMMU device table for the GPU), the GPU will raise a fault and
  the kernel may panic. Mitigations built into the payload: read-only until the victim leaf
  PA is verified, `O_SYNC` log heartbeats before the DMA, and a small self-check (leaf PA ==
  victim PA) before any write.

## 2. Constants (identical to the WRITE path — see GPU_DMA_WRITE.md §4)

| Symbol | Value | Meaning |
|---|---|---|
| `GPU_SUBMIT_IOCTL` | `0xC0108102` | `/dev/gc` submit ioctl (16-byte arg) |
| `PM4_TYPE3` | `3` | type-3 packet tag |
| `PM4_OPCODE_DMA_DATA` | `0x50` | PS5 GFX DMA_DATA (stock amdgpu uses `0x32`) |
| `PM4_OPCODE_INDIRECT_BUF` | `0x3F` | indirect-buffer opcode |
| `PM4_SHADER_COMPUTE` | `1` | |
| `PROT_GPU_READ` | `0x10` | direct-mem GPU-read protection bit |
| `PROT_GPU_WRITE` | `0x20` | GPU-write protection bit |
| `PROT_CPU_READ`/`PROT_CPU_WRITE` | `0x01`/`0x02` | CPU protection bits |
| GPU PDE `VALID` | bit 0 | |
| GPU PDE `IS_PTE` | bit 54 | 2 MB leaf if set |
| GPU PDE `TF` | bit 56 | |
| GPU PDE `BLOCK_FRAGMENT_SIZE` | bit 59 | |
| GPU PDE `ADDR_MASK` | `0x0000FFFFFFFFFFC0` | physical-address field (bits 6..47) |
| CPU PTE `PG_V` / `PG_PS` / `PG_FRAME` | `0x001` / `0x080` / `0x000FFFFFFFFFF000` | x86-64 VA→PA walk |

### PM4 type-3 header
```
header = ((3      & 3)     << 30)   // PM4_TYPE3
       | ((5      & 0x3FFF) << 16)   // count-1  (body = 6 dwords -> field = 5)
       | ((0x50   & 0xFF)  << 8)    // opcode DMA_DATA
       | ((1      & 1)     << 1)    // PM4_SHADER_COMPUTE
```

### DMA_DATA packet (READ direction: 7 dwords)
```
pkt[0] = type3 header (opcode 0x50, count-1 = 5)
pkt[1] = dma_hdr: (1<<31) cp_sync
                | (2<<25) dst_cache_policy
                | (1<<27) dst_volatile
                | (2<<13) src_cache_policy
                | (1<<15) src_volatile
pkt[2..3] = src_va   (victim GPU VA + in-leaf offset  ->  .text)
pkt[4..5] = dst_va   (staging GPU VA)
pkt[6]    = length & 0x1FFFFF
```

### `/dev/gc` submission
```
struct gc_submit { u32 pipe_id; u32 count; u64 cmd_buf_ptr; };
ioctl(gc_fd, 0xC0108102, &{pipe_id=0, count=1, cmd_buf_ptr=desc_va})

// 16-byte indirect-buffer descriptor (desc_va points here):
d[0] = ((gpu_addr & 0xFFFFFFFF) << 32) | 0xC0023F00     // 0xC0023F00 = type3 hdr, INDIRECT_BUF
d[1] = ((size_dwords & 0xFFFFF) << 32) | ((gpu_addr >> 32) & 0xFFFF)
```

## 3. Kernel offsets (per-firmware — the two things NOT specified here)

Everything the SDK already exports (`KERNEL_OFFSET_PROC_P_VMSPACE`,
`KERNEL_OFFSET_VMSPACE_VM_PMAP`, `KERNEL_ADDRESS_DMAP_BASE`, `kdata_base_addr`) is used
directly. Two firmware-specific offsets are **not** in the SDK and are **not** pinned here:

| Field | Needed for | Status |
|---|---|---|
| `vmspace->vm_vmid` (u32) | index into the `gvmspace` array | **UNSPECIFIED** — per-firmware; derive from ps5-hen `offsets.c` or a `.data` pattern scan |
| `gbase_vmspaces` (gvmspace array) `.data` offset | the GPUVM PDB2/PML4 base | **UNSPECIFIED** — per-firmware |

These are `OFFSET_VMSPACE_VM_VMID` and `OFFSET_DATA_GVMSPACE` at the top of
`probe73/main.c`. The payload **bails out cleanly (no panic)** if either is 0. All other
gvmspace field offsets are known and hard-coded (from GPU_DMA_WRITE.md, cross-checked
against ps5-hen/flatz):

| gvmspace field | offset |
|---|---|
| `start_va` | `0x08` |
| `size` | `0x10` |
| `page_dir_va` (GPU PDB2/PML4, **physical**) | `0x38` |
| entry stride | `0x100` |

### The two walks

**CPU VA → PA** (to get the physical address of the slid `.text`): 4-level x86-64 walk from
`pmap->pm_cr3` (`FreeBSD amd64 pmap` first field @ 0, reached via
`vmspace + KERNEL_OFFSET_VMSPACE_VM_PMAP`). Only page-table entries are read (they live in
ordinary RAM via the DMAP), never the XOM text — so this is safe.

**GPU VA → leaf PTE** (to find the victim's 2 MB leaf): 4-level GPUVM walk from
`page_dir_va`; `IS_PTE` (bit 54) marks the 2 MB leaf, `ADDR_MASK` holds the physical page.
The victim is allocated **2 MB-aligned** so it lands on a single 2 MB leaf (one PTE
retarget covers 2 MB). Block-fragment (smaller) granularity is **not** implemented — the
walk returns 0 if it hits a non-`IS_PTE` leaf, and the payload aborts.

## 4. The READ transfer (vs WRITE)

| | WRITE (GPU_DMA_WRITE.md) | READ (this payload) |
|---|---|---|
| victim PTE retarget | `.data` PA | `.text` 2 MB page PA |
| mprotect dance | PROT_GPU_READ then PROT_GPU_WRITE | victim stays PROT_GPU_READ (GPU source); staging PROT_GPU_WRITE (GPU dest) |
| DMA_DATA | src=staging, dst=victim | **src=victim, dst=staging** |
| readback | (none) | CPU reads `staging.cpu_va` |

Because the slid text base `0xffffffffcfed0000` is **not** 2 MB-aligned, the payload
retargets the victim's 2 MB leaf at the 2 MB-aligned page **containing** the text base
(`text_pa & ~0x1FFFFF`) and offsets the DMA source by `TEXT_BASE & 0x1FFFFF` (= the PA low
bits; VA/PA share low bits for 2 MB pages). It then reads 1 MB (`READ_SIZE`) from
`victim.gpu_va + off` into `staging`.

**Assumption flagged:** kernel `.text` is physically contiguous and mapped with 2 MB (or
contiguous 4 KB) pages so that the 2 MB physical region aliased by the victim leaf actually
contains the text. FreeBSD amd64 loads the kernel as one contiguous block and maps it with
large pages, so this holds in practice; if it were mapped with scattered 4 KB pages the
2 MB leaf would read surrounding (non-text) RAM for the non-text parts.

## 5. Files

- `C:\Users\USER\AppData\Local\kex\cache\scratch\ps5\probe73\main.c` — the payload
  (builds `gpuread.elf`; logs `/data/kex_gpuread.txt`, writes `/data/kex_gpuread.bin`).
- `C:\Users\USER\AppData\Local\kex\cache\scratch\ps5\probe73\Makefile` — mirrors
  probe72's, pointing at
  `/c/Users/USER/AppData/Local/kex/cache/scratch/ps5/sdk_v043/ps5-payload-sdk`.

## 6. Unspecified / caveats (flagged honestly)

1. **`vmspace->vm_vmid` and `gbase_vmspaces` offsets are per-firmware and not pinned** — the
   payload needs these two values filled in before it can run (see §3).
2. **GPU VA == CPU VA for onion direct memory is assumed**, then **verified at runtime**:
   the payload walks the GPU page tables for `victim.gpu_va` and checks the leaf's
   `ADDR_MASK == victim.phys`. On mismatch it aborts without touching anything. If the
   assumption is wrong on a given firmware, the GPU VA must be recovered by scanning the
   GPU page tables for the leaf whose physical address equals the victim PA (not implemented).
3. **Block-fragment (64 KB / 8 KB) GPU page granularity is not implemented** — only the
   2 MB leaf path. The public writeup does not fully specify the fragment descent.
4. **Fence** is a crude `usleep(500ms)` (ps5-hen uses 100 ms); a proper GNM
   `sceGnmSubmitDone()` fence is TODO. For a read, verify the DMA landed by checking that
   the `0xA5`-filled staging buffer changed.
5. **Alternative submission path** (`sceGnmSubmitCommandBuffers(1, &cmd_gpu_addr,
   &cmd_size_bytes, 0, 0)` + `sceGnmSubmitDone()`, from `libSceGnmDriverForNeoMode.so`) is
   not used here; the raw `/dev/gc` ioctl is self-contained. Both `sceGnmSubmitCommandBuffers`
   and `sceGnmSubmitDone` are exported by the SDK's `libSceGnmDriver.so` stub if the GNM
   route is preferred.
6. **Build toolchain unavailable in the analysis environment** — the SDK's
   `prospero-clang` wrapper requires an external LLVM (`llvm-config`/`clang`) that is not
   installed here (the old `/mnt/c/Users/USER/ps5-hv-research/sdk/...` path referenced by
   probe71/72 no longer exists; only `sdk_v043` with `prospero-lld.exe` is present, no
   `clang`). The code is written to compile against v0.43 headers and libs (all symbols
   used — `sceKernelAllocateMainDirectMemory`, `sceKernelMapNamedDirectMemory`,
   `sceKernelGetDirectMemoryType`, `sceKernelReleaseDirectMemory`, plus the `ps5/kernel.h`
   toolbox — were verified present in `libkernel_web.so`), but **has not been compiled**.

## 7. References

- `GPU_DMA_WRITE.md` (this repo) — WRITE primitive + full constant table + page-table walk.
- `XOM_BYPASS.md` (this repo) — why CPU reads of `.text` fail (nda bit 58, `EFER.NDA` 16).
- ps5-hen (cragson) `gpu.c`/`gpu.h`, vendored in ps5-linux/ps5-linux-loader.
- flatz `gpu.lua` (BD-JB AGC + PM4 `DMA_DATA`), Znullptr `gpu.lua`, tcphdr
  `PS5-Firmware-Spoofer` (`/dev/gc` ioctl), matem6/YarP2JB.
- psdevwiki: `/ps5/Vulnerabilities` §10.1 (SMAP write bypass via GPU DMA), `/ps5/Hypervisor`.
