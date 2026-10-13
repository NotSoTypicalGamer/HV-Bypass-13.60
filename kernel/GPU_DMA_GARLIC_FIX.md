# GPU-DMA Garlic Fix — probe76 now allocates GPU VRAM (garlic), not onion

**Status:** patched + rebuilt clean (`gpuwrite.elf`, 119,400 B). NOT deployed (console mid-reset).
**Follow-up to:** `GPU_DMA_MEMORY_MODEL.md` §5 (the "onion is still in the gvmspace, medium
confidence" call was wrong) and the 2026-10-06 on-console run whose `gpu_scan_leaf_by_pa` came
back EMPTY for the victim (victim PA `0x47bc00000`, pml4_pa `0x1225a000`, page_dir_va
`0xffffff809e0a0000`, vmid 2, gvmspace `0xffffffff90f1a570`).

## 1. Root cause

`sceKernelAllocateMainDirectMemory(size, size, 1, &off)` allocates from the **onion** (main,
CPU-coherent) pool. On 13.60 the onion buffer is **not** present in the per-VMID `gvmspace`
GPU page tables at any leaf, so the physical-address scan (`gpu_scan_leaf_by_pa`) cannot find
it. The buffer that *is* GPU-mapped is **garlic** (GPU VRAM), so the probe must allocate garlic.

## 2. The exact garlic syscalls (swap applied)

| onion (old) | garlic (new) |
|---|---|
| `sceKernelAllocateMainDirectMemory(len, align, type, &off)` | `sceKernelAllocateDirectMemory(searchStart, searchEnd, len, align, type, &off)` |
| `sceKernelMapNamedDirectMemory(&va, len, prot, flags, off, align, name)` | `sceKernelMapDirectMemory(&va, len, prot, flags, off, align)` |
| `sceKernelReleaseDirectMemory(off, len)` | `sceKernelReleaseDirectMemory(off, len)` (unchanged — generic release) |

New call site (all three buffers, 2 MiB size / 2 MiB alignment, same `PROT_GPU_READ|WRITE`):

```c
p_AllocateDirectMemory(0, DMEM_RANGE_END /*0x400000000*/, 0x200000, 0x200000,
                       DMEM_TYPE_GARLIC /*0xb*/, &off);
p_MapDirectMemory(&va, 0x200000, prot, MAP_NO_COALESCE, off, 0x200000);
```

### memory type constant

`DMEM_TYPE_GARLIC = 0xb` (11). Provenance (PS5-specific, not PS4):

- **Astro Bot (`PPSA21564`)** live `sceKernelAllocateDirectMemory` calls, logged by the prosper
  emulator (`PROSPER_MEMLOG=1`): `range=[0x0,0x400000000) len=0x79800000 align=0x200000 type=0xc`
  and `len=0xc8000000 align=0x10000 type=0xb` — i.e. native PS5 titles allocate VRAM with
  **type 0xb and 0xc** over the 16 GiB pool. (prosper issue #978.)
- **AmprAmm GPU driver** (`sceAmprAmmCommandBufferMap`): the memory type is "constant at 0xb
  across every call; the variable form computes it as 0xb + (x & 7)" — command buffers (which
  the GPU must read) map at type 0xb. (`prosper/src/hle/memory/hle_kernel_mem.cpp`.)

Alternatives if 0xb is refused/empty on-console (all are garlic on PS5): **0xc** (12) and the
PS4-legacy **WC_GARLIC = 3**. The probe bails cleanly on an empty scan, so trying another type
is zero-risk. `DMEM_RANGE_END = 0x400000000` (16 GiB) matches the games' exact search range.

## 3. Page-table walk — verified correct, one latent fix applied

`gpu_scan_leaf_by_pa` checked against the GCN/RDNA GPUVM format (cross-checked with flatz
`gpu.lua`, ps5-linux-loader `gpu.c`, ps5-hen):

- 4-level walk PDB2/PML4 → PDB1/PDP → PDB0/PD → PTB/PTE: **correct**. Level indices 39/30/21/12
  bits, 512 entries/level.
- Constants **all match**: `VALID=bit0`, `IS_PTE=bit54`, `TF=bit56`, `BLOCK_FRAGMENT_SIZE=bits
  59-63 (0x1F)`, `ADDR_MASK=0x0000FFFFFFFFFFC0`.
- PDB2 read via `kernel_copyout(pdb2_va …)` is correct because `gvmspace.page_dir_va` is a
  **DMAP kernel VA** (`0xffffff809e0a0000` = DMAP_BASE + `0x9e0a0000`), not a raw physical; the
  "(PA)" label in the probe's log line is just misleading. Subsequent levels are read via
  `read_phys` (DMAP + physical from `ADDR_MASK`) — correct.
- 2 MiB leaf (`IS_PTE`) and sub-block (PTE) branches both match a 2 MiB-aligned target.

**Fix applied:** the PTE branch reconstructed the leaf GPU VA with a hard-coded 4 KiB shift
(`i1 << 12`). Now it decodes the leaf page size from the PDE's `BLOCK_FRAGMENT_SIZE`
(0→4 KiB, 1→8 KiB, 4→64 KiB) so the VA is correct for non-zero leaf offsets too. For the probe's
2 MiB-aligned buffers the leaf is always at `i1 == 0`, so the result is unchanged — the decode is
robustness, not a behavioral fix for this payload.

**Removed:** the dead `find_gpu_pte()` (its 4 KiB-granularity walk was the old, incorrect path;
it was unused after the scan replaced it and now only produced a `-Wunused-function` warning).

## 4. Build

```
wsl -e bash -lc 'cd /mnt/c/Users/USER/AppData/Local/kex/cache/scratch/ps5/probe76 && \
  PS5_PAYLOAD_SDK=/mnt/c/Users/USER/AppData/Local/kex/cache/scratch/ps5/sdk_v043/ps5-payload-sdk make'
```

Clean — zero warnings, zero errors. Output `gpuwrite.elf` (ELF 64-bit x86-64 PIE, dynamically
linked, ~119 KB).

## 5. Not done / still flagged (unchanged from before)

- **`KDATA_TARGET_OFF` is still `0x0`** — the probe will write to `KERNEL_ADDRESS_DATA_BASE+0`,
  which is NOT safe to run until a real padding/BSS field is chosen from `kdata`. Not touched
  here (out of scope for the garlic swap).
- `DATA_BASE_GVMSPACE=0x2EEA570`, `VMSPACE_VM_VMID=0x1FC`, `KERNPHYSADDR=0x200000` carry over
  unchanged (13.60 values from `HANDOFF.md`).
- **Not deployed.** Deploy on the next `sk` (elfldr, TCP 9021) and watch
  `/data/kex_gpuwrite.txt`: expect `victim: gpu_va=0x164… phys=0x… pte_pa=…` (leaf found) and
  `GPU leaf pa == CPU phys` (no WARN), then the PASS/FAIL write test.
