# GPU-DMA READ Fix — Deterministic GPU-VA Recovery in probe73

## Symptom

`probe73/gpuread.elf` walks the GPU page tables using the victim buffer's **CPU
virtual address** and assumes `GPU VA == CPU VA` for onion direct memory
(`b->gpu_va = (uint64_t)(uintptr_t)va`). On 13.60 that assumption is broken:

- `gvmspace.start_va == 0x0`, `size == 2^48` — the GPU VM is a full 48-bit
  address space.
- Onion/main direct-memory buffers live at **huge GPU VAs**
  (`0x164000000000`-region), NOT at the CPU userland VA (`0x200200000`) and NOT
  at the `0x2000000000` bus address.

So a VA-keyed walk (`gpu_find_leaf`) resolves the wrong leaf (or none), and the
`DMA_DATA` packet carries a GPU VA that the GPU VM never mapped.

There was a second, independent bug in the CPU walk: `vmspace->vm_pmap` was
dereferenced as a pointer (`pmap = kernel_getlong(vmspace + VM_PMAP_OFF)` then
`cr3 = kernel_getlong(pmap)`), and `pm_cr3` was read at offset 0. The pmap
struct is actually **inline** in `vmspace` at `+0x2E8`, with `pm_cr3` at
`+0x28`.

## Fix (ported from probe76/gpuwrite.elf)

Two functions copied from `probe76/main.c` replace the old `va_to_pa` /
`gpu_find_leaf`:

1. **`cpu_va_to_pa(pml4_pa, va)`** — 4-level x86-64 walk from the *physical*
   PML4 (`pm_cr3`, inline pmap @ `vmspace+0x2E8` + `0x28`, masked `& ~0xFFF`).
   Handles 1 GB / 2 MB / 4 KB leaves.

2. **`gpu_scan_leaf_by_pa(pdb2_va, target_pa, …)`** — scans the sparse GPU
   tables (PDB2/PML4 → PDPT → PD → PTE) for the leaf whose physical-address
   field (`GPU_PTE_ADDR_MASK`) equals `target_pa` (2 MB- or 4 KB-aligned), then
   reconstructs the leaf's GPU VA from the four index levels
   `(i4<<39)|(i3<<30)|(i2<<21)|(i1<<12)`. The PDB2 top level is a **kernel VA**
   (read via `kernel_copyout`); child table pages are linked by **physical**
   address (read via DMAP). Returns the leaf PTE's physical address (`*pte_pa`)
   and raw value (`*pte_val`) so the caller can retarget it.

Wiring in `main()`:

- `pml4_pa` is read from the inline pmap (`pmap = vmspace + VM_PMAP_OFF`).
- `text_pa = cpu_va_to_pa(pml4_pa, TEXT_BASE)`.
- For victim/staging/cmd: `phys = cpu_va_to_pa(pml4_pa, cpu_va)`, then
  `gpu_scan_leaf_by_pa(page_dir_va, phys, …)` to recover `gpu_va` and the
  victim leaf (`leaf_pa`/`leaf_val`).
- `struct gpu_buf` gained `off_t off` (direct-memory offset, used for
  `sceKernelReleaseDirectMemory`); `phys` now holds the CPU physical address,
  `gpu_va` the recovered GPU VA.

## Preserved / unchanged

- `OFFSET_VMSPACE_VM_VMID = 0x1FC`, `OFFSET_DATA_GVMSPACE = 0x2EEA570`.
- READ flow: retarget victim 2 MB leaf to the `.text` page
  (`text_pa & ~0x1FFFFF`), `PACKET3_DMA_DATA` with `src = victim.gpu_va + src_off`
  (`src_off = text_pa & 0x1FFFFF`), `dst = staging.gpu_va`, read staging back.
- `.text` 2 MB-aligned retarget and offset handling unchanged.

## Build

Clean build, no warnings, via ps5-payload-sdk v0.43 (`prospero-clang`, LLVM-18
host toolchain):

```
prospero-clang -Wall -g -I. -c -o main.o main.c
prospero-clang -o gpuread.elf main.o
# -> gpuread.elf: ELF 64-bit LSB pie executable, x86-64
```

## Note

The `cmd` buffer is 4 KB (`0x1000`); its GPU VA is recovered via the 4 KB-PTE
scan path in `gpu_scan_leaf_by_pa`. If a buffer is mapped at block-fragment
granularity (neither 2 MB nor 4 KB), the scan returns `-1` and the probe bails
out cleanly (no panic) rather than guessing.
