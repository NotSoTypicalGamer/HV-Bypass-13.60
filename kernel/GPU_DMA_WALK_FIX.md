# GPU-DMA Walk Fix — Correct GPU VA for Onion/Main Direct Memory

## Symptom

probe76/gpuwrite.elf reaches the GPU page-table walk with the *correct* context:

- `vmid = 2` (VMSPACE_VM_VMID @ vmspace+0x1FC) — correct.
- `page_dir_va = 0xffffff8097aa0000` (gvmspace[2]->page_dir_va @ +0x38) — correct.

but `find_gpu_pte()` returns **rc = -4**: the PDPT (PDB1) entry at `pdpe_idx` is not
VALID for the input GPU VA `0x201000000`.

Walk indices for `0x201000000`:

```
pml4e_idx = (0x201000000 >> 39) & 0x1FF = 0   -> PDB2 entry VALID (read OK)
pdpe_idx  = (0x201000000 >> 30) & 0x1FF = 8   -> PDPT[8] NOT VALID  -> rc=-4
```

## Root cause

The walk input is the **wrong address**. probe76 walks the **CPU userland VA**
(`victim_va = 0x201000000`, the value returned by
`sceKernelMapNamedDirectMemory`). The GPU's per-VMID page tables (`gvmspace`)
for onion/main direct memory are indexed by the **physical offset (bus address)**
returned by `sceKernelAllocateMainDirectMemory` — **not** the CPU VA.

## Cross-check against the references

All three reference implementations walk a *translated* VA:

1. **cragson/ps5-hen `gpu_dma.cpp`**
   ```c
   rel_va = gpu_get_relative_va(vmid, victim_va);
   gpu_walk_pt(vmid, rel_va, &page_size);
   ```
2. **ps5-linux-loader `gpu.c`** — byte-for-byte the same `gpu_get_relative_va` +
   `gpu_walk_pt`.
3. **flatz `gpu.lua`** — `get_ptb_entry_of_relative_va(virt_addr)` →
   `get_relative_va(vmid, va)` → `gpu_walk_pt(vmid, relative_va)`.

`gpu_get_relative_va` / `get_relative_va` is:

```c
if (va >= start_va && va < start_va + size)
    return va - start_va;      // start_va/size from gvmspace +0x08/+0x10
return (uint64_t)-1;
```

i.e. **GPU VA = CPU VA − `start_va`**. On the firmware these references were
developed against, `gvmspace.start_va` was the CPU base VA of the direct-memory
region (≈ `0x200000000`), so `va − start_va` reduced the CPU VA to the
direct-memory **physical offset** — which is the GPU (bus) address of onion
memory.

## Why 13.60 breaks the old formula

On 13.60 the `gvmspace.start_va` field is **0x0**, so `gpu_get_relative_va`
returns `va` unchanged (`0x201000000`). That raw CPU VA is **not a mapped GPU
VA** (its PDPT entry is absent), hence rc=-4. The physical offset is still the
correct GPU VA — it can just no longer be derived as `victim_va − start_va`. It
must be taken **directly** from the `off`/`phys_out` out-parameter of
`sceKernelAllocateMainDirectMemory`.

## The correct GPU VA

> **GPU VA for onion/main direct memory == the physical offset
> (`off`/`phys_out`) returned by `sceKernelAllocateMainDirectMemory`.**

For the victim buffer: walk `victim_off`, not `victim_va`.

## Fix applied to probe76/main.c

1. **Walk** — `find_gpu_pte(page_dir_va, (uint64_t)victim_off, ...)`
   (was `(uintptr_t)victim_va`).
2. **DMA_DATA dst** — `(uint64_t)victim_off` (was `victim_va`). The retargeted
   PTE is keyed on the GPU VA we walked, so the copy destination must be that
   same GPU VA.
3. **DMA_DATA src** — `(uint64_t)staging_off` (was `staging_va`).
4. **Submission descriptor cmd-buffer GPU address** — `(uint64_t)cmd_off`
   (was `cmd_va`).

The `mprotect(victim_va, …)` calls are **left on the CPU VA** — they are CPU-side
syscalls that also invalidate the GPU TLB for the corresponding GPU mapping; only
the GPU-side address arithmetic changes.

## Sanity check

`victim_real_pa = pte_val & GPU_ADDR_MASK` must equal `victim_off`. A `WARN` is
emitted if it does not, since that would indicate the GPU VA is not (or is no
longer) the identity-mapped physical offset.
