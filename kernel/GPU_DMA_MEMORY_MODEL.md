# GPU-DMA Memory Model — onion vs garlic, and the correct GPU VA on 13.60

**Scope:** probe76 (`scratch/ps5/probe76/main.c`) walks the GPU page tables
(`gvmspace[vmid].page_dir_va` → PDB2/PML4 → PDPT → PD → PTE) to find a victim
buffer's PTE, retargets it, and issues a `PACKET3_DMA_DATA` write. On 13.60 the walk
fails at the PDPT level (rc=-4) for **both** the CPU VA (`victim_va=0x200200000`) and
the `phys_out` bus address (`victim_off=0x2027a00000`). This doc resolves which address
space and which VA is correct.

---

## TL;DR answers

| Q | Answer | Confidence |
|---|---|---|
| (a) onion or garlic in ps5-hen? | **Onion** (main direct memory) | **high** — all 3 references |
| (b) correct GPU VA on 13.60? | A **huge 48-bit GPU VA** (`0x164000000000`-region), **not** the CPU VA and **not** the `0x2000000000` bus address | **high** (negative + region-table evidence) |
| (c) must allocate garlic instead? | **No** — onion is still in the gvmspace, at a huge VA. The bug is the wrong VA, not the wrong allocation. | medium (see §5) |

**The fix (patched into probe76/main.c):** stop guessing the GPU VA. Compute each
buffer's **physical** address via the CPU page tables, then **scan the GPU page tables
for the leaf PTE whose physical-address field equals it**. That recovers the buffer's
GPU VA deterministically, whatever the region layout is, and self-validates (leaf PA ==
victim PA) before any retarget.

---

## 1. What the references actually walk — onion (main direct memory)

Three independent, working implementations all allocate the *same* thing and walk the
*gvmspace* page tables for it:

- **cragson/ps5-hen `gpu_dma.cpp`** — `sceKernelAllocateMainDirectMemory(size, size, 1, &phys_out)`
  + `sceKernelMapNamedDirectMemory`, then `rel_va = gpu_get_relative_va(vmid, victim_va)`
  (`victim_va − gvmspace.start_va`) and `gpu_walk_pt(vmid, rel_va, …)`.
- **flatz `gpu.lua`** — identical: `alloc_main_dmem()` → `get_ptb_entry_of_relative_va(victim_va)`
  → `get_relative_va(vmid, va)` → `gpu_walk_pt(vmid, relative_va)`.
- **ps5-linux-loader `gpu.c`** — byte-for-byte the same as ps5-hen.

`sceKernelAllocateMainDirectMemory` is the **"main" (onion/system RAM)** pool, not the
garlic pool. So the primitive is built on **onion** memory. The returned `phys_out` is a
**bus address**, not the physical address (see §2).

## 2. Two different address spaces are being conflated

On 13.60 the victim's numbers are:

- CPU userland VA (`sceKernelMapNamedDirectMemory` out): `0x200200000`  — the fixed
  direct-memory **VA window** (base ≈ `0x200000000`).
- `phys_out` (`sceKernelAllocateMainDirectMemory` out): `0x2027a00000` — the **bus
  address** in the `0x2000000000`+ space. On PS4/PS5 that `0x2000000000`-relative space is
  the GPU/garlic **bus** domain; `0x2027a00000 − 0x2000000000 = 0x27a00000` is the
  **onion physical offset** (≈39.7 MB, i.e. right after the kernel image, which loads at
  physical `0x200000` — a sane first allocation).
- The **physical** address (what the GPU PTE's `ADDR_MASK` field actually holds, per
  ps5-hen's `cleared_ptbe = current_ptbe & ~pmap_kextract(victim_va)`): `0x27a00000`
  (0x0-based).

Neither `0x200200000` nor `0x2027a00000` is the GPU VA. `0x2027a00000` has PDPT index 128;
`0x200200000` has PDPT index 8; both are absent from the per-VMID page tables.

## 3. The 13.60 GPU VA space (measured, own console)

From the live `gvmspace_1360_dump.bin` + vmspace dump (see `GVMSPACE_DRIFT_1360.md`,
`GPUVM_OFFSETS_1360_v2.md`):

| gvmspace field | offset | 13.60 value |
|---|---|---|
| `start_va` | `+0x08` | **`0x0`** |
| `size` | `+0x10` | `0x1000000000000` (2⁴⁸, apps VMIDs 2–5) |
| `page_dir_va` | `+0x38` | kernel VA, `0xffffff80a0c98000` + `0x4000`/entry |

So the per-VMID GPU VM is a **48-bit address space [0, 2⁴⁸)** with `start_va = 0`. The
direct-memory regions are mapped at **huge** GPU VAs, per the **direct-memory region
table** (`.data + 0x1D2B00`, `0x28`-byte stride): entries `start_va = 0x164000000000 …`
incrementing by 256 GB, sizes 2 GB / 1 GB / 64 MB (see `DATA_DIFF_761_1360.md` §2,
`GPUVM_OFFSETS_1360.md` §2). `0x164000000000` = 256 GB × 89; the GPU VAs for direct
memory live in this high region, not in the low `0x200000000`/`0x2000000000` ranges the
probe tried.

### Why ≤7.61 worked and 13.60 broke

On the firmwares the references were built against, `gvmspace.start_va` was the base of the
direct-memory VA window, so `victim_va − start_va` collapsed the CPU VA to the direct-memory
offset (the GPU VA). On 13.60 `start_va = 0`, so `victim_va − 0 = victim_va` — a raw CPU VA
that is **not** a mapped GPU VA (the GPU VAs are huge, §3). The probe's "walk the bus
address" fallback is equally wrong: the bus address is not the GPU VA either.

## 4. The correct GPU VA, and how to get it deterministically

Candidate formulae (best guess first) for a buffer at onion physical `p`:

```
GPU VA ≈ 0x164000000000 + p          # region 89 base (0x164000000000) + physical offset
```

(e.g. victim → `0x164000000000 + 0x27a00000 = 0x164027a00000`). This matches the region
table's "256 GB stride / huge VA" signature, but the exact region→physical pairing is
per-boot and not pinned here.

**Therefore the patch does not guess.** It recovers the GPU VA by the one property that is
invariant across onion/garlic and region layout: the GPU leaf PTE's `ADDR_MASK` equals the
buffer's physical address. Algorithm (in `main.c`):

1. `victim_phys = cpu_va_to_pa(victim_va)` via a 4-level x86-64 walk from
   `pmap->pm_cr3` (reach `vmspace` → `pmap` at `VMSPACE_VM_PMAP=0x2e8`, `pm_cr3` @ `+0x28`).
2. `gpu_scan_leaf_by_pa(page_dir_va, victim_phys, …)` — iterate the (sparse) GPU PDB2/PML4
   → PDPT → PD → PTE tables and return the leaf whose `ADDR_MASK == victim_phys` **and** the
   GPU VA of that leaf (reconstructed from the four index levels).
3. Do the same for the staging and cmd buffers.
4. Drive the DMA with the recovered GPU VAs (src=staging, dst=victim, cmd descriptor), and
   retarget the victim leaf as before.

This also *answers* §(c) at runtime: if no leaf matches the victim's physical, onion is
**not** in this VM's gvmspace on that boot and the payload bails with a clear log line
(instead of panicking or silently failing).

## 5. Onion vs garlic — final call

- **ps5-hen/flatz walk onion** (main direct memory), and onion **is** present in the
  per-VMID gvmspace on the firmwares they target (≤7.61). Nothing measured on 13.60 shows
  onion was *removed* from the gvmspace — only that the old "GPU VA = CPU VA / bus address"
  assumption is wrong there.
- **Garlic allocation is therefore not required.** The deterministic fix is the
  physical-address scan (§4). If (and only if) the scan comes back empty for an onion
  buffer, fall back to `sceKernelAllocateDirectMemory` (garlic) — which is mapped in the
  same gvmspace and recovered by the same scan.

## 6. References

- cragson/ps5-hen `gpu_dma.cpp` / `gpu_dma.h`; ps5-linux-loader `source/gpu.c`; flatz `gpu.lua`.
- Local corpus: `GVMSPACE_DRIFT_1360.md` (gvmspace @ `.data 0x2EEA570`, `start_va=0`,
  `size=2^48`), `GPUVM_OFFSETS_1360_v2.md`, `GPUVM_OFFSETS_1360.md` (region table
  `0x164000000000`), `DATA_DIFF_761_1360.md`, `GPU_DMA_WRITE.md`, `GPU_DMA_READ.md`,
  `HANDOFF.md`.
