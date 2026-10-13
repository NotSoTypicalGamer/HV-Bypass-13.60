# GPU-DMA physical-address fix — probe76 (13.60, live-console verified)

**Status:** FIXED + verified on-console. `probe76/gpuwrite.elf` now logs
`victim: gpu_va=0xc80000000 phys=0x34c00000 pte_pa=0x13432800` and `LEAF FOUND`.

The original bug: the probe computed each buffer's physical with `cpu_va_to_pa(va)`
(4-level x86 walk from `pmap->pm_cr3`), got `0x47bc00000` (past 16 GiB), and then
scanned the GPU page tables for a leaf whose `ADDR_MASK == 0x47bc00000`. Nothing
matched. Root cause: the garlic direct-memory CPU VA is a special bus-translated
mapping, NOT a plain x86-mapped VA, so the x86 walk returns a "fake" address and the
physical scan keys on the wrong value.

---

## 1. What was actually wrong (three independent confusions)

| Quantity | Value (13.60, measured) | What it really is |
|---|---|---|
| `victim_va` (from `sceKernelMapDirectMemory`) | `0x200600000` | direct-memory CPU VA **window** (base ≈ `0x200000000`) |
| `victim_off` (from `sceKernelAllocateDirectMemory`) | `0x2027a00000` | **bus address** = `0x2000000000 + 0x27a00000` (onion-style) |
| `cpu_va_to_pa(victim_va)` | `0x47bc00000` | **FAKE** — walking the special direct-memory VA gives garbage > 16 GiB |
| victim garlic physical (from GPU leaf PTE) | `0x34c00000` | the **real** value the GPU leaf's address field holds |

- `off` is **not** the physical (`0x2027a00000` is a bus address).
- `VA - dmap_base` is **meaningless** (the direct-memory VA `0x200600000` is a
  userland VA, not in the DMAP range).
- `cpu_va_to_pa(va)` is **wrong** for the direct-memory VA (returns fake `0x47bc00000`).
- The garlic physical `0x34c00000` is a **separate VRAM address space** — it is NOT
  readable through the CPU DMAP alias (verified: `read_phys(0x34c00000)` does not
  return the buffer contents), so a "pattern-match via DMAP" sanity check also fails.

## 2. The correct 13.60 model (measured)

- `gvmspace[vmid].start_va = 0x0`, `.size = 0x1000000000000` (2^48). The GPU VM is a
  full 48-bit space, so `rel_va = cpu_va - start_va == cpu_va` is **NOT** the GPU VA.
  (This breaks the ≤7.61 `rel_va` formula, where `start_va` was the direct-memory
  window base.)
- The direct-memory (garlic) buffers are mapped at a **fixed high GPU VA base
  `0xc80000000`** (= PDPT index 50). First allocation (victim) → `0xc80000000`,
  then staging `0xc80200000`, cmd `0xc80400000`.
- The GPU page tree is **5 levels for 8 KB leaves**:

```
PDB2 (PML4)  @ page_dir_va (kernel VA 0xffffff809e0a0000, = DMAP VA)
  -> PDB1 (PDPT) @ pml4e & ADDR_MASK          (idx = (gva>>39)&0x1FF)
    -> PDB0 (PD)  @ pdpe & ADDR_MASK          (idx = (gva>>30)&0x1FF)
      -> PTB (64 KB, frag=4) @ pde & ADDR_MASK (idx = (gva>>21)&0x1FF)
        -> 8 KB leaf sub-table (TF bit56 set)  (idx = (gva>>16)&0x1F)
          -> 8 KB leaf PTE                     (idx = (gva>>13)&0x7)
```

- PDE/PTE bit layout (confirmed by dumping the tree):
  - `VALID` bit0, `IS_PTE` bit54 (2 MB leaf), `TF` bit56, frag bits 59–63.
  - Table-pointer `ADDR_MASK` = `0x0000FFFFFFFFFFC0` (bits 6–47).
  - 8 KB leaf physical = bits **13–47** (`0x0000FFFFFFFFE000`); **bit 50 is a flag**
    (VRAM/system), NOT part of the address.
- Measured leaf: `pdb2[0]=0x0000000013430005` → `pdpt[50]=0x0000000013431005` →
  `pd[0]=0x2000000013432005` (frag=4) → PTB `0x13432000` → sub-table `0x13432800` →
  leaf PTE `0x0004000034c00177` ⇒ garlic physical `0x34c00000`.

## 3. The fix (patched into probe76/main.c)

1. **Read `gvmspace[vmid].start_va` (+0x08) and `.size` (+0x10)** and log them.
2. **Walk the GPU tree directly** (5 levels, including the TF/8 KB sub-table), instead
   of scanning by physical address. Collect the leaf at the **lowest GPU VA**
   (`0xc80000000`) = the first allocation = the victim.
3. Recover the victim's physical from the leaf PTE itself: `phys = leaf & 0x0000FFFFFFFFE000`
   (bits 13–47). Do **not** use `cpu_va_to_pa` or `off`.
4. The DMA src/dst and the retarget use the recovered **GPU VA** (`0xc80000000`) and the
   leaf PTE's DMAP VA (`0x13432800`), not the CPU VA.

## 4. Answers to the three original diagnostic questions

1. **What CPU VA does `sceKernelMapDirectMemory` return, and how is it mapped?**
   ~`0x200600000` (direct-memory VA window, base ≈ `0x200000000`). It is a special
   bus-translated direct-memory mapping, **not** a plain x86 pmap mapping — the x86
   walk on it returns a fake `0x47bc00000`.
2. **Is the physical `= off + garlic_base`, or `= VA - dmap_base`?** Neither. The only
   correct source is the GPU leaf PTE's address field (`0x34c00000`). `off`
   (`0x2027a00000`) is a bus address; `VA - dmap_base` is undefined for this VA.
3. **GPU PDB2 dump** (done): `pdb2[0] = 0x0000000013430005` — a single valid PML4 entry.
   The PDE/PTE format matches the documented constants (VALID bit0, IS_PTE bit54,
   TF bit56, frag 59–63, pointer ADDR_MASK bits 6–47), plus the 8 KB leaf physical in
   bits 13–47 with bit 50 = VRAM flag.

## 5. Still open (for the write test, deliberately deferred)

- `KDATA_TARGET_OFF` is still `0x0` — not safe to run the actual GPU write until a real
  padding/BSS `.data` field is chosen. The probe stops after `LEAF FOUND`.
- The tree showed **36 leaves** (≈288 KB of the 2 MB victim) — GPU page-table population
  appears lazy/demand. The 8-byte sentinel only needs the first leaf (`gva 0xc80000000`),
  which is present.
- Fence/sync: the write path still needs the retarget → submit → restore sequence (with
  the victim PTE located at `0x13432800` and garlic physical `0x34c00000`).
