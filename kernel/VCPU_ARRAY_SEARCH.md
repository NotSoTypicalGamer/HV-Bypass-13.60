# VCPU Array / VMCB-Pointer Search — PS5 13.60 Guest Memory

**Date:** 2026-10-05
**Target:** Hypervisor VCPU array — a repeating array of 16 (or 8) host-physical-address
pointers to VMCBs (8 bytes each, 4KB-aligned, small stride ~0x2000–0x3000).
**Inputs (all offline):**
- 186 sparse 1MB chunks `hvcluster_<hex>.bin` (hex = guest-PA base), guest-PA `0x07d00000`–`0x5ff00000`
- contiguous 608MB dump `hvdump_0x26000000_600MB.bin`, base `0x26000000` → covers `0x26000000`–`0x4C000000`

## Conclusion (short)

**No VCPU/VMCB-pointer array was found in the dumped memory.** Multiple exhaustive scans
(contiguous 8-byte runs + periodic struct arrays up to 256-byte stride, in both pure Python and
NumPy) found zero 8–16-entry arrays of 4KB-aligned host-PA pointers with a constant small stride.

The hypervisor's VCPU array is almost certainly **outside the dumped guest-PA range**. The dumps
cover guest-PA **0x07d00000–0x60000000 (≈1.5 GB)**. The old-firmware VMCB host-PAs
(`0x6290B000` / `0x62A05000` = 1.65 GB) already sit **above** this ceiling, and the task's own
suspected ranges (`0x6xxxxxxx` = 1.6 GB, `0x8xxxxxxx` = 2.1 GB) are also above it.

## Evidence

### 1. Old-firmware VMCB PAs are absent (HV base moved — confirmed)
- Searched for `0x6290B000` and `0x62A05000` across all dumps: **0 occurrences**.
- Consistent with the 8.00+ HV relocation.

### 2. No contiguous VMCB-pointer array
- Exhaustive scan for runs of ≥8 consecutive non-zero 4KB-aligned u64 with a **constant** stride
  in `0x1000–0x10000` (the VMCB signature): **1 hit** in the entire dump set —
  a kernel *page-size table* at guest-PA `0x4923c180` (`0x4000,0x8000,0xC000,…`), not VMCBs.
- Relaxed scan for runs of ≥16 consecutive aligned values with **any** stride, all in host-RAM
  range `0x10000000–0x400000000`: only `0x10000000` DMA-region filler and page-table constants.

### 3. Periodic / struct-array scan (up to 256-byte entries) — near-misses
The only repeating aligned-pointer structures found are **guest-kernel memory-management
structures**, not VMCB pointers:

| Structure | Period | Value pattern | Interpretation |
|---|---|---|---|
| vm_page / page descriptors | 24/48/72/96 B | `{0x8xxxxxxxx phys, 0xfffff1a0… KVAS, 0xfffff1a0… KVAS}` | FreeBSD-style `vm_page` array; phys page frames live at **0x8xxxxxxxx (32–40 GB)** |
| page stacks (see §4) | 8 B | 16× 4KB-aligned `0x2xxxxxxxx` (8.1–8.4 GB), stack/decrementing | guest page-frame stacks, **not** VMCB (decrementing, 8 instances) |
| region map | 16 B | `{base=0x6d9ax000, size=0x4000}` interleaved | `{phys_base, size}` region table, base `0x6d9ac000` (≈1.7 GB) |

### 4. Strongest near-miss: 16-entry 4KB-aligned host-range arrays
Eight arrays of *exactly 16* non-zero 4KB-aligned values, all in `0x10000000–0x400000000`
(8.1–8.4 GB), found at:

```
guest_pa=0x1d265e00  -> 0x2049a7000 .. (stack)
guest_pa=0x346fca00  -> 0x205659000 .. (stack)
guest_pa=0x37d17200  -> 0x207a31000 .. (stack)
guest_pa=0x38ea9e00  -> 0x207afd000 .. (stack)
guest_pa=0x3e018a00  -> 0x20554d000 .. (stack)
guest_pa=0x3eae1e00  -> 0x2055ab000 .. (stack)
guest_pa=0x40ef9400  -> 0x204b8b000 .. (stack)
guest_pa=0x4b1e8000  -> 0x207a8b000 .. (stack)
```

Each is `[base, top, top-0x1000, …, base+0x2000, base+0x1000]` — a **page-frame stack**
(FreeBSD `pmap` page-table-page list or a free-page stack), with values decrementing by `0x1000`.
VMCB arrays on the old fw incremented by `core*0x3000`; a decrementing page stack is not a VMCB
layout, and 8 distinct instances (8×16 = 128 distinct pages) point to page tracking, not to a
single 16-VMCB array.

### 5. Value-range landscape
4KB-aligned non-zero u64 values are dominated by:
- `0x0–0x10000000` (guest low PA, page tables) — 306 k hits
- `0x10000000` repeated (DMA/IOMMU filler)
- `0x8xxxxxxxx` (32–40 GB) — guest physical page frames (vm_page `[0]` field)
- `0xfffff1a0…` / `0xffffffff…` — kernel virtual addresses (KVAS / canonical high)

## What to search instead

**Extend the dump upward.** The current coverage ends at `0x60000000`; the old VMCB region
(`0x62xxxxxx` ≈ 1.65 GB) and the suspected new HV locations (`0x6xxxxxxx`, `0x8xxxxxxx`) are
above it.

Priority guest-PA ranges to dump next:
1. **`0x60000000 – 0x90000000`** (1.5–2.25 GB) — old VMCB PAs + `0x6xxxxxxx`/`0x8xxxxxxx` hints.
2. **`0x800000000 – 0x900000000`** (32–40 GB) — where the guest's physical page frames actually
   live; if the root NPT maps HV physical memory identity-ish and the HV relocated to high
   physical memory, the VCPU array would be here.
3. (Optional) **`0x0 – 0x07d00000`** (low 131 MB) — the currently-uncovered low window.

If the VCPU array is present once those ranges are dumped, look for **16 contiguous 8-byte values,
all 4KB-aligned, all in the same 256MB band, with an *incrementing* stride of `0x2000–0x3000`**.

## Method / artifacts
- `scan_vcpu.py` (pure-Python run scanner), `scan_vcpu2.py` (constant-stride runs),
  `scan_vcpu3.py` (value-band histogram + old-PA search), `scan_vcpu5/6.py` (NumPy periodic scan,
  periods 1–32 u64), `scan_vcpu7.py`/`enum16.py` (≥16 / exact-16 aligned runs).
- JSON results: `vcpu_scan_results.json`, `vcpu_conststride.json`, `vcpu_periodic.json`.
- No network access used; all analysis offline against the local dumps.
