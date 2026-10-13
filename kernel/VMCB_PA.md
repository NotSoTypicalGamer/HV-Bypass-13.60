# VMCB_PA.md — the VMCB physical address on PS5 firmware 8.00–13.60

**Question:** what is the per-core AMD-SVM VMCB physical address (the `VMCB+0x90` NP_ENABLE
target of the COMPLETION_WAIT write) on firmware 8.00–13.60?

**Answer (short):** **not public, and not recoverable offline from `kdata_1360.bin`.** On 8.00+
the hypervisor is a separately-loaded component whose base moved off the old `0x628xxxxx` HV
carve-out, and the 13.60 kernel `.data` dump contains **zero** references into that region. The
VMCB PA must be re-derived from the NPT-aliased HV code once it is dumped (plan in §4).

---

## 1. Every public VMCB PA / derivation (all ≤ 7.61 — none apply to 8.00+)

All public HV-defeat offsets place the hypervisor (code, stacks, PML4, VM table, VMCBs) inside a
physical carve-out at **`0x62800000–0x62B00000`**. Sources: `ps5-linux/ps5-linux-loader`
(`source/offsets.c`, `hv_defeat_0304/0506/0607.c`, `shellcode_0607/main.c`) and
`cragson/ps5-hen` (`hv_defeat.cpp`, `offsets.h`).

| firmware | VMCB PA (per-core) | source |
|---|---|---|
| 3.00–3.21 | `0x6290B000 + core*0x3000` | ps5-hen `hv_defeat.cpp get_vmcb()` |
| 4.00–4.51 | `0x62A05000 + core*0x3000` | ps5-hen `hv_defeat.cpp get_vmcb()` |
| 5.00–5.50 | `0x62A08000 + core*0x2000` | ps5-linux-loader `hv_defeat_0506.c` |
| 6.00–6.02 | `0x62A57000 + core*0x2000` | ps5-linux-loader `hv_defeat_0506.c` |
| 6.50–7.61 | **derived, not fixed** (see §2) | ps5-linux-loader `shellcode_0607/main.c` |

Supporting fixed HV PAs that stay constant through 7.61 (proof the HV has NOT moved on ≤7.61):

| symbol | value | meaning |
|---|---|---|
| `HV_CODE_CAVE_PA` | `0x62806F00` | HV code cave (constant 3.00→7.61) |
| `HV_HANDLE_VMEXIT_PA` | `0x6282CBCB` (3.00–3.21), `0x6282B45D` (4.xx), `0x6282EBD0` (5.0x), `0x6282DFEB` (5.50), `0x62841CE0` (6.0x), `0x62841D50` (6.50), `0x6283D800` (7.0x–7.61) | VMEXIT handler entry |
| `HV_REENTER_HYPERCORE_07xx` | `0x62806380` | HV re-entry point |
| `HV_STACK_TABLE_07xx` | `0x6282E120` | HV per-core stack table |
| `HV_PML4_07xx` | `0x6282E1A0` | **PA holding the HV's own PML4 pointer** |
| `HV_ENTRY_07xx` | `0x6282E1B8` | **PA holding the HV entry pointer** |

## 2. The 6.50–7.61 derivation algorithm (the template for 8.00+)

`shellcode_0607/main.c` does **not** hardcode the VMCB PA — it resolves it from the HV's own page
tables, which is the algorithm that must be reproduced on 8.00+ with the moved anchors:

```c
hv_pml4 = *(u64*)HV_PML4_07xx;                    // read HV's PML4 PA from a fixed PA
hv_base = *(u64*)HV_ENTRY_07xx - HV_MAIN_07xx;    // HV_MAIN_07xx = 0x0E20 (6.50: 0x0F10)
g_vm_tab = vtophys_custom(hv_base + G_VM_TAB_07xx, hv_pml4);   // G_VM_TAB_07xx = 0x27C80 (6.50: 0x23C80)
for (i = 0; i < 16; i++) {
    vc   = vtophys_custom(g_vm_tab[i], hv_pml4);   // vCPU object
    vmcb = vtophys_custom(*(u64*)(vc + 0x08), hv_pml4);   // VMCB pointer at vCPU+0x08
    *(u64*)(vmcb + 0x90) &= ~1;                    // clear NP_ENABLE
}
```

Key invariants (also confirmed by Byepervisor and ps5-hen `HV_VCPU_VMCB_PTR=0x08`):
- **the VMCB pointer lives at `vCPU + 0x08`** (`R14`=vCPU, `[R14+8]`=VMCB).
- the vCPU objects are reachable through the HV's **global VM table** (`g_vm_tab`, 16 entries).
- the HV's **own PML4** (`hv_pml4`) is needed to VA→PA translate these (they are HV-virtual, not
  guest-physical).

So "the VMCB PA" is not a magic number on modern firmware — it is `vtophys(vCPU[i]+0x08, hv_pml4)`,
and the only *fixed* inputs are (a) where the HV's PML4 pointer is stored, and (b) the HV code base.

## 3. Why 8.00+ is not recoverable from what we have (evidence)

Three independent negative results, all verified offline today:

1. **`kdata_1360.bin` holds ZERO references into the old HV region.** A scan for every u64 in
   `0x62800000..0x62B00000` (the entire old carve-out) returns **0 distinct values**. The 13.60
   kernel no longer points at `0x628xxxxx` at all — consistent with the HV being relocated on 8.00+.
2. **No VMCB structure in the dump.** A page-by-page scan of the 15 MB dump for the VMCB
   control-area predicate (`np_enable@0x90 & 1`, `n_cr3@0xB0` 4 KB-aligned, `asid@0x58` in 1..16,
   non-zero intercepts, `cs.selector@0x410` in {0x20,0x28,0x33,0x3B}) yields **0 hits** — the VMCB
   is HV-private memory and is simply not in the kernel `.data`.
3. **The only `vmcb`/`hv_*` strings in the dump are log format strings and CPUID leaf
   `0x8000000A` feature names** (`VmcbClean`, `FlushByAsid`, …) — no data, no pointers.
   The `hv_*` hits are debug-print format strings for the (XOM, ring-0-only) hypercall wrappers
   (`hv_iommu_set_guest_buffers`, `hv_unmap_pt_tmr`, `hv_get_tmr_violation_error`, …).

The physical region table in `.data` (at `0xffffffffd16bfa40`, see `VMCB_DISCOVERY.md §0.3`) only
confirms the *HV/secure/TMR carve-out still exists* as reserved memory (`0x60000000..0x70000000`),
but gives the **reserved-region boundaries, not the VMCB PA**.

The two HV-code dumps in hand are **unusable**:
- `hvcluster_7780.bin` (the `0x77800000` 22-SVM-hit cluster) is **all zeroes** — a failed dump
  (page read as zero; the NPT alias had moved by the time it was pulled).
- `hvcluster_2c7.bin` (5 MB) has median block entropy **6.84** and a zlib ratio 0.76 → compressed
  data, **not** x86 code (the "SVM instructions" are coincidences in compressed bytes).

## 4. Concrete plan to recover the 8.00–13.60 VMCB PA

The 6.50–7.61 algorithm is the exact template. Its only unknown inputs on 8.00+ are the **moved**
anchor PAs (`HV_PML4`, `HV_ENTRY`) and the moved `g_vm_tab` offset — all of which live in the HV's
own memory, reachable only through the Sonic-Iso **root-0 NPT alias** (≤13.60).

1. **Dump the HV code via the NPT alias.** Run `probe67/hvscan3.elf` on a "code-readable" boot
   (dense SVM clusters `0F 01 D8..DF`, ≥3 hits/MB), dumping each dense 1 MB cluster inline before
   any fault page is touched. The HV code/data sit in the guest-visible band just above the
   carve-out (observed 1.86–1.96 GB on one boot, moves per boot). This is the existing lane in
   `HV_RESEARCH.md` / `references/hv-npt-alias.md`.
2. **Offline: locate the new anchors by disassembly.** The dumped HV's init/vcpu-setup code stores
   absolute PAs (its PML4, its entry/stack table, the per-core VMCB bases) exactly like the old HV
   did — the new `HV_PML4`/`HV_ENTRY` equivalent will appear as **literal 4 KB-aligned PAs in the
   0x6xxxxxxx range** (or wherever the new HV image loads). The vCPU array (`g_vm_tab`) is a table
   of 16 pointers and the VMCB pointer at `vCPU+0x08` (invariant) chains to the VMCB PA.
3. **Confirm on-console.** Once the HV's `hv_pml4` and `g_vm_tab` PA are known, read them through
   the DMAP (`DMAP_BASE + pa`), apply `vtophys_custom` (the FreeBSD pmap VA→PA walk over the HV's
   PML4), and read `n_cr3 = *(u64*)(vmcb+0xB0)` to confirm the NPT base.
4. **Fire the write half.** With the real per-core VMCB PA, enqueue the AMD-Vi COMPLETION_WAIT
   (opcode `0x1`, S=1) to store 0 to `VMCB+0x90` (NP_ENABLE), then `vmmcall` on each core to force
   reload (`IOMMU_AUDIT.md`). The IOMMU window bases (`0xffffec8c01130000 + N*0x4000`) are already
   known from the `.data` unit-contexts.

**Fallback if the alias dump only yields code (no HV `.data`):** the HV *executes* `vmrun` with the
VMCB PA in `RAX`, so single-stepping the HV entry (or reading the vCPU array reachable from the HV
code's own global references) still yields the VMCB PA without needing the HV `.data` segment.

## 5. Change log
- 2026-10-05: created. Compiled the complete public VMCB-PA table (3.00→7.61) from
  ps5-linux-loader + ps5-hen; documented the 6.50–7.61 vtophys(vCPU+0x08) derivation as the
  8.00+ template; proved (3 negative scans) that `kdata_1360.bin` holds no VMCB and no reference
  into the old HV region; gave the NPT-alias-dump → disassemble → vCPU-walk recovery plan.
