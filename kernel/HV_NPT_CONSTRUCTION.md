# HV_NPT_CONSTRUCTION — NPT-construction path & readable-vs-trapped decision (13.60)

**Date:** 2026-10-05
**Input:** 186 × 1 MB guest-PA chunks at `C:\Users\USER\Caliper-C0re\kernel\hv_dump\hvcluster_<hex>.bin`
(guest-PA range 0x07D00000–0x5FF00000), collected by `probe67/hvscan3.elf`.
**Method:** offline static disassembly only (capstone 5.0.7, x86-64). No console access used.

---

## 1. TL;DR / verdict

**The NPT-construction code — including the bit-58 (`xotext`/NDA) readable-vs-trapped decision —
is NOT present in this dump.** Every global scan for page-table-walking/PTE-writing idioms came
back empty (evidence in §3). The dump is SVM-signature-biased: it captured only the
SVM-instruction-dense *runtime* code (vmrun loop, #VMEXIT dispatch, VMCB setup, a bignum
library), and **missed the boot-time NPT init, which contains no SVM instructions and therefore
never cleared the ≥3-SVM-hits-per-MB filter**.

Consequence for the three questions asked:

- **(a) NPT walk/create code:** not in this dump; cannot be located here.
- **(b) readable (present+R) vs trapped (present+NDA/bit-58) on the HV's own memory:** the
  deciding code is not in this dump. It is a boot-time action, not a runtime toggle (no runtime
  bit-58 manipulation exists anywhere in the dumped runtime code).
- **(c) guest-controllable?** No guest-writable input is referenced by the dumped runtime code
  that would affect it. Consistent with the per-boot "coin-flip" NPT-permission roll already
  recorded in `HANDOFF.md` / `ROOT0_NPT_FLAG.md`: the SL QA flag (`qa_flags[1]&0x02`) is dead on
  8.00+ and no modern flag is public.

To actually see the NPT constructor and the bit-58 decision, the dump must be recollected
**without** the SVM-density filter (full readable-region dump), or by reading the HV's own NPT
structure pages (those pointed to by VMCB `nCR3`). See §6.

---

## 2. What the dump actually contains (characterized, with guest-PA offsets)

186 chunks, 160 unique contents; 27 chunks are byte-identical **all-zero** 1 MB pages (zeroed
scratch/page-table pages). The rest split into real code and data/garbage.

### 2.1 VCPU run loop (`vmrun`) — 6 mirrored chunks, 40 `vmrun` each
Two clusters of ~20 `vmrun` per chunk (the SVM guest-run loop + its exit re-entry):

| chunk base | vmrun cluster 1 | vmrun cluster 2 |
|---|---|---|
| 0x3fd00000 | 0x3fd8ec7e–0x3fd8f928 | 0x3fd9673e–0x3fd973e8 |
| 0x41000000 | 0x4102ac7e–0x4102b928 | 0x4103673e–0x410373e8 |
| 0x43d00000 | 0x43d56c7e–… | 0x43d5e73e–… |
| 0x45700000 | 0x4575ac7e–… | 0x4576673e–… |
| 0x46100000 | 0x46112c7e–… | 0x4611e73e–… |
| 0x46400000 | 0x46496c7e–… | 0x464a273e–… |

The same logical code is re-aliased at 6 guest-PAs (root-0 NPT maps the HV's own pages at
multiple guest-PA aliases). Same for the handler block below.

### 2.2 Intercept / #VMEXIT dispatch (`vmmcall`/`vmsave`/`vmload`/`clgi`/`stgi`)
Dense handler chunks (23 hits/MB) — the VM-exit dispatch + SVM state save/load:

- `vmmcall` handler: 0x2bab8fce (chunk 0x2ba00000), aliases 0x2d4d8fce, 0x2eb80fce, 0x2f5c0fce, …
- `vmload`/`vmsave` clusters: 0x2ba05a0e, 0x2bab081e, 0x2babbc9e, 0x2bab0f8e (chunk 0x2ba00000),
  mirrored into 0x2d400000, 0x2eb00000, 0x2f000000, 0x2f500000.

### 2.3 VMCB / control-structure builder (CPUID-feature-driven) — 0x41001590–0x41001757
This is the only place in the whole dump where any paging-adjacent constant appears:

```
0x41001665: movabs r13, 0x8000000000000000      ; bit 63 (NX)
0x4100166f: or     r13, 0x1200
0x4100167b: mov    qword ptr [rsp-0x50], r13    ; 0x8000000000001200
...
0x41001698: mov    word ptr [r15+r13], 0x1200
0x41001716: movabs r8, 0x8000000000000d         ; bit63 | US | PWT | P
```

Preceding it (0x41001590–0x41001642) is a chain of `or rX, {0x80000,0x100000,0x200000,0x400000,
0x800000,0x1000000,0x2000000,0x4000000}` each gated by `cmp [rsp-0x64/0x60/0x5c], {0x80,0x100,
0x200,3,2,0,1,0}` + `cmovne` — i.e. a feature-bit → control-bit mapping (CPUID-like). This builds
a VMCB/descriptor control word, **not** an NPT entry (no physical-address field, no present bit
for a leaf page, no bit-58).

### 2.4 Bignum library (RSA/ECC-style) — chunk 0x3fd00000
`shrx`/`shlx`/`div` big-integer loops with AVX2 `vpsrlvq`/`vpsllvq`/`vpor` vectorization:

- 0x3fd00a7c / 0x3fd00a81 (scalar shift-or loop), vectorized twin at 0x3fd00c30 (`vpsrlvq`/`vpsllvq`)
- 0x3fd00e80 / 0x3fd00e8e (shift-and-or carry loop)
- 0x3fd01e00 (`div` long-division loop), 0x3fd01ed6 / 0x3fd01f2e (`shlx`/`shrx` + `imul`)

These are the only variable shifts in the dump — they are **crypto/bignum, not page-table walks**.

### 2.5 A single 32-bit table-entry builder (not a page-table walk)
0x3fd03784–0x3fd037ab:

```
shl r12d, 0xc      ; r12 <<= 12
shl r13d, 0x18     ; r13 <<= 24
and r15d, 0xfff    ; page-offset mask
and r12d, 0xfff000 ; page-frame mask
or  r12d, r13d ; or r15d, r12d
mov qword ptr [rax+rcx*8+0x50], r15   ; 32-bit value, zero-extended
```

Constructs a 32-bit `[frame:12][flags:8][offset:12]` value into a per-core table at `+0x50`
(also writes `+0x190`, `+0x210`, `+0x150`, `+0xd0`). This is a 32-bit control/address field in a
per-vCPU structure (TMR/VMCB-adjacent), **not** a 64-bit NPT entry (no phys address in bits
32–51, no present/NDA semantics).

---

## 3. Evidence the NPT-construction code is ABSENT (global scans, all 186 chunks)

Every scan below was run over the full dump (24,379,392 aligned qwords, ~186 MB, linear capstone
disassembly of every chunk):

| searched idiom (why it identifies NPT code) | result |
|---|---|
| `shr reg, {9,12,21,30,39}` (PML4/PDPT/PD/PT level-index shifts) | **0 hits** |
| `and reg, {0x1ff,0x3ff,0x7ff,0xfff,…}` (page-table index masks) | **0 hits** (only 1 `and r15d,0xfff` in the 32-bit builder above) |
| `or/mov [mem], {1,2,3,0x21,0x23,0x27,0x63,0x67,0x83,0x87,…}` (PTE entry writes) | **0 hits** |
| `bts/btr/btc/bt` with immediate bit {0,1,2,5,6,7,11,58,63} | **0 hits** |
| `movabs 0x0400000000000000` (bit-58 NDA/xotext mask) | **0 hits** |
| `movabs 0x8000000000000000` (bit-63 NX) | 1 hit (0x41001665, VMCB builder §2.3) |
| `movabs 0x008000000000000d` | 4 hits (VMCB builder §2.3) |
| `mov cr0/cr3/cr4` (paging enable / root load) | **0 hits** |
| `rep stosq/stosd` (page-table page zeroing) | **0 hits** in coherent code |
| 8-byte-aligned qwords shaped like present page-table entries | only text/data noise (e.g. `0x0074006100720065` = UTF-16 "erat"); no physical-address+flag NPT entries |

The only shifts present are the 32-bit builder (§2.5) and the bignum library (§2.4). A page-table
constructor cannot be written without level shifts and index masks, so its absence is conclusive.

### Why it is missing
`hvscan3.elf` dumps only 1 MB blocks whose SVM-signature density (`0F 01 D8..DF`) is ≥3/MB.
The boot-time NPT constructor is pure memory/page-table manipulation — zero SVM instructions —
so it never triggered the filter and was not saved. The 27 all-zero chunks are almost certainly
the (zeroed) page-table/scratch pages that *would* hold the NPT; their populated entries live in
the "hidden"/trapped region (present-but-no-access → hard panic on read, per HANDOFF.md).

---

## 4. What this means for the readable-vs-trapped decision

- AMD NPT permission model: a **present** entry always permits data **reads** unless **bit 58
  (`NDA`, no-data-access) — the "xotext" bit** — is set (then data reads → #NPF; instruction
  fetch still allowed). So the two observed states are:
  - **readable (lucky boot):** `phys | P | R/W | U/S | A | D` (no bit-58).
  - **trapped (normal boot):** `phys | P | NDA(bit-58)` → read → #NPF → panic.
- The decision "set bit-58 on the HV's own pages" happens **once, at boot, in the missing NPT
  constructor**. The dumped *runtime* code contains **no** code path that sets/clears bit-58 at
  all (no `bts 58`, no bit-58 mask immediate, no bit-58 test), so the readable state cannot be
  toggled after boot by anything the dumped code does.
- Therefore it is **not** a runtime flag check reachable from the guest; it is a boot-time
  decision. This matches the recorded per-boot NPT-permission "coin flip" (fresh-update boot was
  1-of-8 readable; every subsequent cold-boot/re-JB landed trapped).

## 5. Controllability (question c)

- **No guest-writable input controls it.** The dumped runtime code (vmrun loop, dispatch, VMCB
  builder, bignum) references no QA-flag / config value that gates bit-58. Prior work
  (`QA_FLAGS_ROUTE.md`, `ROOT0_NPT_FLAG.md`) established the SL-debug QA flag (`qa_flags[1] bit 1`)
  was the historical "flag checked at NPT construction" but only ever gated *kernel* `.text` XOM
  and is **dead on 8.00+** (HV moved to a separate region in 3.00, no longer reads kernel QA flags).
- The Slopervisor / Sonic-Iso mechanism that makes the HV's own memory guest-visible is
  **unreleased**; the specific trigger for the readable-vs-trapped split is not public and not
  recoverable from this SVM-dense dump.

## 6. To actually find the NPT constructor + bit-58 decision (next steps)

1. **Re-dump without the SVM filter.** Use `probe54/hvdump.elf` (configurable base+size) to dump
   the *whole* confirmed-readable band (liveness-mapped first) instead of only dense clusters, so
   the low-density boot-init/page-table code is captured. Then re-scan for `shr {12,21,30,39}` +
   `and 0x1ff` and `bts 58` / `or imm64 bit-58`.
2. **Read the HV's own NPT pages.** Once VMCB `nCR3` is recovered (VMCB_PA.md lane), walk the
   nested page tables directly and read the actual entries for the HV's own guest-aliased pages —
   the `P|R/W` vs `P|NDA` bit pattern is then observable as *data* even without the constructor.
3. **Target the boot-init region** (the HV's reset/entry code, which does `mov cr3` + page-table
   fill). It is the missing piece; the dump's `mov cr0/cr3/cr4` count of zero is the smoking gun
   that init code was filtered out.

---

## 7. Scripts/artifacts produced (all in `hv_dump/`)

- `scan_svm.py` — SVM-opcode census (1186 hits; per-chunk density; vmrun/dispatch locations).
- `scan_npt.py` / `scan_npt3.py` — bit-58/63/11 `bts`, imm64, `or/and/test/cmp` immediate census.
- `scan_movabs.py` — distinct `movabs` imm64 histogram (18 values; no bit-58 mask).
- `scan_pte.py`, `scan_shifts.py`, `scan_bmi.py` — PTE-write / level-shift / BMI / CR3 scans.
- `scan_pte_entries.py` — aligned-qword page-table-entry shape scan (noise).
- `scan_dedup.py` — chunk hash dedup (160 unique; 27 all-zero identical).
- `dis_windows.py`, `dis_shrx.py` — disassembly evidence for §2.3/§2.4/§2.5.
