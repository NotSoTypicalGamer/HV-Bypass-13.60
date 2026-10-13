# HV_LAYOUT.md — 13.60 hypervisor layout characterization (offline, from hv_dump)

**Date:** 2026-10-05
**Input:** `kernel/hv_dump/hvcluster_<hex>.bin` — 186 × 1 MiB files, filename hex = guest-PA base.
**Method:** offline only — byte/entropy analysis + full iced-x86 disassembly of every chunk.

---

## Bottom line

**The 186 dumped chunks are guest RAM (13.60 FreeBSD kernel code + data + page cache), NOT the
hypervisor.** The `hvscan3.elf` SVM-signature scan (`0F 01 D8..DF`) false-positived on structured
data, so every "dense SVM cluster" it dumped is a data artifact. **No HV code, no HV `.data`, no
VMCB, no NPT pages, and no host-PA literal is present in any chunk.** The HV host-PA base is
therefore **not recoverable from this dump** — see §4 for the single datum that would nail it.

---

## 1. What the chunks actually are (evidence)

### 1.1 The SVM "hits" are data false-positives, not instructions

Disassembling around every `VMRUN/VMCALL/VMLOAD/VMSAVE/STGI/CLGI/SKINIT/INVLPGA` hit shows each
one sits in the middle of a data stream, not a code sequence. Representative (all 86 vmrun/vmcall/
vmload/vmsave sites checked):

```
07da5bb1  add ecx,[rdi-0Ah]      <- nonsense
07da5bb4  (bad)
07da5bb6  mov dl,0EBh
07da5bb8  vmsave                 <- false positive (0F 01 DB)
07da5bbc  or dl,ch
07da5bc1  add al,0EBh
07da5bc7  sbb eax,0F7CE1D20h
```

The same byte pattern repeats at **identical relative offsets** across many chunks (e.g. the
`vmsave` block at +0x5bb8 / +0xc5bb8 / +0xd5bb8 / +0x15bb8 in chunks 0x7d00000, 0x9f00000,
0xcb00000, 0xdc00000, 0xe800000, 0x19a00000, 0x1bc00000, 0x1f200000), proving a repeated **data
table**, not code. The generator is a 16-bit value table — bytes `… d2 00 d4 00 d8 00 3e 01 …`
and `… 0f 01 d8 00 c9 00 d2 00 …` put `0f 01 d8` at arbitrary alignment (a `0x010f`,`0x00d8`
16-bit pair). Same table (small 0x00xx–0x01xx codepoint/offset values) is consistent with a
character-class / case-map table (e.g. an exFAT upcase table).

SKINIT (`0F 01 DE`) appears 72×, STGI 56×, INVLPGA 82×, CLGI 86× — a running HV never executes
SKINIT/INVLPGA at that density scattered through memory; these are the same data-table artifact.

### 1.2 The chunks contain genuine *guest* kernel code and data

- Chunk `0x3fd00000` starts with a FreeBSD syscall-dispatch stub:
  `ret; mov r15d,eax; mov rdi,r14; lea esi,[r15-2]; call …; test eax,eax; jne …`
  (`r15d` = sub-opcode, error-path via `call r13`) — canonical `sys_*` shape, not hypervisor code.
- ASCII strings throughout the 0x6xxxxxxx numeric band of the u64 scan are just English text
  landing in that range (`0x64616572`="read", `0x656c6261`="able", `0x65646f4d`="Mode",
  `0x6e6f6974`="tion", …).
- IEEE754 constants (`0x3f8000003f800000` = 1.0f×2, etc.) and AMD/kernel MSR encodings
  (`0xC0010006…` = MSR_SYSCFG, `0x81000006…`, `0xC0010707…`).
- High-entropy (≈8.0) chunks are page-cache/compressed data, not code.

### 1.3 No host-PA literals anywhere

- `movabs r64,imm64` (48 B8..BF) scan across all 186 chunks: **zero** 4-KiB-aligned immediates in
  `0x60000000..0x70000000` (the HV carve-out). The 4-KiB-aligned movabs immediates that do exist
  are bit-masks / MSR values / FP constants, none in `0x6xxxxxxx`.
- 8-byte little-endian word scan (numpy, every 8-byte window): **zero** values in the old HV
  region `0x62800000..0x62B00000` (16 hits are non-page-aligned coincidences), and no
  4-KiB-aligned `0x6xxxxxxx` pointers. This is the same negative result VMCB_PA.md §3 already
  obtained from `kdata_1360.bin` — the 8.00+ HV is referenced by nothing guest-visible.

---

## 2. Answers to the three questions

**(a) HV host-PA base — NOT recoverable from this dump.**
There are no absolute PA literals and no self-referential code. On ≤7.61 the anchors
(`HV_PML4=0x6282E1A0`, `HV_ENTRY=0x6282E1B8`, VMCB base literals) were absolute PAs inside the
0x628xxxxx carve-out; the 8.00+ equivalent would have appeared here as `0x6xxxxxxx` literals or
as pointer values in an HV `.data` segment. Neither is present.

**(b) VMCB array / NPT (nCR3) root pages — NOT present.**
A VMCB page carries `iopm_base_pa`/`msrpm_base_pa`/`n_cr3` as 4-KiB-aligned `0x6xxxxxxx` host-PAs;
the NPT PML4 (nCR3) is itself a 4-KiB-aligned host-PA. §1.3 shows zero such values exist in the
dump, so neither the VMCB array (base/stride) nor any NPT root page can be read here.

**(c) guest-PA ↔ host-PA alias for this boot — identity for the dumped region; HV alias not
captured.**
Every dumped chunk lies at guest-PA `0x07d00000..0x5ff00000`, i.e. *below* the carve-out top
(`0x60000000`), in normal guest RAM. Reads there go `DMAP_BASE+pa → guest-PA pa → NPT identity →
host-PA pa`, so the chunks are plain RAM, not an NPT alias of HV memory. The HV-code alias that the
Sonic-Iso lead promises would sit at a guest-PA that the NPT maps to a `0x6xxxxxxx` host-PA; on the
previous boot that alias was observed at guest-PA `0x77800000` (22 SVM hits) but dumped all-zero
(failed read). On this boot no such cluster was captured — the scan's only "hits" above and below
the carve-out were the §1.1 data false-positives.

---

## 3. SVM-hit distribution confirms the false-positive picture

Corrected scan (bytes `0f 01` + opcode `D8..DF`), per chunk across all 186 files:

```
0 hits: 27 chunks   3: 45   4: 32   5: 22   6: 3   7: 15   8: 2   9: 7
10: 7   11: 3   12: 4   13: 4   14: 1   15: 2   17: 1   18: 1   20: 1   23: 3   40: 6
```

Heavily peaked at 3–5 hits (just above the scanner's ≥3 threshold) = classic false-positive tail.
A genuine HV code image would show a tight high-density cluster (the previous boot's real signal was
22 hits in one 1 MiB chunk at 0x77800000). The six 40-hit chunks are the repeated 16-bit table, not
code. The 27 zero-hit chunks are all-zero (failed/zeroed reads, the NPT re-rolling mid-scan).

---

## 4. The single datum that would nail the HV host-PA base

Read the **AMD-Vi IOMMU MMIO registers** on-console and record the two host-PA base registers:

| MMIO offset | register | gives |
|---|---|---|
| `+0x00` | **Device Table Base (DTRB)** | host-PA of the IOMMU device table (256 KiB-aligned) |
| `+0x08` | **Command Buffer Base (CBRB)** | host-PA of the IOMMU command buffer (4 KiB-aligned) |

Read at VA `0xffffec8c01130000 + N*0x4000` (N=0..7), single 8-byte `kernel_copyout` reads — no scan,
no panic risk (device MMIO is readable). CBRB/DTRB land inside the HV carve-out (`0x60000000..
0x70000000`), so **either value immediately pins the HV host-PA region**, from which the VMCB array
and NPT pages can be walked (the 6.50–7.61 `vtophys(vCPU[i]+0x08, hv_pml4)` algorithm is the
template once the moved anchors are known). This is approach (1) of `VMCB_DISCOVERY.md`.

Fallback datum: a *genuine* NPT-alias dump on a code-readable boot, using a **stricter** SVM
scanner — require ≥2 SVM opcodes decoded at *valid instruction boundaries* within a tight window
(e.g. 64 B) and reject the 16-bit-table pattern (`…d2 00 d4 00 d8 00…`), instead of a raw
`0F 01 D8..DF` byte count.

---

## 5. Artifacts

- `hv_dump/analyze.py`, `svm_real.py`, `svm_real2.py`, `svm_fix.py`, `vmrun_ctx.py`,
  `u64_scan.py`, `u64_np.py`, `find_6ac4.py` — the offline analysis scripts (iced-x86 + numpy).
- No HV layout values recovered; nothing written to the console.

## Change log
- 2026-10-05: created. Disassembled all 186 chunks; proved the dump is guest RAM and the SVM
  signature false-positived on a repeated 16-bit data table; established the HV host-PA base /
  VMCB / NPT are unrecoverable from it; identified the IOMMU MMIO CBRB/DTRB read as the single
  datum that resolves the host-PA base.
