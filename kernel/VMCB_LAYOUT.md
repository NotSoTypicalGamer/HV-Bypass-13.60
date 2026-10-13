# VMCB_LAYOUT.md — VMCB control-area offsets & bits for the PS5 13.60 HV (NP_ENABLE verification)

**Task:** verify that VMCB+0x90 is NP_ENABLE, pin the exact bit, and enumerate the other
control-area fields the HV writes (intercepts, GMET) needed for a complete NPT-disable sequence.
Method: disassemble the 186-chunk HV dump (`hv_dump/hvcluster_<hex>.bin`) offline.

---

## 0. Verdict (read first)

- **NP_ENABLE is at VMCB control-area offset `0x90`, and it is bit 0.** Confirmed against the AMD
  architectural VMCB layout (AMD APM Vol 2 §C-1 / SVM manual), the Linux KVM `svm.h` definitions,
  the FreeBSD `vmcb.h` offsets already pinned in `VMCB_DISCOVERY.md`, and the historical Sony HV
  (`shellcode_0607`: `*(u64*)(vmcb+0x90) &= ~1`).
- **GMET (Guest Mode Execute Trap) is bit 3 of the SAME +0x90 field.** This is the key new finding
  and it means the single planned COMPLETION_WAIT store of `0` to `VMCB+0x90` clears NP_ENABLE
  (bit 0) **and** GMET (bit 3) in one 8-byte write — exactly the "disable NPT + GMET" action.
- **The 186-chunk dump does NOT contain the HV's VMCB-init / VMRUN-loop code**, so the 13.60 HV's
  layout could not be re-verified from its own disassembly (details in §3). No evidence of a
  non-stock (custom) VMCB layout was found anywhere; every independent source says stock AMD.

---

## 1. NP_ENABLE — offset and bit (the COMPLETION_WAIT target)

| question | answer | evidence |
|---|---|---|
| offset | **`+0x90`** | Barevisor/AMD layout table (`+0x090` = nested-paging enable); KVM `struct vmcb_control_area` places `nested_ctl`/`misc_ctl` immediately after `exit_int_info`@0x88 + `exit_int_info_err`@0x8C, i.e. at 0x90 |
| bit | **bit 0** | `SVM_NESTED_CTL_NP_ENABLE BIT(0)` (KVM `svm.h`); Barevisor "bit 0"; FreeBSD `VMCB_CTRL_NP_ENABLE`; Sony `shellcode_0607` clears bit 0 |
| width | 32-bit field (bits 0..3 defined) | KVM `u64 nested_ctl` (upper 32 reserved); APM defines NP_ENABLE as 32-bit |

Bit layout of the **+0x90** field (KVM `SVM_NESTED_CTL_*`):

| bit | name | meaning |
|---|---|---|
| 0 | **NP_ENABLE** | nested paging enable (the NPT-disable target) |
| 1 | NP_SEV | SEV enable (unused on PS5) |
| 2 | NP_SEV_ES | SEV-ES enable (unused on PS5) |
| 3 | **GMET** | Guest Mode Execute Trap (XOM execute-enforcement) |

---

## 2. GMET — the other field that matters for a complete disable

GMET (Guest Mode Execute Trap) is **AMD's "Mode-Based Execute Control"** (Zen 2+; the AMD analogue
of Intel MBEC). It is **not a separate VMCB offset** — it is **bit 3 of the same +0x90 field as
NP_ENABLE**. Evidence:

- KVM `svm.h`: `#define SVM_NESTED_CTL_GMET_ENABLE BIT(3)` sits directly under `NP_ENABLE BIT(0)`,
  `SEV_ENABLE BIT(1)`, `SEV_ES_ENABLE BIT(2)`.
- KVM `init_vmcb()`: `control->misc_ctl |= SVM_MISC_ENABLE_GMET;` (same field that gets
  `SVM_MISC_ENABLE_NP`).
- CPUID `0x8000000A` EDX bit 13 reports GMET; the 13.60 kernel's SVM-revision string enumerates it
  (`DATA_DIFF_761_1360.md`: "SVM rev bits (…VmcbClean…GMET…)"). GMET is the XOM enforcement
  primitive (`HANDOFF.md`: "Guest-Mode Execute Trap … blocks allocating/running new kernel code").

Mechanically GMET changes **NPT PTE** semantics (it repurposes the NPT "U/S" bit 62 so that, with
NX=0, U=0 = executable by user+supervisor and U=1 = executable by user only; a supervisor fetch of
a user-only page traps). It therefore only has effect **while nested paging is on** — clearing
NP_ENABLE (bit 0) removes the NPT, which removes GMET enforcement automatically; clearing GMET
(bit 3) too is belt-and-braces and matches what Byepervisor's ROP chain did ("disable NPT + GMET").

**Complete NPT-disable sequence implication:** one COMPLETION_WAIT storing `0` to `VMCB+0x90`
zeroes bits 0..3 (NP_ENABLE, SEV, SEV-ES, GMET) in a single 8-byte store. No second write is
required to a GMET field. `nCR3`@0xB0 becomes irrelevant once NP_ENABLE is cleared.

---

## 3. Full VMCB control-area layout (AMD architectural — the offsets the HV writes)

Control area = first 0x400 bytes of the 4 KB-aligned VMCB; guest-state (save) area = 0x400..0xFFF.

| offset | size | field | note |
|---|---|---|---|
| 0x000 | 4 | intercept_cr | CR read/write intercepts |
| 0x004 | 4 | intercept_dr | DR intercepts |
| 0x008 | 4 | intercept_exception | exception vector intercept bitmap |
| 0x00C | 4 | intercept_inst1 | instr intercepts #1 (e.g. CPUID bit 18, VMMCALL, …) |
| 0x010 | 4 | intercept_inst2 | instr intercepts #2 (VMRUN bit 0, VMLOAD/VMSAVE/STGI/CLGI/INVLPGA) |
| 0x014 | — | reserved | (0x014..0x03F) |
| 0x040 | 8 | iopm_base_pa | I/O permission map PA (12 KB) |
| 0x048 | 8 | msrpm_base_pa | MSR permission map PA (8 KB) |
| 0x050 | 8 | tsc_offset | TSC offset |
| 0x058 | 4 | asid | guest ASID (1..N) |
| 0x05C | 4 | tlb_ctrl | TLB flush control (0/1/3/7) |
| 0x060 | 4 | v_intr_ctrl | virtual interrupt control (V_IRQ, V_INTR_MASKING…) |
| 0x068 | 8 | interrupt_shadow | interrupt shadow |
| 0x070 | 8 | exitcode | #VMEXIT reason (written by CPU) |
| 0x078 | 8 | exitinfo1 | exit info 1 |
| 0x080 | 8 | exitinfo2 | exit info 2 (faulting GPA on #NPF) |
| 0x088 | 4 | exitintinfo | exit interrupt info |
| **0x090** | 4 | **np_enable / misc_ctl** | **bit0 NP_ENABLE, bit1 SEV, bit2 SEV-ES, bit3 GMET** |
| 0x098 | 8 | event_inj | event injection (EVENTINJ) |
| **0x0B0** | 8 | **n_cr3** | **nested page table base (NPT PML4 PA)** — the value `nptwalk` wants |
| 0x0C0 | 4 | vmcb_clean | VMCB clean bits |
| 0x0C8 | 8 | next_rip | nRIP (next instruction RIP) |

`VMCB_OFF_STATE(x) = x + 0x400` for the save area (CS.sel@0x410, EFER@0x4D0, CR3@0x550,
CR0@0x558, RIP@0x578, RSP@0x5D8 …) per `VMCB_DISCOVERY.md §0.1`.

---

## 4. Disassembly of the 186-chunk dump — what was actually found (verified negative)

I disassembled the dump offline (Capstone 5.0.7, x86-64). Result: **the dump is not disassemblable
HV code.** Specifically:

- **1186 SVM byte-hits** (`0F 01 D8..DF`) were all **false positives** — disassembling a window
  around each produced garbage context (`fdivr`, `iretd`, `int3`, `.byte`…) with the SVM mnemonic
  landing in the middle of junk, not in a coherent VMRUN/VMSAVE sequence.
- **Entropy:** 27 chunks all-zero (failed reads); ~130 chunks at entropy 3.8–7.4 (structured
  data / RAM); 16 chunks at 7.9–8.0 (compressed/encrypted). No chunk sits in the clean-x86-code
  band. Hexdumps of representative chunks show data/random bytes, not opcode streams.
- **No VMCB-init store exists in the dump.** A byte-exact search for `mov dword [reg+0x90], 1`
  (the canonical "NP_ENABLE = 1") and `or [reg+0x90], 1` returns **0 hits** across all 186 MB.
  All stores to `[reg+0x90]` that do exist write `0` or unrelated values in non-VMCB contexts.
- **Scattered clean code exists but is not HV VMCB code.** E.g. `hvcluster_3f800000.bin` contains
  a real structure-init loop (stride `0xa0`): `mov qword [r15+0x88],0; mov qword [r15+0x90],0xf;
  …; add r15,0xa0`. The `0xf` at +0x90 there is a 0xa0-stride structure's field, **not** a VMCB
  NP_ENABLE write (VMCB is 4 KB, and the surrounding offsets +0x78/+0x88/+0x98 don't match the
  VMCB control area).

**Conclusion for the write primitive:** the +0x90/bit-0 target stands on the architectural layout
and the ≤7.61 Sony-HV evidence; the 13.60 dump could not add independent confirmation because it
does not contain the HV's VMCB-init or VMRUN-loop code. This is consistent with the earlier dump
history in `VMCB_PA.md` (`hvcluster_7780.bin` all-zeroes, `hvcluster_2c7.bin` compressed data) —
the dump-on-sight scanner's "dense SVM clusters" are not reliably the HV code image. If the HV's
own VMCB-init code is wanted, the dump must be re-taken from a code-readable boot and the clusters
validated by *clean disassembly* (≥3 consecutive valid instructions around each `vmrun`), not by
SVM byte-density alone.

---

## 5. Custom-layout check

- No evidence of a Sony-specific VMCB layout. The ≤7.61 HV used the stock AMD offsets
  (`vCPU+0x08` → VMCB, `vmcb+0x90` NP_ENABLE, `vmcb+0xB0` nCR3). The 13.60 kernel's own strings
  enumerate only standard AMD SVM revision features (`VmcbClean`, `GMET`, …).
- **GMET is not a Sony invention** — it is AMD's standard feature (CPUID `0x8000000A` EDX bit 13,
  MBEC analogue), bit 3 of the standard +0x90 field. Earlier workspace notes treated it as opaque;
  it is not a custom VMCB extension.

---

## 6. Sources

- AMD SVM/APM Vol 2 — VMCB layout (Table C-1) and VMRUN semantics (0x04.net mirror of AMD 33047).
- Linux KVM `arch/x86/kvm/svm/{svm.c,svm.h,nested.c}` — `SVM_NESTED_CTL_NP_ENABLE BIT(0)`,
  `SVM_NESTED_CTL_SEV_ENABLE BIT(1)`, `SVM_NESTED_CTL_SEV_ES_ENABLE BIT(2)`,
  `SVM_NESTED_CTL_GMET_ENABLE BIT(3)`; `init_vmcb()` `control->misc_ctl |= SVM_MISC_ENABLE_GMET`.
- Wikipedia "Second Level Address Translation" — MBEC/GMET (AMD Zen 2, GMET = MBEC analogue).
- Workspace: `VMCB_DISCOVERY.md` (FreeBSD vmcb.h offsets), `VMCB_PA.md` (shellcode_0607 derivation),
  `COMPLETION_WAIT_PLAN.md` (write encoding), `DATA_DIFF_761_1360.md` (GMET enumerated),
  `XOM_BYPASS.md` / `ROOT0_NPT_FLAG.md` (XOM = NPT xotext bit 58 + GMET enforcement).
