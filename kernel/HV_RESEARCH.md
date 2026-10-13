# HV Research — hypervisor lane (13.60)

**Goal:** on the 13.60 console, locate and analyze the hypervisor (the AMD SVM secure monitor that
enforces XOM, blocks code patches, and intercepts CR0.WP/CR4.SMEP).

**Status:** not started — blocked on the 7.61 → 13.60 update + re-jailbreak (Relapse supports
7.00–13.60).

## The lead (from Sonic-Iso, 2026-10-05)

> "root-0 NPT no longer maps the hypervisor's own physical memory" — patched in 14.10.

Meaning: on firmware **≤ 13.60 (and 14.00?), the guest kernel's nested page table (NPT) maps the
hypervisor's own physical pages.** So a process with kernel R/W can reach the HV's memory through
the guest's physical address space — read it, and (per the Slopervisor/Byepervisor lineage) patch it.
14.10 removed the HV's pages from the root-0 NPT, killing that door.

This is the primitive to exploit on 13.60: the HV's memory is guest-visible via the NPT.

## Plan (once 13.60 is JB'd)

1. Get kernel R/W (Relapse → elfldr → a payload).
2. Walk the NPT (the guest's nested page table / the SVM paging structures) to enumerate the
   guest-physical mappings that alias the HV's own memory.
3. Identify the HV's physical range (the HV code + data) via those aliases.
4. Dump it (kernel R/W → the aliased physical pages).
5. Static-analyze the HV (Ghidra, AMD64 SVM): the VMCB setup, the intercept handlers, the
   XOM/CR0.WP/SMAP enforcement paths — hunting a new HV primitive that survives 14.10.

## How the HV defeat was already achieved (public methods)

| firmware | method | mechanism |
|---|---|---|
| 1.00–4.51 | **Byepervisor** (SpecterDev) | (1) HV's `VMMCALL` jump tables were in read-only pages but reachable via **mirroring** (mmap R/W + flip the PTE) → hijack `VMMCALL_HV_SET_CPUID_PS4` → execute in HV context → ROP to disable NPT+GMET. (2) **QA flag fail**: the "system-level debugging" flag makes kernel .text R/W (XOTEXT skipped); it's guest-shared and *not* reinit'd on suspend/resume → set it via kernel exploit → rest mode → resume → strip XOM. |
| 3.00–4.51 | **hv_defeat_0304** (ps5-linux-loader) | (1) **TMR relaxation**: write `TMR_CFG_PERMISSIVE=0x3F07` to TMR config regs (idx 5,16,17,18). (2) **IOMMU write primitive**: use the IOMMU **COMPLETION_WAIT (opcode 0x1 — NOT 0x05, which is INVALIDATE_INTERRUPT_TABLE and writes nothing)** command to store 0 to VMCB offset 0x90 (the `NP_ENABLE` field) — the IOMMU bypasses CPU/HV permission checks. (3) `vmmcall` on every core to force VMCB reload. VMCB PAs: 0x6290B000 (3.00–3.21) / 0x62A05000 (4.00–4.51) + core*0x3000. |
| 5.00–6.02 | **hv_defeat_0506** (ps5-linux-loader) | ROP-based #GP hijack: patch the IDT + TSS IST6/IST7 stacks, ROP to corrupt the VMCB `NESTED_CTRL` bits, trigger on ACPI resume. |
| 3.00–6.02 + 7.61 | TheFlow | unreleased/unimplemented |
| **8.00–13.60** | **unreleased** | per Sonic-Iso: **"root-0 NPT maps the hypervisor's own physical memory"** — the HV's own pages are guest-visible via the NPT → read/patch them. **Patched in 14.10** (HV memory dropped from the root-0 NPT). This is our 13.60 target primitive. |

## Does dumping kdata help the HV defeat?

**Indirectly.** The direct HV primitives (VMCBs, TMR regs, the HV's NPT, the HV's own code/data)
live in the *hypervisor's* memory, not the kernel `.data` — so a kdata dump does **not** contain
them. But kdata does hold the kernel-side HV interface we need:
- the **IOMMU** config/command-queue setup (the write primitive used by hv_defeat_0304),
- the **psp_mbox / a53mm** secure-world IPC structures,
- any kernel references into the HV's reserved region.

So: kdata is worth dumping for the IOMMU/psp-mbox context, but the HV itself must be located via
the **NPT lead** (the `hvscan.elf` physical-memory sweep), then dumped from the guest-physical
alias. The two work together: kdata → IOMMU write primitive + VMCALL trigger; NPT lead → the HV's
actual pages to patch.

## 2026-10-05 cross-reference + findings (from agents + public research)

**Public confirmation (cragson/ps5-hen `hv_defeat.h`):** TMR_CFG_PERMISSIVE=0x3F07, VMCB_NP_ENABLE=0x90,
VMCB_TLB_CONTROL=0x58 (the ASID field), TMR_CONFIG(n)=n*0x10+0x08, TMR index/data ports 0x80/0x84,
MAX_TMR=22, MAX_VMCBS=16. Stages: stage1_tmr_relax → stage2_find_vmcbs → stage3_patch_vmcbs →
iommu_selftest → stage3b_remove_xotext. COMPLETION_WAIT opcode = 0x1 (OSDev confirms).

**New leads (psdevwiki hypercall table):**
- `IOMMU_READ_DEVICE_TABLE` (hypercall 0xc) — reads the IOMMU device table back = a CLEAN read
  path to the HV's IOMMU config (no XOM, no MMIO guessing).
- `GET_TMR_VIOLATION_ERROR` (hypercall 0xd) — TMR violation state.
- `tmr_disable()` (PS5 Linux loader) — zeroing TMR CONFIG 0–23 as the brute-force alternative
  to the permissive-relaxation.

**HV/secure/TMR carve-out = 0x60000000–0x70000000** (from kdata .data reserved-region map at
0xffffffffd16bfa40): collapses the VMCB search to ≤256MB. VMCB predicate: 4KB-aligned +
np_enable@0x90 bit0 + n_cr3@0xB0 4KB-aligned + asid@0x58 in 1..16.

**Region access correction:** the "second region" 0xffffffffcfed0000 is the KASLR-slid kernel
**TEXT** (slide +0x4FA60000; == canonical 0xffffffff80470000), XOM like the rest of .text — NOT
a readable data BSS. The TMR/psp_mbox/a53mm *data* state is NOT directly readable via
kernel_copyout. Read paths: single-stepping, the NPT physical read, or the **PSP TMR path** —
`sceSblTmrMap`/`sceSblTmrDumpReg` ("MP1 Dump TMR" reads TMR config back without touching XOM).

**IOMMU write primitive (from IOMMU_AUDIT.md):** COMPLETION_WAIT 16-byte entry
`d0=(target&0xFFFFFFF8)|1; d1=0x10000000|((target>>32)&0xFFFFF); d2=0; d3=0` → stores 0 to
VMCB+0x90. MMIO windows at VA 0xffffec8c01130000 + N*0x4000 (N=0..7). CmdBuf base @0x08,
tail @0x2008 (doorbell).

**SAFE ranges (no KP):** readable VA = .data 0xffffffffd0930000–0xffffffffd1830000 + AMD-Vi MMIO
0xffffec8c01130000–0xffffec8c01210000; guest-PA normal RAM 0–1.5GB + 1.75–16GB; probe-first
0x60000000–0x70000000. NEVER ≥16GB (killed 11.60) or the XOM live-exec mapping.

## Open questions

- Does the "root-0 NPT maps the HV" behavior hold on **14.00** too, or only ≤ 13.60? (Determines
  whether the HV lane extends to 14.00 or stops at 13.60.)
- What is the exact physical address / NPT entry that aliases the HV? (The concrete lead to
  enumerate first.)
- Is the HV XOM too (its text unreadable), or only the kernel's? (Affects whether we can dump the
  HV code directly or must single-step it.)

## Change log

- 2026-10-05: created; captured the NPT-mapping lead + plan.
