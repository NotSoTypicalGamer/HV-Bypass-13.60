# ROOT0_NPT_FLAG — what gates "root-0 NPT maps the HV's own physical memory" (8.00–13.60)

**Question posed:** on 8.00–13.60, what EXACTLY gates whether the root-0 NPT maps the
hypervisor's OWN physical memory READABLE vs present-but-trapped? Is it a per-boot flag
(analogous to the Byepervisor SL-debugging QA flag) checked at HV NPT-construction time?

**Verdict (short):** The Byepervisor SL flag is the analog, but it only ever gated KERNEL
`.text` XOM — it never made the HV's *own* memory readable, and it is **dead on 8.00+**.
The 8.00–13.60 "root-0 NPT maps HV memory" state is the **Slopervisor / Sonic-Iso** bug,
whose exact mechanism (including what makes the HV's own pages readable vs no-access) is
**unreleased** (reported to Sony HackerOne by Jordy 2026-09, same bug TheFlow held). There
is **no publicly documented 8.00+ flag/bit** to force the readable state.

---

## (a) The analog flag — exact byte/bit

- **Flag:** System Level (SL) debugging QA flag.
- **Location / bit:** `qa_flags[1] & 0x02` — **byte index 1 of the 16-byte QA-flags array,
  bit 1 (mask 0x02)** ("allow sl debugger").
- **What it gated (<=2.70):** at HV NPT construction, when set, kernel `.text` NPT entries
  had the `xotext` bit (**PTE bit 58, AMD "nda"**) left CLEAR **and** the write bit SET →
  kernel `.text` became guest R/W (once the guest also flipped its own PTEs).
- **Corroboration:** the PS5 UMTX/IPV6 kernel chain writes `kernel_write2(QA_FLAGS + 0x1,
  val | 0x103)` → `qa_flags[1] |= 0x03` (0x01 ul-debugger + 0x02 sl-debugger). Byepervisor
  README + slides call the SL flag "the one the hypervisor's NPT constructor checks".
  `PDE_XOTEXT = 58` in Byepervisor `include/paging.h`.

**Critical distinction (do not elide):** even on <=2.70, the SL flag made **kernel .text**
readable — NOT the HV's own data/code. The Byepervisor "Bug 1" slides state the hypervisor
"has its own reserved data region **unmapped from the guest kernel**" (page tables, VMCBs,
MSRPM), and flat_z's PS5 talk shows "HV pages **not mapped**" in the NPT. So there is no
historical case where a QA flag made the *HV's own memory* readable through the NPT — the
SL flag is an analog for the *permission-stripping-at-NPT-construction* mechanism, not for
the *HV-self-mapping* question.

## (b) Does it persist across rest mode, and is the sequence valid on 8.00+?

- **The Byepervisor mechanism (confirmed, <=2.70):** QA flags live in a kernel data segment
  shared with the in-kernel HV. On suspend/resume the **secure loader restores QA flags from
  the hibernation file unchanged** (does NOT reinitialize them), but the **HV re-runs its NPT
  init on resume**. So: set SL flag → rest mode → resume → HV re-builds NPT honoring the flag
  → kernel `.text` loses xotext/gains write. Byepervisor's `main.cpp` confirms the two-send
  flow (pre-suspend: clear guest-PTE xotext + write a 0x1337 sentinel to a kernel data cave;
  post-resume: re-clear guest PTEs and dump/patch).
- **Valid on 8.00+?** **NO.** "Starting in 3.00, the hypervisor is loaded in a separate
  region independently of the kernel — and thus these exploits do not work" (Byepervisor
  slides, verbatim). psdevwiki marks it `<=2.70`, patched "maybe since FW 3.00". On 8.00+
  the HV no longer shares/reads the kernel-data QA flags during NPT construction, so
  `qa_flags[1] |= 0x02` + suspend/resume does **nothing** to any HV-enforced mapping.
  (`kernel_set_qaflags` / `KERNEL_ADDRESS_QA_FLAGS` still exist in ps5-payload-sdk v0.43, but
  they only touch the guest kernel's own copy; the HV-side consumer is gone.)

## (c) What reproduces the "HV code readable" state we saw on the fresh-update boot?

**Unknown / not publicly documented.** The evidence points to a **per-boot NPT-permission
roll**, not a controllable flag:

- The team's own record already classifies it: "a code-readable boot is a **coin flip**" —
  the fresh-update boot was 1 of 8; every subsequent cold-boot + re-JB landed "protected".
- The NPT is rebuilt per cold-boot; the HV's guest-visible layout (carve-out top, code-alias
  guest-PA, fault-page positions) **re-rolls every boot** (DMAP base observed
  `0xffffcd50../0xffffda2b../0xfffffc95..` across boots).
- Mechanistically the two observed states are the two present-entry permission forms of the
  Slopervisor bug: **present + R** (HV code guest-readable) vs **present + no-access**
  (read → #NPF → panic). Which form lands depends on the HV's NPT-construction pass and the
  (randomized per boot) placement of the HV's own pages relative to the identity-mapped RAM —
  not on any known QA flag.

**Do not treat the SL flag as the lever for this.** It is the analog *shape* of the bug
(permission strip gated at NPT construction), but no 8.00+ flag is public, and the Slopervisor
mechanism is unreleased. The deterministic lane for dumping the HV remains the offline one:
recover IOMMU cmd-buffer PA + VMCB PA from `kdata_1360.bin` (COMPLETION_WAIT_PLAN.md /
VMCB_PA.md / IOMMU_CMDBUF.md), or keep re-rolling cold-boots with the dump-on-sight scanner
(`probe67/hvscan3.elf`) to catch the next code-readable boot.

## (d) Concrete deterministic test sequence (flag → rest mode → resume → rescan)

This is a **NEGATIVE test** — its expected result is *no change*, and it is only worth one
cycle to formally rule out the SL-flag analog on 8.00+:

1. **Set the flag (kernel R/W):** `qa_flags[1] |= 0x02` via `kernel_set_qaflags` (or direct
   `kernel_write8(KERNEL_ADDRESS_QA_FLAGS + 1, qa_flags[1] | 0x02)`). Read back to confirm.
2. **Enter rest mode** (suspend).
3. **Resume** (power back on). Re-establish kernel R/W if the exploit host dropped
   (elfldr :9021 usually survives; if not, re-run Relapse/UMTX).
4. **Rescan:** run `probe65/liveness.elf` first (maps the readable band), then
   `probe67/hvscan3.elf` from just above the carve-out (`0x7000000` → `0x100000000`),
   watching the 1.86–1.96 GB band for dense SVM clusters (`0F 01 D8..DF`, ≥3/MB).
5. **Expected:** same read-FAULT band, no HV-code readability — **confirms the QA-flag route
   is dead on 8.00+** and that the readable state is not flag-reproducible.

If a *positive* reproduction is wanted, the only known lever is **re-rolling cold-boots**
(fresh cold-boot + re-JB, then hvscan3.elf dump-on-sight) until a code-readable boot lands —
the fresh-update boot was not special in any flag sense that has been identified.

---

## Uncertainty (explicit)

1. **The Slopervisor / "root-0 NPT" mechanism is unreleased.** Everything about *why* the
   8.00+ HV maps its own memory into the root-0 NPT, and *what determines* readable vs
   no-access on a given boot, is inference from the Sonic-Iso tweet + public architecture,
   not from any published writeup. There may well be an 8.00+ flag that nobody has named in
   public; if it exists, it is not in Byepervisor, hv_defeat, ps5-linux-loader, or psdevwiki.
2. **The fresh-update readable state is unexplained** beyond "per-boot roll." It is possible
   (not established) that the first boot after an update runs the HV in an update/recovery
   mode where the protect-my-own-pages pass is skipped. No public source confirms this.
3. **`qa_flags[1] bit 1` is the analog, not the answer.** It is the closest documented
   "flag checked at NPT-construction time" and the one the user named; but it gates kernel
   text, is <=2.70, and never touched HV-owned memory.

## Sources

- PS5Dev/Byepervisor — README.md, `src/main.cpp` (resume sentinel 0x1337 flow),
  `include/paging.h` (`PDE_XOTEXT=58`). https://github.com/PS5Dev/Byepervisor
- Byepervisor slides (hardwear.io NL 2024, PDF in repo): "Hypervisor's NPT construction
  contains a special condition… If System Level Debugging QA flag set, kernel .text pages
  are R/W"; "Starting in 3.00, the hypervisor is loaded in a separate region… these exploits
  do not work." https://hardwear.io/wp-content/uploads/2026/03/Byepervisor__Breaking_PS5_Hypervisor_Security.pdf
- flat_z "Next-gen exploitation — exploring the PS5 security landscape" (slideshare): "HV
  pages not mapped / Kernel text is nested / Enforces XOM on guest kernel."
  https://www.slideshare.net/slideshow/next-gen-exploitation-exploring-the-ps5-security-landscape-pdf/269866512
- psdevwiki Hypervisor ("In-Kernel Hypervisor (<= 2.70)"; NPT/xotext bit 58) + Vulnerabilities.
  https://www.psdevwiki.com/ps5/Hypervisor
- Sonic-Iso, 2026-10-05: "root-0 NPT no longer maps the hypervisor's own physical memory …
  patched enough on 14.10." (via videocardz / X).
- Slopkit/Slopervisor context (Jordy/@couldbeautism reported the HV bug to Sony HackerOne
  2026-09; TheFlow held the same bug; PoC "hardware tested 10.00, possible 13.60").
  onejailbreak.com / wdcnews6.com.
- ps5-linux-loader `source/offsets.c` (HV_PA anchors 3.00–4.xx, `hv_defeat_0304/0506`),
  cragson/ps5-hen `hv_defeat.h` (TMR/VMCB/COMPLETION_WAIT) — for the *write* half, not the
  readable-vs-trapped gate.
- Workspace: QA_FLAGS_ROUTE.md, HV_RESEARCH.md, HANDOFF.md (per-boot NPT re-roll + coin-flip
  observation), references/hv-npt-alias.md.
