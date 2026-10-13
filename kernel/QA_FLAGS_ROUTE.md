# QA Flags Route (Byepervisor bug #2) — Assessment for PS5 8.00–13.60

**Verdict: NO-GO on 8.00–13.60.** The Byepervisor QA-flags route is dead on every firmware
>= 3.00, because the hypervisor was moved out of the kernel into a separately-loaded region
(which 8.00+ definitely has). Setting the flag via `kernel_set_qaflags` still works as a
kernel-data write, but it no longer causes the hypervisor to strip XOM/XOTEXT.

---

## (a) The exact flag that gates XOM/XOTEXT

- **Gate:** the System Level (SL) debugging QA flag.
- **Location / bit:** `qa_flags[1] & 0x02` — i.e. **byte index 1 of the 16-byte QA-flags array,
  bit 1 (mask 0x02)**. Sony's QA-flags bit map (from the scene's PS4/PS5 payload docs, same
  layout):
  ```
  qa_flags[0] & 0x01  flagged updater
  qa_flags[0] & 0x02  force update
  qa_flags[0] & 0x04  int dev (internal libc), allow init vtrm
  qa_flags[0] & 0x08  allow registry access
  qa_flags[0] & 0x10  int dev for psm, allow psm debug
  qa_flags[0] & 0x40  special i
  qa_flags[1] & 0x01  allow ul debugger
  qa_flags[1] & 0x02  allow sl debugger   <-- System Level (SL) debugging flag (XOM gate)
  qa_flags[1] & 0x04  beta update test
  qa_flags[2] & 0x01  debug menu / debug menu for psm
  ...
  ```
- **Corroboration:** the PS5 UMTX/IPV6 exploit chain (which Byepervisor credits as already
  setting "this flag ... for other reasons") writes `kernel_write2(QA_FLAGS + 0x1, val | 0x103)`
  → `qa_flags[1] |= 0x03` (0x1 ul-debugger + 0x2 sl-debugger) and `qa_flags[2] |= 0x01`
  (debug menu). Byepervisor's README/slides call the SL flag the one the hypervisor's NPT
  constructor checks.
- **What it does when honored (<=2.70):** during hypervisor NPT construction the `xotext` bit
  (**PTE bit 58, AMD "nda"**) is left CLEAR on kernel `.text` NPT entries **and** the write
  bit is SET, so kernel `.text` is fully R/W to the guest once the guest also flips its own
  PTEs.
- **XOTEXT bit (the thing being gated):** PTE **bit 58** (`PDE_XOTEXT = 58` in
  Byepervisor `include/paging.h`; EFER enable = bit 16 per psdevwiki/MSR-protection table).
  Flipping bit 58 in the *guest* PTEs alone does nothing — the nested page table (NPT/SLAT) is
  authoritative and lives in HV-only memory.

## (b) Is it still effective on 8.00+? — NO

- **Why it worked <=2.70:** the hypervisor was *embedded in the kernel binary*, and the QA flags
  lived in a kernel data segment *shared* with the HV. On suspend/resume the secure loader copied
  the QA flags back from the hibernation file **without** reinitializing them, but the HV **was**
  reinitialized — so its NPT init re-read the (now attacker-set) SL flag and built kernel `.text`
  NPT entries without xotext and with write.
- **The fix:** Sony moved the hypervisor to a **separate region independent of the kernel
  starting in 3.00**. Byepervisor slides, verbatim: *"Starting in 3.00, the hypervisor is loaded
  in a separate region independently of the kernel — and thus these exploits do not work."*
  psdevwiki §13.6 marks the bug `<=2.70`, "Patched: maybe since PS5 FW 3.00".
- **8.00+ consequence:** the hypervisor is a separately-loaded component (confirmed by SpecterDev;
  consistent with psdevwiki "In-Kernel Hypervisor (<= 2.70) ... later versions have the Hypervisor
  as a separately loaded component"). It no longer shares/reads the kernel-data QA flags during
  NPT construction, so setting `qa_flags[1] |= 0x02` has **no effect** on XOM enforcement.
- **The SDK primitives still exist** — `kernel_get_qaflags`/`kernel_set_qaflags(uint8_t[16])` and
  `KERNEL_ADDRESS_QA_FLAGS` are present in ps5-payload-sdk v0.43 and the QA-flags array still
  exists in modern kernels — but they only touch the *guest* kernel's copy of the flags. The
  consumer of the flag (the in-kernel HV NPT constructor) is gone. Setting SL does not strip XOM.

## (c) Exact sequence (as it was, <=2.70)

1. Kernel R/W (UMTX/IPV6 chain, or etaHEN-class primitive) → set `qa_flags[1] |= 0x02`
   (SL debugging). (The UMTX chain already leaves this bit set as a debug-menu side effect.)
2. Enter **rest mode** (suspend).
3. **Resume.** Secure loader restores QA flags from hibernation file unchanged; the (in-kernel)
   hypervisor re-runs NPT init and honors the SL flag → kernel `.text` NPT entries lose xotext
   and gain write.
4. Guest edits its **own** PTEs (clear bit 58, set R/W) → kernel `.text` is now read/write →
   dump + patch/hook.
5. Byepervisor payload is sent twice (once pre-suspend to set up, once post-resume to dump/patch).

**Destructive / recoverable:** non-destructive and fully recoverable. The state change is
RAM-only and cleared by a full power-off/cold reboot (a cold boot reinitializes QA flags + HV +
NPT). The only destructive hazard is Byepervisor's own kernel-dump loop, which is commented out
because it panics when it walks past mapped memory — that is a *crash*, not a brick. Setting the
QA flag itself is benign.

## (d) Evidence it was patched / superseded

- **Byepervisor slides (hardwear.io NL 2024), Conclusion slide:** *"Sony realized this — Starting
  in 3.00, the hypervisor is loaded in a separate region independently of the kernel — and thus
  these exploits do not work."* Also: *"Breaking the hypervisor on 3.xx+ is more challenging."*
- **psdevwiki Vulnerabilities §13.6** — "<=2.70 - System Level debug flag in kernel data segment
  and not wiped after rest mode (Byepervisor bug #2)"; Patched: "Maybe since PS5 FW 3.00".
- **psdevwiki Vulnerabilities §13.8** — "<=2.70 - Hypervisor integrated as part of the kernel
  binary" (the architectural change that killed both Byepervisor bugs).
- **Byepervisor README** — "PS5 hypervisor exploit for <= 2.xx firmware", primary chain = QA
  flags exploit, jump-table chain kept only "for preservation".
- **Superseded by a different bug:** the modern HV defeat for 8.00–13.60 is **Slopervisor**
  (Jordy/couldbeautism, "hypervisor defeated PoC hardware tested 10.00, possible 13.60";
  psdevwiki §13.1 "<=13.60 - Slopervisor"). It is an unrelated vulnerability — proof that the
  QA-flags route is not the path anyone uses for current firmware.

## Go / No-Go

**NO-GO** for using the Byepervisor QA-flags route on 8.00–13.60. `kernel_set_qaflags` still
writes the array, but the SL flag is no longer honored by any code that strips XOM. Do not spend
a suspend/resume cycle expecting XOM to be dropped — it won't be.

**Exact flag (for the record):** `qa_flags[1] |= 0x02` (byte index 1, bit 1 = "allow sl
debugger" / System Level debugging). PTE bit being gated = **58 (xotext/nda)**.

**Risk:** LOW. Non-destructive, recoverable by cold reboot; realistically a *dead end* (no effect
on 8.00+), not a hazard. The only real risk is wasted effort and a pointless rest-mode cycle.

---

## Sources

- PS5Dev/Byepervisor — README.md, `src/main.cpp`, `include/paging.h` (`PDE_XOTEXT = 58`),
  `include/offsets/2_50.h`. https://github.com/PS5Dev/Byepervisor
- Byepervisor slides — hardwear.io NL 2024, "Byepervisor: Breaking PS5 Hypervisor Security".
  https://hardwear.io/wp-content/uploads/2026/03/Byepervisor__Breaking_PS5_Hypervisor_Security.pdf
- psdevwiki — Hypervisor ("In-Kernel Hypervisor (<= 2.70)") and Vulnerabilities §13.6/§13.8.
  https://www.psdevwiki.com/ps5/Hypervisor , https://www.psdevwiki.com/ps5/Vulnerabilities
- ps5-wiki — eXecute Only Memory (XOM). https://ps5dev.github.io/ps5-wiki/xom
- QA-flags bit map — scene payload docs (kmeps4 gist "Enable debug settings payload";
  PS4/PS5 share the layout). https://gist.github.com/kmeps4/b4799c09f1c1228c070c688a2e11e76f
- PS5 UMTX exploit-host (sleirsgoevy/Idlesauce fork) — `kernel_write2(QA_FLAGS+0x1, v|0x103)`
  sets `qa_flags[1]|=0x03` (incl. SL bit 0x2). https://git.etawen.dev/Idlesauce/PS5-UMTX-Jailbreak
- ps5-payload-sdk v0.43 — `target/include/ps5/kernel.h`: `kernel_get_qaflags` /
  `kernel_set_qaflags(uint8_t[16])`, `KERNEL_ADDRESS_QA_FLAGS` (offset resolved in `libkernel.so`
  per firmware).
