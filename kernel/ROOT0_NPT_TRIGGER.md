# ROOT0_NPT_TRIGGER.md — SlopVisor: public-knowledge synthesis + deterministic-trigger probes

**Date:** 2026-10-05
**Scope:** "root-0 NPT maps the hypervisor's own physical memory" (Slopervisor / SlopVisor),
8.00–13.60, patched 14.10. Consolidates everything *public* about (a) the exact mechanism and the
readable-vs-trapped "special condition", (b) the jump-table/shared-memory analog on 8.00+, (c) the
8.00+ HV relocation, (d) the state of any SlopVisor writeup/leak — then gives concrete
deterministic-trigger probes.
**Companion docs (do not re-derive):** `ROOT0_NPT_FLAG.md` (the QA-flag analog), `HV_NPT_CONSTRUCTION.md`
(offline dump analysis), `HV_LAYOUT.md` (the 186-chunk dump was guest RAM, not HV), `HV_UNMAP_PT_TMR.md`,
`references/hv-npt-alias.md`, `HANDOFF.md`.

---

## 0. TL;DR / verdict

- **The mechanism is a *data* read/write of HV memory through the guest page tables.** The guest NPT
  (Second-Level Address Translation) fails to carve out the HV's *own* physical region, so on a lucky
  boot the HV's code is present + readable at guest-PA aliases (dense `0F 01 D8..DF`). "root-0" = the
  NPT **root-level (PML4) entry 0**, whose subtree identity-maps low guest RAM (0–512 GB) and therefore
  covers the HV's carve-out (~0.6–0.7 GB) unless explicitly carved.
- **The readable-vs-trapped "special condition" is the AMD NPT `NDA` bit (bit 58, the "nda"/xotext
  feature).** A present NPT entry permits data reads *unless* bit 58 is set. So the two observed states
  are `phys|P|R/W|U/S|A|D` (readable, ~1-in-12 boots) vs `phys|P|NDA` (trapped → #NPF → panic), plus
  `not-present` (carve-out → #PF → `kernel_copyout` returns −1). **Nothing public names the exact
  boot-time input that flips this on 8.00+** — the SlopVisor mechanism is unreleased.
- **The Byepervisor "special condition" is the *analog shape*, not the answer.** Its NPT constructor
  checked the SL-debugging QA flag (`qa_flags[1] & 0x02`) and skipped xotext on *kernel `.text`* when
  set. It never made the HV's *own* memory readable, and it is dead on 8.00+ (HV no longer reads kernel
  QA flags). It teaches the *lesson*: the HV re-runs NPT construction on **resume from rest mode**, and
  some boot-time inputs are **not** reinitialized across that boundary — that asymmetry is the most
  promising deterministic-trigger lever (see §5.1).
- **The jump-table attack has NO direct 8.00+ analog** (it needed the in-kernel HV of ≤2.70), **but the
  shared-memory *class* survived** in exactly the SlopVisor form: instead of "guest page tables map HV
  static data", it is now "guest NPT maps HV physical memory".
- **No SlopVisor technical writeup exists.** psdevwiki §13.1 is a stub (credits + "patched: No as of
  13.60" only). The only mechanism hint anywhere is Sonic-Iso's 2026-10-05 tweet.

---

## 1. (a) The exact "root-0 NPT" mechanism

### 1.1 What "root-0" means

Two public readings, both consistent; the first is the mechanically meaningful one:

1. **NPT root level, entry 0.** AMD NPT is a 4-level walk rooted at `nCR3` (VMCB+0xF0). The root is a
   PML4 table; **entry 0** covers guest-PA `0x0000000000000000 – 0x7FFFFFFFF0000000` (512 GB). All of
   PS5 RAM (≤16 GB) plus the HV carve-out (~0.6–0.7 GB) sits under entry 0's subtree. If that subtree
   identity-maps RAM and fails to carve the HV region, the HV memory is guest-readable. The 14.10 fix —
   "root-0 NPT **no longer maps** the hypervisor's own physical memory" — reads naturally as "entry 0's
   subtree now carves out the HV region."
2. **"ring-0 guest's NPT"** — i.e. the NPT as seen from the non-secure kernel (root ring-0), not the
   trusted/secure world. Emphasis, not a different mechanism.

The skill note (`ps5-hypervisor-defeat`) already resolves this the same way: "root-0 = the NPT's root
level (PML4), NOT core 0 — the readable/trapped state is not per-core."

### 1.2 The readable-vs-trapped "special condition" (the NPT permission model)

AMD NPT present entries always permit **data reads** unless **bit 58 = `NDA`** ("no data access" — the
hardware-backed "nda feature"/xotext that psdevwiki describes as an AMD collaboration). So the three
states the team has already observed on-console map exactly onto the NPT entry forms:

| guest read result | NPT entry form | meaning |
|---|---|---|
| `ret=0`, real HV bytes | `phys \| P \| R/W \| U/S \| A \| D` (no bit 58) | HV code **readable** (lucky boot) |
| hard PANIC | `phys \| P \| NDA(bit 58)` | present-but-data-trapped → #NPF → HV treats as fatal |
| `ret=-1` | not-present | carve-out → #NPF → HV injects #PF → `kernel_copyout` catches |

This is *exactly* the Sonic-Iso picture: **code readable, data trapped** = the HV's own pages are mapped
present in the guest NPT, with bit 58 set on some and clear on others, depending on the boot.

**What controls bit-58 vs clear vs carve-out on a given boot is NOT public.** `HV_NPT_CONSTRUCTION.md`
proved the NPT-construction code (where the bit-58 decision lives) is absent from the SVM-dense dump and
that no *runtime* code path touches bit 58 — the decision is made **once, at boot (or resume), in the
missing constructor**. The Byepervisor "special condition" phrase — *"Hypervisor's NPT construction
contains a special condition… If System Level Debugging QA flag set, kernel .text pages are R/W, XOTEXT
is not applied"* — is the closest documented "flag checked at NPT-construction time", but it gates kernel
`.text`, is ≤2.70-only, and never touched HV-owned memory. Treat it as the *mechanism shape* (a boot-time
permission-strip gated by a flag/input), not the 8.00+ trigger.

### 1.3 Why the coin flip (~1 in 12): two candidate causes

The ~1/12 rate across cold boots (and the single observed readable boot being the **fresh-update boot**,
1-of-8) points to one or both of:

- **HV placement/ASLR.** The 8.00+ HV is a separately-loaded component whose physical base is randomized
  per boot. If the own-pages carve-out is computed relative to where the HV landed, a race/off-by-one
  leaves the real region mapped when the HV lands in an unexpected spot. (This explains cold-boot
  variance but NOT why the update boot was special.)
- **A boot-mode flag.** If the NPT constructor skips the own-pages protect pass in a non-cold path
  (first-boot-after-update / recovery / resume-from-rest), that path is the deterministic lever. The
  fresh-update observation is direct evidence for this class.

Neither is confirmed by any public source. Both are cheaply testable (§5).

---

## 2. (b) Jump-table / shared-memory analog on 8.00+

**Jump-table exploit (Byepervisor bug #1), verbatim mechanics (≤2.70):** the in-kernel HV's vmexit
handler used **two jump tables that were mapped in the *guest* page tables** (read-only pages). Specter's
"mirroring" trick requested an R/W mapping via `mmap()` then changed the PTE address to alias the
read-only page, overwrote the `VMMCALL_HV_SET_CPUID_PS4` jump entry, and JOP→ROP'd (setjmp/longjmp
gadgets; unused HV registers preserved across the VM-exit boundary) to write VMCB+0x90 (`NP_ENABLE`) and
disable NPT+GMET on that core, then the other cores' VMCBs.

**Why it is dead on 8.00+:** the exploit requires HV code/static data (the jump tables) to be mapped in
the guest's *own* page tables — a property of the in-kernel HV. "Starting in 3.00, the hypervisor is
loaded in a separate region independently of the kernel — and thus these exploits do not work"
(Byepervisor slides, verbatim). On 8.00+ the HV's code/data/jump tables are not in the guest PTs, so
there is no guest-writable jump-table entry to hijack.

**The analog that DID survive — and it is SlopVisor itself:** the *shared-memory class* never died; it
changed surfaces. The ≤2.70 bug was "HV static data shared into guest page tables"; the 8.00–13.60 bug is
"HV physical memory shared into the guest **NPT**". Both are the same root error — the HV failing to fully
isolate its own memory from the guest's address-translation view — and both yield the same endgame
(disabling NPT/GMET via VMCB+0x90), but via different primitives:

| | ≤2.70 jump-table | 8.00–13.60 SlopVisor |
|---|---|---|
| shared surface | HV jump tables in guest PTs | HV physical region in guest NPT |
| primitive | guest write → HV code exec (JOP/ROP) | guest data **read + write** of HV memory |
| endgame | write VMCB+0x90 | locate VMCB/NPT in the readable region → write VMCB+0x90 (or IOMMU COMPLETION_WAIT) |

Consequence for the write half: SlopVisor is the *only* shared-memory door on 8.00+; there is no
second (jump-table-class) analog to pursue. (`HV_UNMAP_PT_TMR.md` separately rules out the 5.00–6.02
`hv_unmap_pt_tmr` VMCB heap-OOB — closed at 6.50, anchors gone on 8.00+.)

---

## 3. (c) HV relocation — where the 8.00+ HV lives

| FW | HV placement | anchors |
|---|---|---|
| 1.00–2.70 | **in-kernel** (embedded in the kernel binary) | jump tables + QA flags shared with guest |
| 3.00–4.51 | isolated "v2" carve-out | `HV_CODE_CAVE_PA=0x62806F00`, `HV_HANDLE_VMEXIT=0x6282xxxx`, `HV_ENTRY=0x6282E1B8`, `HV_PML4=0x6282E1A0`, VMCB `0x6290B000`/`0x62A05000` + core*0x3000 |
| 5.00–7.61 | same 0x628xxxxx region | `hvm_shm=0x62a01000`/`0x62a22000`, `vmcb0=0x62a08000`/`0x62a57000`; 6.50–7.61 defeat walks `vtophys(vCPU[i]+0x08, hv_pml4)` |
| **8.00–13.60** | **separately-loaded component, base moved + randomized** | **unknown**; `kdata_1360.bin` has ZERO u64 refs into `0x62800000–0x62B00000`; the `0x60000000–0x70000000` carve-out DMAP read returns −1 (not in guest DMAP) |

**How to pin the 8.00+ base deterministically (already documented in `HV_LAYOUT.md` §4):** the AMD-Vi
IOMMU MMIO registers **Device Table Base (DTRB, `+0x00`)** and **Command Buffer Base (CBRB, `+0x08`)**
live *inside* the HV carve-out. Reading them at VA `0xffffec8c01130000 + N*0x4000` (N=0..7, single
`kernel_copyout` reads) returns host-PAs that immediately locate the HV region — on **any** boot, no coin
flip. Caveat already on record: the IOMMU MMIO window read all-zero on a JB'd boot (the guest's
`iommudrv` drives the IOMMU via `hv_iommu_*` hypercalls, not raw MMIO), so treat the MMIO read as
UNVERIFIED until a read-back proves the window is live. The HV relocation (this doc) is *why* the 8.00+
base is not in any `.data` dump — the component is loaded outside the guest-visible address space, which
is precisely the isolation the SlopVisor NPT bug then leaks back.

---

## 4. (d) SlopVisor writeup / leak status

**There is no public technical writeup.** What exists:

- **psdevwiki `Vulnerabilities` §13.1 "<=13.60 – Slopervisor"** is a stub: *"Credits — Discovered by
  TheFloW before 2026-09-16. Independently discovered by Jordy before 2026-09-16."* and *"Patched — No as
  of PS5 FW 13.60."* The Analysis / Bug description / Implementation subsections are **empty**. (Fetched
  2026-10-05; the page is Cloudflare-gated but the search index shows the section has no mechanism text.)
- **Sonic-Iso tweet (2026-10-05)** — the only mechanism hint, quoted via videocardz:
  *"the hypervisor exploit was patched enough on 14.10 to not work anymore since root-0 NPT no longer
  maps the hypervisor's own physical memory. rip. updating over 13.60 isnt smart."*
- **TheFloW / Jordy dual discovery + the report drama** (techpowerup 2026-09-15): TheFloW had found "the
  only hypervisor bug left" and deliberately left it in the hope it survived to GTA VI (Linux-on-PS5-Pro
  in 2027); "slop kiddies" (newcomers, the Slopkit/Jordy/@couldbeautism circle)
  independently found it and reported it to Sony's HackerOne program, which led TheFloW to drop the PS5
  Linux project. This confirms the bug was reported to Sony **before** 14.10 shipped.
- **Slopkit / "Slopervisor proof for latest FW"** (couldbeautism screenshot, 2026-09): PoC "hardware
  tested on 10.00", 13.60 listed as a possible target; Slopkit added per-firmware offset files up to
  13.60. Offsets only — no mechanism.

**Bottom line:** everything in §1 about the *exact* trigger is inference from (i) the AMD NPT/NDA model,
(ii) the Sonic-Iso phrase, and (iii) the Byepervisor precedent. Treat "root-0 NPT entry 0 identity-maps
the HV region unless carved" as the best-supported reconstruction, not as confirmed.

---

## 5. Deterministic-trigger next-probe ideas (prioritized)

Ordered by (expected info gained) × (1 / cost). All on the 7.61 workhorse → 13.60; destructive probes on
the workhorse, never the 11.60 Pro.

### 5.1 [TOP] Rest-mode suspend → resume → rescan (the Byepervisor asymmetry lever)
**Why:** Byepervisor's *entire* bug-2 was that on suspend/resume the HV **re-runs NPT construction**
while some input (the QA flags) is **not** reinitialized. If the 8.00+ NPT constructor has the same
asymmetry for the *own-pages* carve-out — e.g. it only applies bit-58/carve-out on the cold path, or
re-derives the HV region from a stale value on resume — then **every resume leaves the HV's own pages
readable**. This would turn the 1-in-12 coin flip into a deterministic per-resume trigger.
**Probe:** cold-boot → re-JB → `probe65/liveness.elf` (map readable band) → enter rest mode → resume →
re-establish kernel R/W if the exploit host dropped → `probe67/hvscan3.elf` dump-on-sight. Repeat 3–5
resume cycles before concluding negative. This is the highest-value, cheapest test in the list.

### 5.2 [TOP] First-boot-after-update / recovery / safe-mode boot (matches the one observed readable boot)
**Why:** the single confirmed readable boot was the **fresh-update boot** (1-of-8). Hypothesis: the
update/recovery path runs the HV with the own-pages protect pass skipped, or before relocation is
finalized — a deterministic superset of the cold-boot coin flip.
**Probe:** (a) reinstall the *same* 13.60 `PS5UPDATE.PUP` (already staged at
`/mnt/usb0/PS5/UPDATE/PS5UPDATE.PUP`, 1,247,471,104 bytes) via recovery → forces a first-boot-after-
update; scan immediately. (b) Safe-Mode boot (hold power 7 s from off → menu → "Restart PS5") and
"Rebuild Database" recovery, then scan. Log the boot *mode* alongside every scan so any readable boot is
correlated with its mode.

### 5.3 Fix the scanner so a lucky boot is actually captured (the 186-chunk dump was a false positive)
**Why:** `HV_LAYOUT.md` proved the last "HV dump" was guest RAM — the `0F 01 D8..DF` ≥3/MB heuristic
false-positived on a repeated 16-bit data table. A coin flip is only as good as the capture.
**Probe:** rebuild `hvscan3` to require **≥2 SVM opcodes decoded at valid instruction boundaries within a
tight window (≤64 B)**, **reject the `…d2 00 d4 00 d8 00…` table pattern**, and (ideally) verify
basic-block coherence before dump-on-sight. This converts "coin flip + noise" into "coin flip + reliable
capture".

### 5.4 Re-dump WITHOUT the SVM filter on the next readable boot (capture the NPT constructor)
**Why:** `HV_NPT_CONSTRUCTION.md` §6: the boot-time NPT constructor contains zero SVM instructions, so it
never cleared the density filter and was never captured. It is the *only* code that holds the bit-58 /
carve-out decision — the answer to "what controls readable-vs-trapped".
**Probe:** once liveness confirms a readable band on a given boot, run `probe54/hvdump.elf` over the
**whole** band (not just dense clusters), then offline-scan for `shr {12,21,30,39}`, `and 0x1ff`, `bts 58`,
`mov cr3`, `movabs 0x0400000000000000`.

### 5.5 [Deterministic, no coin flip] Read IOMMU MMIO DTRB/CBRB to pin the HV host-PA base
**Why:** `HV_LAYOUT.md` §4 — DTRB (`+0x00`) and CBRB (`+0x08`) land inside the HV carve-out and pin the
base on **any** boot. This is the deterministic alternative to the coin flip entirely.
**Probe:** `kernel_copyout` 8-byte reads at `0xffffec8c01130000 + N*0x4000` (N=0..7). Verify the window
is live first (the prior all-zero read on a JB'd boot is a known caveat). Once pinned, walk VMCB `nCR3`
→ NPT pages → read the actual `P` vs `P|NDA` bits for the HV's own guest-aliased pages (§5.6).

### 5.6 Read the HV's own NPT pages via `nCR3` (observe the "special condition" as data)
**Why:** once `nCR3` is known, the readable-vs-trapped decision is observable *as data* (the actual NPT
entries) without needing the constructor. `probe55/nptwalk.elf` is already built for this.
**Probe:** walk `nCR3` (VMCB+0xF0) and enumerate which guest-PAs the root-0 subtree maps to HV host-PAs,
and with which permission bits. This directly confirms §1.2 and reveals whether the trigger is a per-entry
bit-58 flip or a whole-subtree carve-out skip.

### 5.7 Rule out / in the QA-flag-analog formally (cheap negative test)
`ROOT0_NPT_FLAG.md` §(d) already scripts this: `qa_flags[1] |= 0x02` → rest mode → resume → rescan.
Expected result: no change (the SL flag is dead on 8.00+). Run once to close the "is there still an 8.00+
flag checked at NPT-construction" question formally, then do not re-chase it.

### 5.8 (Lever, not a trigger) `hv_unmap_pt_tmr` / `hv_restore_pt_tmr` for the *write* half
`HV_UNMAP_PT_TMR.md` §4: the OOB is closed at 6.50, but the wrappers + hypercalls persist unchanged
7.61→13.60. If/when the NPT-alias data-write primitive lands, these are the levers that toggle HV
page-table mapping — not a way to *get* the readable state. Keep in the back pocket; don't chase first.

---

## 6. Uncertainty (explicit)

1. **The SlopVisor mechanism is unreleased.** §1's trigger reconstruction is inference (AMD NDT/NDA model
   + Sonic-Iso phrase + Byepervisor precedent), not from any writeup. There may be an 8.00+ flag/bit that
   nobody has named publicly.
2. **"root-0" is not self-documenting.** The PML4-entry-0 reading is the best-supported interpretation and
   is consistent with the 14.10 fix; the "ring-0 guest's NPT" reading is also defensible. Both point to the
   same primitive.
3. **The coin-flip cause is unresolved between HV-placement-ASLR and a boot-mode flag.** 5.1/5.2 are
   designed to discriminate: if resume or update-boot is deterministic, it's the boot-mode flag; if neither
   is, it's placement and 5.5 (MMIO base) + 5.3 (reliable capture) become the main lane.
4. **The IOMMU MMIO window may be dead on a JB'd boot** (prior all-zero read). 5.5 is the single datum that
   would nail the base, but it is unverified and must be re-probed with a write-back/sentinel before being
   relied on.
5. **Everything here is for the user's own consoles; nothing published, no exfil.** The scene drama
   (TheFloW drop) is context on *why* the trigger was reported and patched, not something to act on.

---

## 7. Sources

- **psdevwiki `Hypervisor`** — in-kernel HV ≤2.70; NPT/SLAT; `xotext` = NPT PTE bit 58, AMD "nda feature";
  two page-table sets at boot (own tables R/W, NPT with bit-58 on kernel text); hypercall table 0x0–0x10.
  https://www.psdevwiki.com/ps5/Hypervisor
- **psdevwiki `Vulnerabilities`** — §13.1 "<=13.60 Slopervisor" (stub: TheFloW + Jordy, both pre-2026-09-16;
  "Patched: No as of PS5 FW 13.60"); §13.7 "<=2.70 hypervisor virtual tables in kernel data segment"
  (Byepervisor bug #1); §13.8 "<=2.70 hypervisor integrated as part of the kernel binary".
  https://www.psdevwiki.com/ps5/Vulnerabilities
- **PS5Dev/Byepervisor** (README + slides PDF, hardwear.io, "Hypervisor's NPT construction contains a
  special condition…"; "Starting in 3.00, the hypervisor is loaded in a separate region").
  https://github.com/PS5Dev/Byepervisor — slides: https://hardwear.io/wp-content/uploads/2026/03/Byepervisor__Breaking_PS5_Hypervisor_Security.pdf
- **Sonic-Iso (2026-10-05)** — "root-0 NPT no longer maps the hypervisor's own physical memory… patched
  enough on 14.10." via https://videocardz.com/newz/gta-vi-reportedly-requires-ps5-firmware-14-10-…
- **techpowerup (2026-09-15)** — TheFloW drop; the HV bug was independently found + reported by
  "slop kiddies" (Slopkit circle). https://www.techpowerup.com/352739/…
- **Slopkit / couldbeautism** — "Slopervisor proof for latest FW" PoC on 10.00, 13.60 possible; offset
  files ≤13.60. (twistedvoxel / tech-oracle / ixbt.games, 2026-09.)
- **Workspace** — `HANDOFF.md`, `HV_LAYOUT.md`, `HV_NPT_CONSTRUCTION.md`, `ROOT0_NPT_FLAG.md`,
  `HV_UNMAP_PT_TMR.md`, `references/hv-npt-alias.md`, `references/hypervisor-defeat.md`,
  `ps5-linux-loader/source/offsets.c`, `cragson/ps5-hen/hv_defeat.h`.

## Change log
- 2026-10-05: created. Consolidated public ground; pinned the NPT-NDA(bit-58) model of the
  readable-vs-trapped split; resolved "root-0" = NPT PML4 entry 0; established the jump-table class has
  no 8.00+ analog but the shared-memory class persisted as SlopVisor; mapped the HV relocation timeline;
  confirmed no SlopVisor writeup exists; proposed the resume-from-rest and first-boot-after-update
  deterministic-trigger probes as the top lanes.
