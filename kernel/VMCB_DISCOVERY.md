# VMCB_DISCOVERY.md — SAFE plan to find the 13.60 VMCB physical address (→ NPT nCR3)

**Goal:** on PS5 13.60, locate the per-core AMD SVM **VMCB** physical address so `probe55/nptwalk.elf`
can read **nCR3** (the nested-page-table base) from it and walk the NPT to read hypervisor memory
(the "root-0 NPT maps the HV's own physical memory" lead, patched in 14.10).

**Constraint:** every `kernel_copyout` on a *bad* physical address PANICS the kernel (no EFAULT).
The 11.60 Pro already died to a 32 GB DMAP oversweep. Everything below is ordered **safety-first**.

---

## 0. Ground truth established offline (no console needed)

### 0.1 VMCB layout — nCR3 offset is **0xB0** (architectural, from FreeBSD `sys/amd64/vmm/amd/vmcb.h`)
The VMCB is **4 KB-aligned**. Control area is the first 0x400 bytes, guest-state area at `+0x400`
(`VMCB_OFF_STATE(x) = x+0x400`). Sony's HV uses the same AMD-defined offsets.

| VMCB offset | field | signature value (guest running) |
|---|---|---|
| `0x000..0x013` | `intercept[5]` (CR/DR/EXC/INST1/INST2) | **non-zero**, specific CR0-WRITE/CPUID/VMMCALL/IO/MSR bits |
| `0x040` | `iopm_base_pa` | 0 or 4 KB-aligned PA |
| `0x048` | `msrpm_base_pa` | 4 KB-aligned PA (MSR permission map) |
| `0x050` | `tsc_offset` | 0 or small |
| `0x058` | `asid` | **1..16** (small) |
| `0x05C` | `tlb_ctrl` | 0..7 |
| `0x090` | `np_enable` (bit 0) | **1** (nested paging is on) |
| **`0x0B0`** | **`n_cr3` (NP_CR3)** | **4 KB-aligned PA → NPT PML4** ← the value we want |
| `0x400+0x010` | `state.cs.selector` | **0x20** (FreeBSD KCSEL) or 0x33/0x3B (user) |
| `0x400+0x0D0` | `state.efer` | ~`0xD01` (SCE\|LME\|NXE) |
| `0x400+0x150` | `state.cr3` | guest kernel CR3 (4 KB-aligned guest-PA) |
| `0x400+0x158` | `state.cr0` | ~`0x80050033` |
| `0x400+0x178` | `state.rip` | kernel text VA (`0xffffffff8…` / `0xffffff80…`) |
| `0x400+0x1D8` | `state.rsp` | kernel stack VA |

**Scan predicate (page p is a VMCB iff):** `(p & 0xfff)==0` **and** `np_enable(p+0x90)&1` **and**
`n_cr3(p+0xB0)` is 4 KB-aligned **and** `asid(p+0x58)` in `[1,16]` **and** `intercepts(p+0x00)`≠0
**and** `state.cs.selector(p+0x410)` in `{0x20,0x28,0x33,0x3B}`. This is a ~1/2^40 discriminator;
false positives in normal RAM are negligible.

### 0.2 DMAP base = `0xfffff80000000000` (4 TB direct map)
FreeBSD amd64 maps guest-PA → guest-VA linearly at `DMAP_BASE`. `probe54/hvdump.elf` and
`probe55/nptwalk.elf` already read physical memory as `kernel_copyout(KERNEL_ADDRESS_DMAP_BASE + pa, …)`.
`KERNEL_ADDRESS_DMAP_BASE` is a crt1.o symbol (SDK v0.43). **Never pass `pa ≥ 0x400000000` (16 GB).**

### 0.3 NEW — the kernel `.data` stores the physical reserved-region map
From `kdata_1360.bin` (base `0xffffffffd0930000`), a 32-bit-pair table at `.data 0xffffffffd16bfa40`
holds 11 region descriptors `{flag = 0x6X010001, base = 0x6X000000}` with **bases
`0x61000000, 0x62000000, 0x63000000, 0x64000000, 0x65000000, 0x68000000, 0x69000000, 0x6A000000,
0x6B000000`** (gap at `0x66/0x67`). Plus a `{base,size}+hash` descriptor at `.data 0xffffffffd16cc190`:
`{0x64000000, 0x800000 (8 MB)}` and `{0x64810000, 0x19000 (100 KB)}`.

**Interpretation:** the HV / secure / TMR carve-out lives in **`0x60000000..0x70000000` (~1.5–1.75 GB)**.
The historical VMCB PAs `0x6290B000` (3.00–3.21) and `0x62A05000` (4.00–4.51) fall **inside the
`0x62` block of this exact table** — so the 8.00–13.60 VMCB + NPT + HV code almost certainly live in
this same 256 MB window. This collapses the search from "16 GB" to "≤256 MB, likely a handful of
16 MB blocks".

---

## 1. Ranked approaches (safety-first)

### (1) SAFEST on-console — read AMD-Vi MMIO registers (approach a)
The IOMMU MMIO is **device-mapped and readable** (unlike XOM text). Base VA `0xffffec8c01130000`
(`.data` unit-contexts at `0xd1701b58…0xd1748b38` confirm windows `0xffffec8c01130000..0xffffec8c0120c000`,
16 KB stride). Read these **AMD-Vi MMIO registers** (standard offsets):

| MMIO offset | register | what it gives us |
|---|---|---|
| `+0x00` | Device Table Base (DTRB) | host-PA of the device table (256 KB-aligned) |
| `+0x08` | Command Buffer Base (CBRB) | host-PA of the IOMMU command buffer (4 KB-aligned) |
| `+0x10` | Event Log Base (ELB) | host-PA of event log |
| `+0x18` | Control (CTRL) | enabled/completion-wait bits |
| `+0x28` | Feature (FR) | feature bits |

These give **concrete host-PAs** of HV/IOMMU structures → pins the HV physical-memory region, and
`CBRB` is the exact buffer the `hv_defeat_0304` COMPLETION_WAIT write primitive uses. Single-shot
reads of known MMIO VAs; **no scan, no oversweep, no panic risk** (a probe that reads 8 qwords at a
fixed VA). This is the FIRST on-console action.

### (2) ZERO-risk (already done, keep mining) — `.data` pointer analysis (approach b)
`kdata_1360.bin` already yields the reserved-region map (§0.3) and the IOMMU unit-contexts. The
kernel does **not** store the VMCB PA directly (it is HV-private; the kernel only speaks to the HV
via `vmmcall`), so (b) cannot *directly* reveal the VMCB — but it **drastically shrinks the search
space** and gives the IOMMU CBRB/DTRB location. Continue mining for: the `phys_avail` array (to
enumerate exact safe RAM vs reserved ranges), and any 4 KB-aligned PA in `0x60000000..0x70000000`
stored as a pointer (DMA/IOMMU table bases).

### (3) MEDIUM risk (recoverable) — bounded chunked physical scan of the reserved window (approach c)
Scan **only `0x60000000..0x70000000`** (256 MB) for the §0.1 VMCB predicate, in **4–16 MB chunks**
with a liveness check + re-JB between chunks (scene-confirmed: small scans panic far less; never one
big sweep). Do it on the **7.61 workhorse**, capture card running, expect a possible panic (cold-boot
+ re-JB recovers; no activation loss). Use `probe54/hvdump.elf` / `dump_chunks.py` with the chunk
size set, and grep the merged image for the predicate instead of streaming.

### (4) HIGHEST risk / lowest yield — single-step the HV entry via DDB handlers (approach d)
Execute-and-read-RIP on XOM text (the `0xffffffffcfed…` DDB/iommu method tables) recovers *code
offsets*, not physical addresses, and touching XOM text + the live `0xffffff80…` mapping panics if
misdirected. Only if (1)–(3) all fail. Do not plan the VMCB discovery around it.

---

## 2. Exact commands / probes to run (console back + reset-tolerant)

**Prep (every session):** verify 2121/3232/9021 reachable; start `klog_capture.py`; start the capture
card (`ffmpeg -f dshow -i video="Guermok USB3 Video " …`, close OBS first).

1. **MMIO read probe** (`probe55`-style, new `iommu_read.elf` — trivial, no new build needed beyond a
   loop that `kernel_copyout`-reads 8 qwords): read
   `0xffffec8c01130000 + {0x00,0x08,0x10,0x18,0x28}` and log each. Also read the 7 sibling windows
   `+0x4000*N` (N=1..7). Result: DTRB / CBRB / ELB host-PAs. → If DTRB/CBRB land in
   `0x60000000..0x70000000`, we've confirmed the HV region and narrowed further.
2. **Boundary test-read** (single page, one at a time, 7.61 only): `kernel_copyout(DMAP + 0x62000000)`,
   then `+0x64000000`, `+0x64810000`. One 4 KB read each. If it returns data → region is NPT-readable
   (lead confirmed on this box). If it panics → that sub-block is HV-protected; skip it and record.
3. **Chunked scan** of `0x60000000..0x70000000` in 4 MB chunks (`dump_chunks.py <host> 60000000
   10000000 4 hvregion.bin`), merging, then grep the VMCB predicate:
   `n_cr3=page-aligned && np_enable&1 && asid in 1..16 && cs.sel in {0x20,0x28,0x33,0x3b}`.
4. On a hit at PA `V`: read `n_cr3 = *(u64*)(V+0xB0)`; write `/data/npt.txt` = `%llx` of it; run
   `probe55/nptwalk.elf` → walk the NPT → enumerate HV/MMIO host-physical mappings.

**Dump commands (probe54, configurable):**
```
echo "60000000 10000000" > /data/hvdump.txt   # dump 0x60000000..0x70000000 (256 MB)
# then run hvdump.elf, FTP /data/hvdump.bin off
python3 dump_chunks.py 10.0.0.x 60000000 10000000 4 hvregion.bin   # chunked driver
```

---

## 3. SAFE vs UNSAFE ranges (for the scan)

- **Safe (readable, no panic):**
  - `0x00000000 .. 0x60000000` (0 – 1.5 GB normal RAM)
  - `0x70000000 .. 0x400000000` (1.75 GB – 16 GB normal RAM)
  - VA: `.data` `0xffffffffd0930000..0xffffffffd1830000`; IOMMU MMIO `0xffffec8c01130000..0xffffec8c01210000`.
- **Target (may be readable on ≤13.60, may fault — probe single pages first):**
  - `0x60000000 .. 0x70000000` (HV/secure/TMR carve-out; VMCB/NPT expected here), sub-blocks per §0.3.
- **UNSAFE (NEVER scan — panics):**
  - `≥ 0x400000000` (past 16 GB RAM — the oversweep that killed the 11.60).
  - `0xffffff80…` live-exec XOM mapping (kernel_copyout panics).
  - any hole the §0.3 table marks reserved (0x66/0x67 gap) — treat as protected until proven readable.

---

## 4. Change log
- 2026-10-05: created. Pinned nCR3 = VMCB+0xB0 (FreeBSD vmcb.h); DMAP base 0xfffff80000000000;
  extracted reserved-region map from kdata_1360.bin → HV carve-out 0x60000000..0x70000000;
  ranked MMIO-read > offline-.data > bounded-scan > single-step; gave exact probes + ranges.
