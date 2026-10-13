# VMCB Sweep — 1.8–4 GB GPU-DMA READ (0x72000000–0x100000000) — IN PROGRESS

**Date:** 2026-10-06 · **Console:** 10.0.0.x (13.60, fw `0x13600007`)
**Primitive:** GPU-DMA READ (bit-50 src-leaf retarget), payload `probe90/gpread90.elf` (v3, main3.c)
**Goal:** find the plaintext AMD VMCB guest-PA or the VCPU-pointer array in the 1.8–4 GB gap,
then clear VMCB+0x90 bit0 (NP_ENABLE) via the WRITE primitive (`probe89/vmid7.elf`).

## Status

- **Swept so far: `0x72000000–0x80000000` (224 MB)** — 4×48 MB segments + 32 MB tail (`0x7e000000`),
  all clean, **no VMCB / no VCPU array**.
- **Fault band `0x80000000–0xA0000000` (2.0–2.5 GB) confirmed** — `0x80000000` hard-panics the GPU-DMA
  read (same as the CPU "2.0–2.5 GB fault band").
- **`0xA0000000` (2.5 GB) reads back PLAINTEXT** (single 2 MB probe: ent 3.76, kernel-text pointers
  `0xffffffff81…`) — so the region above the band is normal guest RAM, NOT ciphertext.
- **3rd KP:** a full 48 MB segment at `0xA0000000` panicked on chunk 1 (`0xA0200000`) even though the
  single 2 MB probe at `0xA0000000` survived. The sub-band above 2.5 GB is therefore NOT uniformly safe
  (or the console is degrading under repeated 24-chunk DMA bursts). Recoverable.

## 2b. Boundary picture (updated after 3rd KP)

- `0x72000000–0x80000000` — **safe**, plaintext (swept, negative for VMCB).
- `0x80000000–0xA0000000` — **fault band** (2.0–2.5 GB), GPU-DMA read panics.
- `0xA0000000` (2.5 GB) — single 2 MB read **safe**, plaintext.
- `0xA0200000` (2.5 GB+2 MB) — panicked on a 24-chunk burst (chunk 1). Cause unconfirmed: either a
  second hole just past 2.5 GB, or GPU-queue/TLB fragility after many DMA bursts. **Needs the klog
  panic text to disambiguate** — deploy klogsrv (3232) on the next boot BEFORE any sweep.

## 3. Resume plan (after re-JB)

1. **Deploy klogsrv first** (`doc_00b1de1b1ab1_klogsrv-ps5.elf` → :9021) so the next KP's fault text
   lands on :3232 (capture with `klog_capture.py`).
2. Boundary-map with SINGLE 2 MB probes (`dump_once.py … <addr> 1`) at 0x84000000/0x88000000/0x8C000000/
   0x90000000 … and 0xA0200000/0xA0400000/0xA0800000 to localize the holes, one probe per re-JB if
   a probe panics.
3. Sweep only the confirmed-safe windows with SMALL chunks (nchunks=4–8), not 24.
4. If the VMCB guest-PA is found → retarget `probe89/vmid7.elf` (WRITE) to `VMCB+0x90` with bit50
   and store 0 to clear NP_ENABLE (disable NPT).

## 1. What the sweep found (192 MB: 0x72000000–0x7e000000)

The region is **NOT uniformly encrypted** (unlike the 4–16 GB band). It is a mix of structured
(low-entropy, zero-heavy) data and a few high-entropy blobs:

- Block entropy histogram (1 MB blocks): **136 / 192 blocks low-entropy (<6.0)**, 22 high (>7.8).
- Many blocks are ~70–90 % zero (page tables / heap / free pages), some 0xFF-heavy (0x72000000–0x72100000).
- A few max-entropy blobs at `0x72b00000–0x72d00000` (ent 7.6–8.0).

**VMCB scan (hard predicate): 0 hits.** No page matches `np_enable@0x90 bit0 && n_cr3@0xB0
4K-aligned && asid@0x58 in [1,16] && intercepts@0x00 != 0 && cs.sel@0x410 in {0x20,0x28,0x33,0x3b}`.

**VCPU-array scan (≥8 u64, const stride): 2 hits, both false positives.** At `0x7a130000`
(44 ptrs) and `0x7a130168` (35 ptrs), stride `0x10000`, first `0x201fa50000` / `0x201ef80000`
(≈8.6 GB, i.e. `0x2xxxxxxxx`). This is the known **page-frame / GPU-structure band**, NOT a VCPU
array (real VCPU arrays increment by `0x2000–0x3000` per VCPU_ARRAY_SEARCH.md; 64 KB stride and
`0x2xxxxxxxx` targets = page stacks / garlic tables).

## 2. NEW FINDING — the GPU-DMA READ also PANICS at 0x80000000 (2.0 GB)

Segments `0x72000000`, `0x75000000`, `0x78000000`, `0x7b000000` dumped clean. Segment
`0x7e000000` completed chunk 15 (`0x7fe00000–0x80000000`) then hard-panicked on chunk 16
(**`0x80000000`**) — console dropped to no-ping (full NIC down), all ports dead.

This is the **same boundary the CPU DMAP sweep hits** ("fault band at 2.0–2.5 GB", HANDOFF.md),
so 2.0 GB is a **hardware/ACPI-reserved boundary, not an NPT trap**: the GPU bypasses the NPT, yet
still faults at 2.0 GB. Consistent with the ACPI reserved region at ~2 GB (FACS PA `0x7fd6e000`,
WRMSR_PROBE_OFFSETS.md). **The GPU-DMA READ is safe for the carve-out and sub-2GB guest RAM but
does NOT make 2.0 GB+ readable.**

Implication: the VMCB/VCPU array, if in this band, must sit in `0x72000000–0x80000000` (the
~224 MB sub-2GB window already swept = negative) **or** above 2 GB, which needs a fresh
boundary probe to see where (if anywhere) GPU-DMA reading becomes safe again.

## 3. Resume plan (after re-JB)

1. Finish `0x7e000000–0x80000000` (32 MB — lost to the panic; the partial 32 MB is still in
   `/data/carveout_7e000000.bin` on the console).
2. **Boundary probe**: GPU-DMA read single 2 MB pages at `0x81000000`, `0x84000000`, `0x88000000`,
   `0x90000000`, `0xA0000000`, `0xC0000000` … to find where the 2 GB fault band ends (if it does).
   One fresh victim per page; do NOT cross 0x80000000 in a contiguous sweep.
3. Sweep the confirmed-readable window above 2 GB, scanning for the VMCB/VCPU predicate.
4. If the VMCB guest-PA is found → retarget `probe89/vmid7.elf` (WRITE) to `VMCB+0x90` with bit50
   and store 0 to clear NP_ENABLE (disable NPT).

## 5. Root cause + garlic fallback (2026-10-06, cross-referenced)

- **The PS5 hypervisor owns the IOMMU** (psdevwiki: "Sony has moved the IOMMU to the Hypervisor",
  hypercalls `IOMMU_SET_GUEST_BUFFERS`=0x6 … `IOMMU_READ_DEVICE_TABLE`=0xc). The GPU (gc0, devid
  0x2000) DMA is translated by the HV's own I/O page table, which maps **only the guest DMA region
  (~0–2 GB)** and leaves **2 GB+ "not mapped"** → `IO_PAGE_FAULT` → panic. This is a *separate* HV
  protection layer from the NPT, and it moves per boot (2.0–2.5 GB edge observed).
- **Net: the GPU-DMA primitive (READ *and* WRITE) is IOMMU-bounded at ~2 GB** — it bypasses the NPT
  only *within* the guest's DMA region. `0x72000000–0x80000000` swept negative; 2 GB+ is unreachable.
- **Garlic aperture is NOT 32–40 GB.** A garlic-mode read (bit-50 off) at `0x800000000` (32 GB)
  faulted. The garlic VRAM pool is ~19.2 GB (`0x47bc004c0`, ~54 MB) — the GPU's own VRAM, not the
  host-DRAM aperture. So the VMCB's host-PA (`0x8xxxxxxxx` from `vm_page.phys`) is NOT reachable via
  the garlic leaf either.
- **Conclusion: the GPU-DMA read/write cannot reach the VMCB** — it is protected by the IOMMU (a
  second HV layer the primitive does NOT bypass) and/or lives at host-PA the GPU aperture can't touch.
  The remaining VMCB paths are the CPU NPT-alias "lucky boot" (Sonic-Iso, ~1-in-12) or the
  a53mm GPU-MMU route (needs kernel R/W). Payload keeps the garlic-mode knob for completeness.


- `probe90/gpread90.elf` was **accidentally overwritten** by a `make` that linked `boundary.o`
  (the CPU-read carve-out probe that PANICS) — root cause of the first KP. Rebuilt from `main3.c`
  (verified: contains "gpread90v3", NOT "READ 0x"/"boundary"); Makefile `OBJS` fixed to `main3.o`.
- `sweep_driver.py`: config-driven 48 MB segments, deploys to :9021, polls FTP for the 48 MB dump,
  pulls it, deletes it; aborts if deploy stdout is not `gpread90v3`. Fixed the `seg = base & ~(SEG-1)`
  bug (48 MB is not a power of 2).
- Dumps land in `scratch/ps5/vmcb_sweep/carveout_<base>.bin`; scan via `scan_vmcb.py`.
