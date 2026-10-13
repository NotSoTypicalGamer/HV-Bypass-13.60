# Root-0 NPT Read/Write — How We Got Here

Handoff for the PS5 13.60 hypervisor-defeat effort. This covers **only** how the
root-0 NPT read/write primitive was established — not the VMCB hunt, not the
NPT-takeover plan.

## Goal (one line)

Defeat the 13.60 hypervisor by clearing `NP_ENABLE` at `VMCB+0x90`. The blocker is
*reaching* the VMCB — it sits in a gated HV region. The root-0 NPT window is the lever.

## 1. The discovery: a readable + writable window into the HV's own NPT

- The HV's NPT (its stage-2 page table) is exposed at the **guest-PA `0x605f0000–0x607fffff`**.
  This is the "root-0 NPT" window.
- It reads **ciphertext** — SME AES-128-XTS. The HV stores the NPT encrypted; the guest
  reads it with C-bit **clear**, so it sees ciphertext, not the entries.
- The C-bit clear is **deterministic (3/3 boots)**, not a coin flip — despite the early
  "lucky boot" framing.
- The window is the **NPT page tables** (sparse ciphertext pages every ~`0x10000`,
  separated by raw zeros), **not the VMCB** — a 200 ms temporal diff showed 0/512 pages
  change, and the VMCB is elsewhere (`0x60000000–0x605effff`).

## 2. The read primitive (GPU-DMA via `/dev/gc`)

- `/dev/gc` (the **dev vmid**, 6 on 13.60) + garlic direct-memory.
- **Allocation size controls the leaf format**: 64 KB / 256 KB / 1 MB → **8 KB leaves**
  (system-RAM-capable); 2 MB → 2 MB leaves (VRAM-only). Use 64 KB.
- **Bit 50** ("system coherent") in the retargeted leaf routes the DMA to system RAM —
  a garlic leaf without it decodes against the VRAM aperture and silently misses.
- Read: retarget the victim leaf's PTE to the target PA
  `(raw & ~0x0000FFFFFFFFE000) | (pa & 0x0000FFFFFFFFE000) | (1<<50)`,
  DMA-copy victim→staging, then restore the PTE.
- Confirmed reading the window (ciphertext, `distinct=256/256`) and the guest's DRAM.

## 3. The write primitive (same path, reversed)

- DMA-copy staging→victim (victim leaf retargeted to the target PA with bit 50), then
  restore the PTE.
- **KDATA-WRITE-PASS** (`probe89/vmid7.elf`): sentinel lands in kernel `.data`, read back
  clean through the kernel's C-bit-SET mapping → the write to guest DRAM is **encrypted/clean**.
- **WRTEST** (2026-10-07, `probe90/sweep.elf`): sentinel `0xDEADBEEFCAFEBABE` written to
  `0x605f2000` (a zero chunk in the window) — `ioctl=0`, readback `bebafecaefbeadde` =
  the sentinel (little-endian) → the GPU-DMA write **lands in the NPT window**.
- Write to the no-access region (`0x60000000–0x605effff`) is **dropped** by the IOMMU
  (no panic, no data) — that region stays unreachable even for the GPU-DMA write.

## 4. Key properties + the open question

- The window is **readable AND writable** through the GPU-DMA bit-50 path.
- Since the NPT is the HV's memory-authority table, writing it is the lever to remap the
  VMCB region as accessible (the NPT takeover — not covered here).
- **Open question:** the WRTEST readback is via the GPU-DMA's *raw* (C-bit-clear) path, so
  the sentinel match means the window write was stored **raw**. The HV reads the NPT
  **encrypted** (C-bit set) — so a raw write may decrypt to garbage from the HV's view,
  unlike the KDATA write (guest DRAM, C-bit set, clean). Confirming whether the HV sees
  the NPT-window write cleanly is the deciding test for the takeover write.

## Key files

- `kernel/ROOT0_NPT_WINDOW.md` — live-confirmed model (window layout, C-bit, write-drop).
- `kernel/DEVGC_VMID_REBIND.md`, `kernel/GPU_DMA_GARLIC_FIX.md` — the bit-50 + 8 KB-leaf fix.
- `probe89/main7.c` (KDATA-WRITE-PASS), `probe90/sweep.c` (read + WRTEST write-landing).
