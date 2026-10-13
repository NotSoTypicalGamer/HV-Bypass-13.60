# IOMMU MMIO / Command-Buffer Physical Addresses — 13.60 (kdata_1360.bin)

Goal: pin the two physical addresses needed for the AMD-Vi COMPLETION_WAIT write primitive —
(1) the IOMMU MMIO register base PA, (2) the IOMMU command-buffer PA. Analysis is fully
offline against `kdata_1360.bin` (15,728,640 B, .data base VA `0xffffffffd0930000`) and the
FreeBSD amdvi register model (`struct amdvi_ctrl`, `amdvi_priv.h`, vmm copy at
`release/12.0.0:sys/amd64/vmm/amd/amdvi_priv.h` — the register layout is identical to the host
driver Sony's `iommudrv` ports).

---

## 1. DMAP base = 0xffffec8c00000000 (PROVEN)

The ctrl VAs are **direct-map (DMAP) VAs**, not device-KVA remaps as the earlier CMDBUF note
assumed. Proof from the dump:

- A full sweep of every 8-byte-aligned 64-bit value in `.data` finds **300 distinct values with
  top 32 bits == `0xffffec8c`** (i.e. `0xffffec8cxxxxxxxx`). Their low 32 bits are page- (mostly
  0x4000-) aligned physical addresses in the low tens-of-MB range — exactly the signature of a
  direct map whose base is `0xffffec8c00000000` (`PHYS_TO_DMAP(pa) = 0xffffec8c00000000 + pa`).
- The 8 window ctrl values `0xffffec8c01130000 + N*0x4000` are all `0x4000`-aligned
  (low 14 bits = 0), matching `CTASSERT(sizeof(struct amdvi_ctrl) == 0x4000)`. Subtracting the
  DMAP base gives `PA = 0x1130000 + N*0x4000`, so the 0x4000 stride is in *physical* space — the
  IVHD "I/O MMU unit" BaseAddress values, not a software remap.
- The same 300-value set contains the other windows found earlier (win −1 … win 13) plus a much
  wider `0x1014000 … 0x1268000` 0x4000-stride run that belongs to *other* drivers' MMIO windows
  (each softc = `[method_ptr][ctrl DMAP VA]`, e.g. `0xffffec8c01030000` @ file `0xdfa318` with
  method ptr `0xffffffffd0f81722` ≠ the IOMMU's `0xffffffffd0fabe59`).

**Conclusion: DMAP base for this boot is `0xffffec8c00000000`.**

Cross-check with FreeBSD `ivrs_drv.c` (`ivhd_attach`): `softc->ctrl = PHYS_TO_DMAP(ivhd->BaseAddress);`
so the softc `ctrl` field *is* `PHYS_TO_DMAP(MMIO_base)`. `PHYS_TO_DMAP(0x1130000) = 0xffffec8c01130000`
⇒ **MMIO base PA = 0x1130000**.

## 2. MMIO base PA and derived registers (CONFIRMED)

From `struct amdvi_ctrl` (offsets are `CTASSERT`-checked in the header):

| Register | Offset | PA (win0) |
|----------|--------|-----------|
| Device Table Base  | +0x0000 | 0x1130000 |
| Command Buffer Base (CBRB) | +0x0008 | 0x1130008 |
| Event Log Base     | +0x0010 | 0x1130010 |
| Control            | +0x0018 | 0x1130018 |
| cmd_head           | +0x2000 | 0x1132000 |
| **cmd_tail (doorbell)** | **+0x2008** | **0x1132008** |
| evt_head / evt_tail| +0x2010 / +0x2018 | 0x1132010 / 0x1132018 |
| **status**         | **+0x2020** | **0x1132020** |

So, as the task hypothesised:
- **Doorbell (command tail) = `0x1130000 + 0x2008` = `0x1132008`**
- **Status register = `0x1130000 + 0x2020` = `0x1132020`**

`cmd.len = 8` (256 × 16-byte entries ⇒ 4 KiB command buffer) and `dte.size = 0x1FF`
(512 × 32-byte entries ⇒ 16 KiB device table) are confirmed from the register bit-layout
(`cmd.base[51:12]`, `cmd.len[59:56]`; `dte.base[51:12]`, `dte.size[8:0]`).

## 3. Command-buffer PA: NOT recoverable from .data alone

The command-buffer **VA** is `0xffffffffd31e4000` (event log `0xffffffffd31e6000`, region size
`0xd3c0`), stored in the iommudrv "region header" at file `0xe0ef18` (13 × 8-byte fields):
`f0/f1 = 0xffffffffd31e4000`, `f2 = 0xd3c0`, `f7/f8 = 0xffffffffd31e6000`, `f9 = 0x1000000008`
(= `(0x10<<32)|8`), `f10 = 0x340000003`. **No PA field** — the region header holds VAs + size only.

That VA `0xffffffffd31e4000` is a *kernel-map* KVA (top word `0xffffffff`), **not** a DMAP VA
(`0xffffec8c...`), so `PA = VA − DMAP_base` does **not** apply. Its PA is produced by
`vtophys(softc->cmd)` (`pmap_kextract` page-table walk) at init and written **only** into the MMIO
`cmd.base` register (offset +0x08) as `(cmd_pa>>12) | (8<<56)`. That register value is hardware
MMIO, not shadowed in `.data`.

Two page-aligned PA-like values were found and ruled out:

- **`0x1030000`** — appears 27× as field 0 of the 27-entry, 0x68-byte per-device context table
  (`0xe0ef80 … 0xe0fa00`), each with `f4 = 0x1FF` (= `dte.size`) and `f3 = 0x2000000NN`,
  `f5 = 0xffffffffd31e6xxx` (per-device buffer in the DMA region), `f9 = (0x10+NN)<<32 | 8`.
  This is the **device-table (or identity-domain root-page-table) PA**, *shared* across all
  contexts, **not** the command buffer: it sits on the device-MMIO 0x4000 stride
  (`= 0x1014000 + 7*0x4000`), it is itself DMAP-mapped (`0xffffec8c01030000` @ `0xdfa318`), and
  its event-log counterpart `0x1032000` (= cmd+0x2000) appears **nowhere** in the dump.
- **`0x1b00000`** — only ever appears inside the packed constant `0x0100000001b00000`
  (`(1<<56)|0x1b00000`), which occurs **39×** spread across unrelated driver regions
  (`0xdd5138 … 0xe28648`). That is a shared DMA-tag/flags constant, **not** a buffer PA.

**Exact remaining step (one of):**
1. **Read the CBRB register at MMIO PA `0x1130008`** (or its DMAP VA `0xffffec8c01130008`).
   `cmd_buf_pa = reg[51:12] << 12` (the low 52 bits, since the buffer is page-aligned).
2. Or `pmap_kextract(0xffffffffd31e4000)` via the kernel's own page tables (`kernel_pmap.pm_cr3`)
   — requires physical-memory read, which `.data` does not provide.

Once `cmd_buf_pa` is known, inject COMPLETION_WAIT via `PHYS_TO_DMAP(cmd_buf_pa)`
(= `0xffffec8c00000000 + cmd_buf_pa`), then ring the doorbell by writing the new tail to
**`0x1132008`** (MMIO cmd_tail, 19-bit index).
