# IOMMU Command-Buffer PA Reconstruction — 13.60 .data dump

Goal: recover the AMD-Vi command-buffer **physical address** for each IOMMU window from
`kdata_1360.bin` alone, so a COMPLETION_WAIT entry can be written to it via the kernel DMAP
without reading the (unreadable) MMIO.

**Verdict: the 52-bit command-buffer PA is NOT stored in `.data`.** Only the *virtual*
addresses (softc `cmd` VA + MMIO VA) are present; the PA is computed by `vtophys()` at init time
and written solely to the MMIO command-buffer base register, which is not readable. Details below.

---

## 1. Driver cross-reference (FreeBSD amdvi)

Sony's `iommudrv` is a port of the FreeBSD amdvi driver (the `io/iommu.h` interface — strings
`amd_iommu_unmap`, `"Sys event log"`, `"failed to allocate device table entry"` are all present
in the dump). The register layout is `struct amdvi_ctrl` (`amdvi_priv.h`), a 0x4000-byte MMIO
block, and the per-unit software state is `struct amdvi_softc`.

The relevant init path (stock FreeBSD, `ivrs_drv.c` + `amdvi_hw.c`):

```c
/* ivrs_drv.c: ivhd_attach() */
softc->ctrl = PHYS_TO_DMAP(ivhd->BaseAddress);   /* MMIO base -> VA (Sony remaps to 0xffffec8c...) */

/* amdvi_hw.c: amdvi_init_cmd() */
softc->cmd      = malloc(sizeof(struct amdvi_cmd) * softc->cmd_max, M_AMDVI, M_WAITOK | M_ZERO);
ctrl->cmd.len   = 8;                             /* 256 entries */
ctrl->cmd.base  = vtophys(softc->cmd) / PAGE_SIZE;   /* <-- PA>>12, written to MMIO ONLY */

/* amdvi_hw.c: amdvi_init_event() */
ctrl->event.base = vtophys(softc->event) / PAGE_SIZE;

/* amdvi_hw.c: amdvi_init_dte() */
ctrl->dte.base  = vtophys(amdvi_dte) / PAGE_SIZE;
ctrl->dte.size  = 0x1FF;
```

Key point: `softc->cmd` holds a **virtual address** (malloc'd kernel-heap KVA). The physical
address exists only transiently inside `vtophys()` (a `pmap_kextract` page-table walk) and is
then latched into the MMIO register `cmd.base` (offset 0x08, PA in bits [12:51], len in bits
[56:59]). The softc does **not** retain the PA.

### `struct amdvi_ctrl` MMIO register offsets (0x4000 block)

| Offset | Register                | Contents |
|--------|-------------------------|----------|
| 0x00   | Device Table Base       | size[8:0], base[51:12] = dte PA>>12 |
| 0x08   | Command Buffer Base     | base[51:12] = cmd PA>>12, len[59:56]=8 |
| 0x10   | Event Log Base          | base[51:12], len[59:56] |
| 0x18   | Control                 | EN/CMD/ELOG/... bits |
| 0x2000 | Command Head pointer    | 19-bit |
| 0x2008 | Command Tail (doorbell) | 19-bit |
| 0x2010 | Event Head              | 19-bit |
| 0x2018 | Event Tail              | 19-bit |
| 0x2020 | Status                  | 19-bit |

All of these live in **hardware MMIO** (unreadable via `kernel_copyout` per prior findings).
`cmd_head`/`cmd_tail` are reset to 0 at init and only ever touched via MMIO writes — they are
**not** shadowed in `.data`.

---

## 2. The 8 per-window unit contexts (softc `ctrl` = MMIO VA)

The MMIO VAs are `0xffffec8c01130000 + N*0x4000`, N=0..7. Each appears exactly once in `.data`
as the first field (`ctrl`) of its softc. `PHYS_TO_DMAP()` is **not** used on PS5 — Sony maps the
MMIO at device KVA `0xffffec8c01xxxxxx`, so `ctrl` is that KVA, not a DMAP address.

| Window | MMIO VA (ctrl)          | File offset | VA (data base 0xffffffffd0930000) |
|--------|-------------------------|-------------|-----------------------------------|
| 0      | 0xffffec8c01130000      | 0xe0caf8    | 0xffffffffd173caf8                |
| 1      | 0xffffec8c01134000      | 0xe0ca58    | 0xffffffffd173ca58                |
| 2      | 0xffffec8c01138000      | 0xe0d678    | 0xffffffffd173d678                |
| 3      | 0xffffec8c0113c000      | 0xe0d8c8    | 0xffffffffd173d8c8                |
| 4      | 0xffffec8c01140000      | 0xe0db38    | 0xffffffffd173db38                |
| 5      | 0xffffec8c01144000      | 0xe0dc68    | 0xffffffffd173dc68                |
| 6      | 0xffffec8c01148000      | 0xe0e0b8    | 0xffffffffd173e0b8                |
| 7      | 0xffffec8c0114c000      | 0xe0e128    | 0xffffffffd173e128                |

The softc entries are not uniformly spaced (windows 0/1 are 0xa0 apart, 2–5 scattered, 6/7/8 in a
0x70-byte run) because they are inline after newbus `device_t` structs allocated at scattered
addresses. **Additional windows exist beyond N=7** — ctrl pointers were also found for N=−1
(0xffffec8c0112c000 @ 0xe0cad8), N=8 (0xffffec8c01150000 @ 0xe0e198), N=9 (0x...154000 @
0xdd1b58), N=10 (0x...158000 @ 0xe0eb78), N=11 (0x...15c000 @ 0xe0ed18), N=12 (0x...160000 @
0xe0eef8), N=13 (0x...164000 @ 0xe0fd68). The PS5 exposes >8 IOMMU MMIO windows/units (or the
0x4000-stride mapping spans a larger device region); the "8 windows" figure is a lower bound.

---

## 3. DMA buffers: VAs only, no PAs

The command buffer / event log are malloc'd DMA buffers in the kernel heap. A DMA-buffer
descriptor table lives at `.data` file offset **0xe0ef18** (0x68-byte entries; entry 0 is the
region header, entries 1+ are per-device contexts). It references:

| Buffer | Heap KVA (VA)           | Notes |
|--------|-------------------------|-------|
| DMA region base (cmd buf) | 0xffffffffd31e4000 | page-aligned, 4 refs (0xe0ef18, 0xe0ef20, 0xe0f9c8, 0xe0f9d0) |
| Event log base            | 0xffffffffd31e6000 | page-aligned, 2 refs (0xe0ef50, 0xe0ef58) |
| region size field         | 0xd3c0 (=54144 B)  | at 0xe0ef28 |

`0xffffffffd31e4000` and `0xffffffffd31e6000` are the only page-aligned heap KVAs tied to the
iommudrv data (the only other candidates in the `0xffffffffd3xxxxxx` range). These are **kernel
map (KVA) addresses** (top word `0xffffffff`), **not DMAP addresses** (`0xffffff80_xxxxxxxx`), so
`PA = VA − 0xffffff8000000000` does **not** apply. The buffers sit above the dump
(`0xffffffffd31e4000 > 0xffffffffd1830000` = dump end) and are not themselves present in `.data`.

No page-aligned physical-address value matching these buffers (a one-off PA like `0x1A2B3000`)
appears anywhere near the unit contexts or the descriptor table; the only page-aligned "PA-range"
values in the dump are round DMA-boundary/page-table constants (`0x100000000` ×992,
`0x88000000` ×488, `0x200000000` ×382, `0x40000000` ×138, …), not per-buffer PAs.

---

## 4. What is / is not recoverable from `.data` alone

**Recoverable (this analysis):**
- MMIO VA per window (`softc->ctrl`) — §2 table.
- Command-buffer / event-log **virtual** addresses — `0xffffffffd31e4000` / `0xffffffffd31e6000`.
- `cmd.len = 8` (256 × 16-byte entries ⇒ 4 KB command buffer) and `dte.size = 0x1FF`.

**NOT recoverable from `.data` alone:**
- **Command-buffer PA (52-bit)** — exists only in MMIO register `cmd.base` (offset 0x08,
  `= vtophys(cmd) >> 12`). Needs an MMIO read (unreadable) or a `pmap_kextract` page-table walk
  (kernel page tables are not in the `.data` dump).
- **cmd_head / cmd_tail** — MMIO 0x2000/0x2008, initialized to 0, never shadowed in `.data`.
- **Device-table PA** — MMIO 0x00 (`= vtophys(amdvi_dte) >> 12`).
- **Event-log PA** — MMIO 0x10.

---

## 5. Implication for the COMPLETION_WAIT write primitive

To inject a COMPLETION_WAIT (`opcode=0x1`, `word0 = (cmp_data_PA & ~0x7) | STORE(1)`,
`word1 = cmp_data_PA[51:32]`, `addr = value-to-write`) into the command buffer via
`PHYS_TO_DMAP(cmd_buf_pa)` you still need `cmd_buf_pa`, which `.data` does not provide. The two
ways forward from here (both outside this binary-only task):

1. **Read the MMIO** `cmd.base` register through the DMAP at the IOMMU *physical* MMIO address
   (obtain the physical MMIO base from the IVRS ACPI table or PCI ECAM at 0xF0000000, not the
   `0xFED80000` guess — the MMIO PA is non-standard on PS5), then `cmd_buf_pa = cmd.base << 12`.
2. **`pmap_kextract` the buffer KVA** `0xffffffffd31e4000` from the kernel's own page tables
   (or a `vtophys`-equivalent primitive).

Either way, the *tail* must also be advanced via an MMIO write to `cmd_tail` (0x2008 doorbell)
before the hardware executes the injected command.
