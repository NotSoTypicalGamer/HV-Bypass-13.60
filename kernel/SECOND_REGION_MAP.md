# SECOND REGION MAP — TMR / psp_mbox / a53mm / IOMMU static state (13.60)

Author: pointer-cluster analysis, 2026-10-05. Offline, Python-only, against
`kdata_1360.bin` (15 MB, `.data` base `0xffffffffd0930000`) + cross-checked against
`kdata_761.bin`. FreeBSD 11.0 has **no** AMD-Vi/ccp driver (`sys/x86/iommu/` is Intel-only), so the
IOMMU/TMR/psp_mbox code is **Sony-original** (a53mm module family); FreeBSD source is not an
oracle here — this map is derived from the pointer graph in the `.data` dump.

## 0. TL;DR — what to dump next (read-only)

| Priority | VA range | size | rationale |
|---|---|---|---|
| **1 (must)** | `0xffffffffcfed0000 .. 0xffffffffcff00000` | 128 KB | dense static-state header: TMR cfg, psp_mbox ctl, a53mm ctxt, IOMMU cmdq ctl + all hot singletons |
| **2** | `0xffffffffd0137000 .. 0xffffffffd0138000` | 4 KB | buffer cluster A (37 refs) — IOMMU cmd-queue / event-log candidate |
| **3** | `0xffffffffd0351000 .. 0xffffffffd0352000` | 4 KB | buffer cluster B (32 refs) — psp_mbox ring / a53mm buffer candidate |
| 4 | `0xffffffffd0176000 .. 0xffffffffd0177000` | 4 KB | minor cluster (8 refs) |
| 5 | `0xffffffffd0342000 .. 0xffffffffd0343000` | 4 KB | minor cluster (6 refs) |
| 6 | `0xffffffffd06f7000 .. 0xffffffffd06f8000` | 4 KB | minor cluster (4 refs) |
| **full** | `0xffffffffcfed0000 .. 0xffffffffd0930000` | **0xa60000 (10.4 MB)** | the whole second region, contiguous, below `.data` |

If you can afford one `kernel_copyout` of ~10.4 MB, dump the **full** range — it is the module's
contiguous RW BSS, and read-only dumping a known-mapped region is safe (the skill's standing rule:
only `kernel_copyout` *known-mapped* ranges; never a blind physical sweep). Otherwise do priorities
1–3 in that order.

## 1. Geometry

- `.data` base (13.60): `0xffffffffd0930000`, 15 MB dump = `0xd0930000 .. 0xd1830000`.
- **Second-region base (13.60): `0xffffffffcfed0000`** = `.data` base − `0xa60000`.
  (7.61: `0xffffffff94bc0000` = its `.data` base `0xffffffff95570000` − `0x9b0000` — same module,
  different slide + internal shift.)
- Extent: distinct pointer targets span `rel 0x0008 .. 0x996ee0`
  (`0xffffffffcfed0008 .. 0xffffffffd0866ee0`), i.e. the region runs from its base to ~10.0 MB
  below `.data`; the last ~424 KB below `.data` (`0xd0867000 .. 0xd0930000`) has **no** inbound
  pointers (top of BSS / alignment).

Pointer inventory (8-byte aligned scan of the dump for values in
`[0xffffffffcfed0000, 0xffffffffcfed0000+0x1000000)`):

- 7439 total hits; **6878** have value **below** the `.data` base (true second-region references);
  561 fall *inside* the `.data` dump range (self-referential `.data` pointers, not second-region —
  ignore).
- **6776 of 6878 (98.5%) land in the first 128 KB** (`rel 0 .. 0x20000`). That 128 KB is the dense
  "static state" header; the remaining ~10 MB is large, sparsely-referenced BSS (buffers/page tables).

### Zone histogram (64 KB buckets, 13.60)

```
rel 0x000000..0x020000  ->  6776  (5987 in 0..0x10000, 789 in 0x10000..0x20000)
rel 0x260000            ->    37   (0xffffffffd0137000)
rel 0x2a0000            ->     8   (0xffffffffd0176000)
rel 0x470000            ->     6   (0xffffffffd0342000)
rel 0x480000            ->    32   (0xffffffffd0351000)
rel 0x820000            ->     4   (0xffffffffd06f7000/8000)
rel 0x990000            ->     2   (0xffffffffd0866000)
+ singles at 0x80000, 0xa0000, 0x170000, 0x1d0000, 0x310000, 0x560000, 0x570000, 0x5c0000, 0x610000
```

## 2. Pointer clusters (the shared singletons)

Top distinct target addresses and how they are referenced from `.data`:

| target VA | rel | refs | storage pattern in `.data` | inference |
|---|---|---|---|---|
| `0xffffffffcfed5760` | 0x5760 | **607** | 48-byte-stride array @ `0xd0ade5c0..0xd0aec000`; ptr at +0x08; +0x28 = `0x100000000` | **a53mm global/context root** — every entry of a 607-element 48-byte table points here |
| `0xffffffffcfed1098` | 0x1098 | 235 | 112-byte structures @ `0xd16df000..0xd1758000` (mixed stride 80/112/464); also at +0x10 of IOMMU MMIO-holding structs | **IOMMU (AMD-Vi) shared root** (lock/list-head) |
| `0xffffffffcfed10a0` | 0x10a0 | 235 | identical histogram to 0x1098 (same entries, adjacent field) | IOMMU root, second qword (mutex/list) |
| `0xffffffffcfee09e8` | 0x109e8 | 173 | 96-byte stride array | second shared object (psp_mbox ctl candidate) |
| `0xffffffffcfee09f8` | 0x109f8 | 129 | 96-byte stride, `0xd172b000..0xd172e000` | adjacent field of 0x109e8 |
| `0xffffffffcfedd710` | 0xd710 | 121 | 88-byte stride | singleton (a53mm input-ring ctl candidate) |
| `0xffffffffd0137e50` | 0x267e50 | 37 | scattered | **large DMA buffer** (IOMMU cmd-queue / event-log) |
| `0xffffffffd0351810` | 0x481810 | 32 | scattered | **large DMA buffer** (psp_mbox ring / a53mm cmd buffer) |
| `0xffffffffcfed8550` | 0x8550 | 54 | scattered | singleton |

### The 40-byte-stride `.data` array → 8-byte-stride target array

A 40-byte-stride array in `.data` (`0xffffffffd16dca18 .. 0xffffffffd16e16e8`, ~450+ entries) has a
pointer at +0x18 into a **contiguous array of 8-byte elements** at
`0xffffffffcfed0cf0 .. 0xffffffffcfee09e8` (stride 8, ~0x100f8 = 64 KB / 8 ≈ 8200 slots). Each
40-byte `.data` record therefore owns an 8-byte slot in the second region. This is the classic shape
of a **per-entity ring/queue of 8-byte control words** (a53mm input-ring command slots or psp_mbox
command slots). The paired singletons `0xcfed1098/0xcfed10a0` sit immediately after this array —
consistent with a ring-control header (head/tail/lock) following the slot array.

### IOMMU unit-context shape (confirmed)

Structures at `.data` `0xd1701b58`, `0xd1702108`, `0xd1702528`, `0xd1702c88` (…one per IOMMU MMIO
window) have the repeating layout:

```
+0x00  IOMMU MMIO window base   (0xffffec8c0115xxxx .. 0xffffec8c011dxxxx, 16 KB stride = 8 windows)
+0x08  status/flags             (often 0x200000001)
+0x10  0xffffffffcfed1098        <-- the shared IOMMU root (second region)
+0x18  self/.data pointer
```

8 IOMMU MMIO windows at 16 KB stride (`0xffffec8c01130000` base, +0x4000 each) → 8 IOMMU units
(A53/ACP + device groups). Each unit context references `cfed1098`, so **`cfed1098` is the AMD-Vi
driver's shared root object** and the command-queue/event-log buffers are reachable from it.

## 3. Structure identification (confidence)

- **IOMMU root** = `0xffffffffcfed1098` (+ `0xcfed10a0` adjacent). **HIGH** — every IOMMU
  unit-context points here at a fixed offset.
- **IOMMU command queue / event log** = buffer at `0xffffffffd0137e50` (rel 0x267e50, 37 refs) or
  `0xffffffffd0351810` (rel 0x481810, 32 refs). **MEDIUM** — these are the only large (>4 KB)
  second-region clusters; both are ring-buffer candidates. Confirm by dumping and looking for a
  power-of-two buffer + head/tail, and 16-byte command entries.
- **psp_mbox ring** = `0xffffffffcfee09e8/0x09f8` (96-byte-stride referencing array) or
  `0xffffffffcfedd710`. **MEDIUM** — `psp_mbox_send_sysmail`/`encode_kernel_text`/`map_tmr` are the
  a53mm PSP functions; their mailbox control + ring live in the dense header.
- **a53mm context/VMID table** = the 607-entry 48-byte table → `0xffffffffcfed5760`. **MEDIUM** —
  a53mm owns VMID alloc + per-app input rings; the 607-entry table matches a per-context pool.
- **TMR config** = small array in the dense header (`0xffffffffcfed0000 .. 0xffffffffcfee0000`).
  **LOW (location only)** — TMR is managed via `psp_mbox_map_tmr`; the config register shadow is in
  the header but its exact offset needs the dump to pin. It is *not* the 8-byte-stride array.

## 4. hv_defeat_0304 targets (IOMMU-write primitive)

The public 3.00–4.51 method (ps5-linux-loader) that the 13.60 work extends:

1. **TMR relaxation** — write `TMR_CFG_PERMISSIVE = 0x3F07` to TMR config registers **idx 5, 16, 17,
   18**. On 13.60 these config values/shadow live in the dense header (`0xffffffffcfed0000..cfee0000`);
   the actual MMIO is outside the second region. Dump the header first to locate the config array.
2. **IOMMU write primitive** — enqueue an AMD-Vi **COMPLETION_WAIT (opcode 0x05)** command in the
   IOMMU **command queue** (buffer candidate `0xffffffffd0137e50` / `0xffffffffd0351810`), with
   `store_addr = VMCB_PA + 0x90`, `store_data = 0`. The IOMMU writes `store_data` to `store_addr`
   bypassing CPU/HV permissions — zeroing the VMCB **VMMCALL intercept** at **offset 0x90**.
3. **VMCB PA** — **not in this region** (hypervisor memory). 13.60 value unknown → comes from the
   NPT lead (`hvscan` physical sweep), *not* this map. Historical anchors: `0x6290B000`
   (3.00–3.21) / `0x62A05000` (4.00–4.51) + `core*0x3000`.
4. `vmmcall` on every core to force VMCB reload.

Command-entry format reminder (AMD-Vi): 16-byte entries; COMPLETION_WAIT carries a `store_addr`
(hi/lo) and `store_data` field — the write primitive's payload.

## 5. Cross-firmware validation (7.61)

Same analysis on `kdata_761.bin` (`.data` `0xffffffff95570000`, region `0xffffffff94bc0000`) gives
the **identical shape**: 7709 below-base pointers, 7615 (98.8%) in the first 128 KB, and the same
singleton count profile — 607 / 204+204 / 173 / 129 / 114 — plus the same 64 KB zone skeleton
(34+8+31+… clusters). The module is the same; only the slide and the internal rel offsets shift
(7.61 top singleton at `rel 0x100c8` vs 13.60 `rel 0x5760`). This confirms the second region is a
**stable, KASLR-slid module BSS**, present across firmware, and that the 13.60 map is not a
one-off artifact.

## 6. Next step

Dump the full range `0xffffffffcfed0000 .. 0xffffffffd0930000` (read-only). Then:
1. In the dense header, find the TMR config array (look for 19×8/16-byte slots holding values near
   `0x3F07`-style masks) → pin TMR cfg offset.
2. In the buffer clusters, find the power-of-two ring with 16-byte entries → pin IOMMU cmd-queue
   base + head/tail.
3. Trace `cfed1098` → cmd-queue → confirm the COMPLETION_WAIT enqueue path and the `store_addr`
   slot.
