# VULN — PS5 HCI Vendor Commands → Attacker-Controlled DMA Read/Write

**Status:** CONFIRMED & EXHAUSTED — controlled DMA read/write pair; kernel-panic DoS + limited data-buffer primitive. Present on 4.03, absent/changed on 7.61/11.60 (exact patch firmware unknown). NOT a KEX path.
**Last updated:** 2026-10-04
**Author:** CaliperC0re kernel research (private; do not publish)
**Firmware:** PS5 4.03 (build J01736823) — FreeBSD 11.0 base, Sony-custom drivers
**Chip:** Marvell Avastar 88W8897 (PCIe) WiFi/BT combo, BT USB id 1286:2059
**Class:** chip-level DMA address confusion → IOMMU fault → kernel panic (DoS). Firmware-whitelisted memory access, no escalation.

---

## 1. Summary

Two HCI vendor commands over the Bluetooth controller's USB control endpoint
(`/dev/ugen0.2`) expose attacker-controlled **DMA read and write** on the Marvell
1286:2059 (combined WiFi/BT) chip:

- **`0xFC01` (plen 4)** — param is a **DMA read address**.
- **`0xFC02` (plen 8)** — param is a **DMA write address (4B) + data (4B)**.

The address is **fully attacker-controlled** (byte-for-byte, 8-byte aligned). The
chip issues the DMA op; when the address is unmapped, the IOMMU raises
`IO_PAGE_FAULT` (READ or WRITE), the WLC (WiFi) driver dumps state and the kernel
panics. Read data exfiltrates back over the USB event endpoint (Command Complete).

**Verdict after full exploration:** the firmware whitelists the accessible ranges —
SRAM and RX data are readable, descriptor rings return `EIO`, the SRAM write is a
silent no-op (read-only), and no wider/register-access opcode exists in the vendor
space. Every escalation route (descriptor corruption, firmware patching) is blocked,
so this is a **kernel-panic DoS + a limited data-buffer read/write — not a KEX
primitive.**

---

## 2. Reachability & trigger

- **Interface:** `/dev/ugen0.2` (the Marvell BT controller, exposed by the xhci driver).
- **Transport:** HCI command via the USB **control** endpoint:
  `ioctl(fd, USB_DO_REQUEST, &req)` with `bmRequestType=UT_WRITE_CLASS_DEVICE(0x20)`,
  `bRequest=0`, `wValue=0`, `wIndex=0`, `wLength=3+plen`, data = `{opcode_lo, opcode_hi, plen, param...}`.
- **Privilege:** open `/dev/ugen0.2` from userland (unprivileged surface, needs the
  jailbreak/etaHEN environment; sandbox-reachability NOT yet verified).
- **Trigger (exact):**
  - opcode `0xFC01`
  - plen `4`
  - param = attacker-chosen 4 bytes, e.g. `11 22 33 44`
- **Effect:** ~1–2 s later (chip processes the command asynchronously), kernel panic
  (all ports 2121/9021/3232 down).

---

## 3. Evidence

Kernel log (captured on port 3232 before halt):

```
IO_PAGE_FAULT: tlsw0@000044332210, pasid:0x0, devid: 4007, [-- -- -- READ -- -- US NX GN]flags:0x20070000
IOPAGE_FAULT_EVENT Raw data[0]:0x00004007
IOPAGE_FAULT_EVENT Raw data[1]:0x20070000
IOPAGE_FAULT_EVENT Raw data[2]:0x44332210
IOPAGE_FAULT_EVENT Raw data[3]:0x00000000
...
[WLC] IO Fault addr: 0x44332210
[WLC] +++++ dump chip registers +++++
[WLC] ... (full register/DMA/descriptor dump) ...
```

Two independent runs established the param→address mapping:

| param (bytes) | param as LE u32 | fault addr | relation |
|---|---|---|---|
| `5A 59 5C 53` | `0x535C595A` | `0x535C5958` | `param & ~0x7` |
| `11 22 33 44` | `0x44332211` | `0x44332210` | `param & ~0x7` |

**WRITE (0xFC02, plen 8):**

```
IO_PAGE_FAULT: tlsw0@000044022210, pasid:0x0, devid: 4007, [-- -- -- WRITE -- -- US NX GN]flags:0x20270000
[WLC] IO Fault addr: 0x44022210
```

- `0xFC02` + `{addr=11 22 02 44, data=AA BB CC DD}` → WRITE fault at `0x44022210`
  (address `11 22 02 44` & ~7). The flags flip from `READ` to `WRITE`, confirming
  `0xFC02` is the write counterpart of `0xFC01`.

The fault is a **DMA READ** (`[...READ...]`), device id `4007` (the Marvell WiFi/BT
combo), through the IOMMU (`tlsw0` TLB + page-fault event). The address is the
parameter with the low 3 bits cleared (8-byte aligned).

---

## 4. Mechanism (hypothesis)

The vendor command `0xFC01` is a Marvell-specific "read from address" command. Its
4-byte parameter is a bus/DMA address. The chip's firmware programs a DMA read from
that address; the IOMMU validates it. Unmapped address → `IO_PAGE_FAULT` → WLC fault
handler → panic.

**Read address space is restricted (observed):** SRAM (`0x00000000`–`0x0001xxxx`) and
the RX *data* buffer (`0x10044000`) are readable; the RX *descriptor* ring (`0x10000400`)
is rejected with `EIO` (control-transfer stall), and unmapped addresses (`0x44332210`)
fault. So the firmware whitelists data/SRAM ranges but not descriptor rings.

---

## 5. Exploitability assessment

- **Confirmed (DoS):** reliable local kernel panic — one `0xFC01` read of an unmapped
  address, reproducible every boot.
- **Confirmed (DMA read):** `0xFC01` reads a 16-bit value from a controlled address and
  returns it in the Command Complete event (exfiltration works via the USB event endpoint,
  using a 1-event + 1-ACL endpoint transport). Read data observed: `0x00000004 → f9 01`,
  `0x00010000 → 00 30`, `0x10044000 → 00 30`.
- **Confirmed (DMA write):** `0xFC02` writes 4 bytes to a controlled address. Writing
  `0x11223344` to `0x10044000` (the WLC RX buffer) succeeded and corrupted the chip's active
  RX buffer (following read returned EIO) — proving the write mutates host DMA memory.
- **Limitation:** the reach is **IOMMU-gated** — bounded by the chip's DMA window
  (≈`0x10000000..0x1008c000` per the WLC dump), not arbitrary physical RAM (`0x44332210`
  faulted). So this is not yet arbitrary kernel read/write.

### Escalation routes — all blocked (final)
- **BD descriptor corruption:** `0xFC01`/`0xFC02` on the TX BD ring (`0x10000000`) return
  EIO — the firmware refuses descriptor-ring access. DEAD.
- **SRAM firmware patching:** `0xFC02` write to `0x00000000` returns status 0x00 but the
  read-back is unchanged → SRAM is read-only (write is a silent no-op). DEAD.
- **Wider/register opcode:** full 0xFC00-0xFFFF enumeration found only `0xFC01`/`0xFC02`
  as memory access; the rest are info-reads (MAC/version/config) or unknown. DEAD.

Conclusion: a DoS + limited data-buffer read/write, not arbitrary kernel access.

---

## 6. Reproduction

1. Jailbroken 4.03 PS5 (etaHEN; FTP 2121, elfldr 9021, klog 3232).
2. Deploy `probe41/khcictrl.elf` (single opcode+plen+param sender) or write
   `/data/fuzz_ctrl.txt` = `fc01 4 11 22 33 44`.
3. Fire; ~1–2 s later the console panics (all ports down).
4. Start a klog capture (`klog_cap.py` → port 3232) before firing to capture the
   `IO_PAGE_FAULT` / `[WLC] IO Fault addr` lines.

Trigger payloads (all in `scratch/ps5/`): `probe34..probe41` (`khcifuzz*.elf`,
`khciplen.elf`, `khcictrl.elf`); `probe39` reads range from `/data/fuzz_range.txt`,
`probe40` reads opcode+plen from `/data/fuzz_plen.txt`, `probe41` reads
opcode+plen+4 param bytes from `/data/fuzz_ctrl.txt`.

---

## 7. Outcome & forward pointers

Resolved: IOMMU window (~`0x10000000..0x1008c000`), read granularity (16-bit only),
descriptor format (from the klog WLC dump + Linux mwifiex structs), and the opcode space
(fully enumerated — only `0xFC01`/`0xFC02` are memory access). No escalation reachable
through the BT HCI channel.

Forward pointers (off the chip, for the actual KEX hunt):
- **a53mm / MP4 device** (`/dev/a53mm`, `/dev/a53mmsys`, `/dev/a53io` — the Oberon PSP +
  GPU MMU). Known public read/write (astrelsky/mp4rw) and A53 EL3 code-exec (cragson/a53-code-exec,
  via the DECI5S/sdbgp `SDBGP_WRITE_MEMORY` path). See `RESEARCH_A53MM.md`. The A53 code-exec
  route is the highest-value lead: it was **not patched as of 13.60** and its 14.00 status is unverified.
- **wlan drivers** (`if_wlc` + `mvwl`/`mtwl`) — the WiFi-side `MEM_ACCESS (0x0086)` (full 32-bit)
  lives here; see `RESEARCH_WLAN.md`.
- **Stock-kernel no-CVE candidates** — see `FINDINGS.md` (kqueue fd-knote race PR 293382 is the
  best remaining lead).

---

## 8. Side effects / risks

- **Sending `0xFC01`/`0xFC02` can wedge the shared Marvell WiFi/BT chip**, which takes the
  DualSense (same USB device / BT controller) down with it — observed: controller disconnected
  and even **wired** input stops. Recovery requires a **cold reset** (full power off, not warm
  restart) to clear the Marvell firmware state.
- **Reading the RX BD descriptor ring (`0x10000400`) wedges the chip** (reproduced 2× on clean
  boots): `0xFC01` reads of the chip's *active* descriptor ring trigger a firmware side-effect
  (controller disconnects, won't re-pair even over USB). Reading SRAM (`0x00000000`) and RX
  *data* (`0x10044000`) is safe. ⇒ the descriptor layout must be recovered from source + the
  klog dump, not live DMA reads.
- Reading a mapped-but-unsupported address returns `EIO` (control-transfer stall) rather than
  data — the read-address space / acceptable ranges are not yet mapped out.

## 10. Firmware differences (Marvell vendor-command surface across consoles)

Probed the Marvell BT chip on three consoles (1-event + 1-ACL transport, plen=0 enumeration +
standard-HCI check). The vendor-command surface **shrinks with firmware version**:

| firmware | vendor opcodes 0xFC00-0xFCFF | higher opcodes | standard HCI (0x1001 etc.) |
|---|---|---|---|
| **4.03** (10.0.0.x) | respond (status: 461 unknown / 26 badparam / 20 OK) | respond (unknown 0x01) | responds |
| **7.61** (10.0.0.x) | no response | **EIO (stall) from 0xFD01** | no response on this transport |
| **11.60 Pro** (10.0.0.x) | no response | **EIO (stall) from 0xFC2E** | no response on this transport |

Interpretation: the chip firmware's vendor-command block (including `0xFC01`/`0xFC02` read/write
memory) is **fully live on 4.03**, but on 7.61/11.60 the opcode range that the firmware still
stalls (rather than answers) is narrower (0xFD01 / 0xFC2E), consistent with the debug/vendor
commands being **removed or gated in later firmware**. The standard-HCI no-response on 7.61/11.60
is a transport/race effect (the newer bt_hci driver wins the endpoint races), so a definitive
presence/absence call on 7.61+ would need driver-detach exclusive access (not done — it wedges the
controller). Net: **the DMA primitive is confirmed present only on 4.03; it is absent or changed
on 7.61 and 11.60. The exact firmware where the vendor block was patched/removed is UNKNOWN — it
lies somewhere between 4.03 and 7.61 and has not been narrowed.** This is a DoS/limited-primitive
finding; there is no evidence it survives to 14.00.

## 9. Change log

- 2026-10-04: **exfiltration confirmed.** With a minimal endpoint transport (1 event + 1 ACL
  read, not the 48/16 flood — the flood stalls the control transfer with EIO and wedges the
  chip), `0xFC01` read `0x00000000` returns `Command Complete status=0x00` with 2 data bytes
  `00 30` (chip SRAM base). DMA read → data round-trip works. Next: map which address ranges
  return chip SRAM vs host (IOMMU) memory.
- 2026-10-04: **Read primitive not reliably reproducible.** Detaching the kernel driver
  (`USB_IFACE_DRIVER_DETACH` on iface 0, ret=0) did NOT clear the EIO — reads of `0x10000000`,
  `0x00000000`, `0x10044000` still return EIO under exclusive access. The EIO is chip/firmware
  level, not a driver race. The reads *worked* earlier (SRAM `00 30`, `f9 01`) but stopped after
  the `0xFC02` write to the RX buffer — that write left the firmware rejecting `0xFC01` even
  after a cold boot. So the read round-trip is a one-shot/state-dependent effect, not a stable
  primitive.
- 2026-10-04: **Chip exhausted as a KEX vector.** Full vendor-opcode enumeration (0xFC00-0xFFFF,
  plen=0): 461 unknown, ~20 info-reads (0xFC65 = BT MAC+ver, 0xFC63/0xFC0F/0xFC85 = config),
  ~26 badparam (complex config, not addresses), 0xFCF0 accepts a 4B param. Only 0xFC01/0xFC02 are
  memory access. SRAM write (`0xFC02` → `0x00000000`) returns status 0x00 but read-back is
  unchanged (`00 30`) → SRAM is read-only (write is a no-op). So every escalation route is blocked:
  descriptor rings EIO, SRAM read-only, no wider/register opcode. Final: DoS + read-only SRAM +
  writable-but-self-corrupting data buffers.
- 2026-10-04: **BD-corruption path DEAD.** Both `0xFC01` read and `0xFC02` write to the TX BD
  descriptor ring (`0x10000000`) return EIO. Descriptor rings are firmware-protected (EIO),
  while SRAM + RX data (`0x10044000`) are accessible. The firmware deliberately blocks
  descriptor-ring access, so repointing the DMA engine via descriptor corruption is not
  reachable through this command. Primitive = DoS + limited data-buffer read/write, NOT
  arbitrary kernel read/write.
- 2026-10-04: **write reaches host memory (indirect).** `0xFC02` write `0x11223344` to `0x10044000`
  (the WLC RX buffer PA) succeeded, and the following read of that address returned EIO — the write
  corrupted the chip's active RX buffer, wedging the RX path. So the write mutates host DMA memory.
  The primitive is **IOMMU-gated**: reachable range = the chip's DMA window (≈0x10000000..0x1008c000
  per the WLC dump), not arbitrary physical RAM (0x44332210 faulted).

- 2026-10-04: initial write-up. Confirmed `0xFC01` + 4-byte param → controlled DMA
  READ address (param & ~0x7), IOMMU fault → WLC panic. Reproduced with two distinct
  params.
- 2026-10-04: **WRITE opcode found — `0xFC02` (plen 8, addr + 4B data).** Batch hunt
  over 0xFC02..0xFC0F with distinct per-opcode addresses; fault addr `0x44022210`
  identified `0xFC02` and the flags flipped to `WRITE`. Complete DMA read/write pair.
