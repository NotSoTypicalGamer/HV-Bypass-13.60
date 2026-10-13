# 13.60 probe — 0xFC01 / 0xFC02 DMA read/write (fire-on-demand)

Derived from VULN_HCI_DMA_READ.md + HCI.md (4.03-confirmed primitive). Use on the updated
13.60 console (10.0.0.x) to test whether the Marvell mem-access survives.

## Transport (verified on 4.03, ghost-toothAPI / probe34)
- `fd = open("/dev/ugen0.2", O_RDWR)`   (Marvell BT, 1286:2059)
- HCI command = USB **control** transfer:
  `ioctl(fd, USB_DO_REQUEST, &req)` with
  `bmRequestType = UT_WRITE_CLASS_DEVICE (0x20)`, `bRequest = 0`, `wValue = 0`, `wIndex = 0`,
  `wLength = 3 + plen`, data = `{opcode_lo, opcode_hi, plen, param...}`  (opcode little-endian).
- Response = **1 event IN (0x82) + 1 ACL IN (0x81)** endpoint transport. Do NOT use the 48/16
  flood — it stalls the control transfer with EIO and wedges the chip.

## Commands
| opcode | plen | param | effect |
|---|---|---|---|
| `0xFC01` | 4 | 4-byte read address (8-byte aligned) | DMA read; 16-bit result in Command Complete |
| `0xFC02` | 8 | 4-byte addr + 4-byte data | DMA write |

## Probe sequence (13.60)
probe41 `khcictrl.elf` reads `opcode plen param...` (hex) from `/data/fuzz_ctrl.txt`, fires one
command, prints the Command Complete status + data bytes. klog_cap.py → port 3232 captures faults.

1. **Safe read (SRAM base):** `fc01 4 00 00 00 00`
   - Live → Command Complete status 0x00 + 2 bytes `00 30`.
   - Gated → EIO (control-transfer stall) or no response.
2. **Safe read (RX data):** `fc01 4 00 44 00 10`  (0x10044000)
   - Live → `00 30`.
3. **Panic test (unmapped):** `fc01 4 10 22 33 44`  (0x44332210)
   - Live → ~1–2 s later `IO_PAGE_FAULT ... devid:4007 READ` + `[WLC] IO Fault addr: 0x44332210`, panic.
   - Gated → EIO / no response.
4. **Write test (RX data buffer):** `fc02 8 00 44 00 10 aa bb cc dd`
   - Live → write mutates the active RX buffer (following read returns EIO).

## Important caveats
- **7.61 / 11.60 already stall (EIO) on vendor commands** (VULN_HCI_DMA_READ.md §10): 4.03
  answers the whole 0xFC00–0xFCFF block; 7.61 stalls from 0xFD01, 11.60 from 0xFC2E. If that
  stall was real gating (not the driver transport race), **13.60 will also EIO** and the DMA
  primitive is dead on 13.60. A definitive call needs driver-detach exclusive access (wedges the
  controller — cold reset required). Expect the stall first; a live answer is the surprise.
- **Side effects:** reading the RX *descriptor* ring (0x10000400) wedges the chip (controller
  disconnects, needs full power-off). Reading SRAM (0x00000000) and RX *data* (0x10044000) is safe.
- Recovery from any wedge: **cold reset** (full power off), not warm restart.
