# HCI.md — PS5 Bluetooth/HCI attack surface (new line, 2026-10-04)

## Status: Sony-custom BT stack, black-box, NOT publicly exploited

Evidence (kernel data dump strings + FS listing):
- **Kernel:** `bt_hci`, `bt_usb`, `bluetooth_hid` modules (Sony internal source paths
  `W:\Build\J01736804\sys\internal\modules\bluetooth_hid\bluetooth_hid.c`), threads
  `SceBtSync` / `SceBtHidGiant` / `SceBtTimer`.
- **Userland:** `libSceBluetoothHid.sprx`, `libSceHidControl.sprx`, `libScePad.sprx`,
  `libScePadTracker.sprx` (in /system/common/lib).
- **FreeBSD `ng_hci` / `ng_l2cap` ABSENT** — Sony replaced netgraph Bluetooth with their own.
- BT chip = Marvell `1286:2059` (integrated WiFi/BT on xhci), exposed as `/dev/ugen0.2` with
  TWO BT controllers on one USB device (controller 0 = HCI, controller 1 = DualSense).

## Attack model
1. Kernel's `bt_hci` parses **HCI events** from the Marvell controller, which relays remote BT
   device traffic → a malicious BT peer's crafted packets reach the kernel parser (adjacent-
   attackable, like Linux BleedingTooth / CVE-2020-24490, CVE-2026-31771).
2. **Userland injection path proven:** `ghost-toothAPI` talks HCI directly on `/dev/ugen0.2`'s
   USB pipes WITHOUT detaching the kernel driver — so a payload can inject crafted HCI
   commands/events that the kernel `bt_hci` parser must handle. (ghost-toothAPI = userland BT
   audio, NOT a kernel exploit — the kernel-bug angle is unclaimed.)

## Why it fits the 14.00 goal
- Sony-original code (same profile as aio_multi_wait = Relapse's bug) — not in FreeBSD source,
  less fuzzed, invisible to FreeBSD-diff hunts.
- NOT in PUBLIC_KEX.md (no public HCI KEX found) → genuinely new ground.

## Concrete injection primitive (FGG-PlayPods, verified 2026-10-04)
`FGGstore/FGG-PlayPods` (PS5 homebrew A2DP, GPLv3) is a working reference for raw HCI-over-USB
on this console. Transport, copied from its `src/hci.c` and **verified live** (probe34):
- `fd = open("/dev/ugen0.2", O_RDWR)` — the Marvell 1286:2059.
- **HCI commands** go on the USB **control** endpoint via `ioctl(fd, USB_DO_REQUEST, &req)` with
  `bmRequestType=UT_WRITE_CLASS_DEVICE(0x20)`, `bRequest=0`, `wValue=0`, `wIndex=0`, data =
  the 3+N-byte HCI command (opcode LE + plen + params). This needs NO `USB_FS_INIT`/endpoint
  setup — control transfer works on the raw fd.
- **Bulk endpoints** (via `USB_FS_INIT`/`USB_FS_OPEN`/`USB_FS_START`/`USB_FS_COMPLETE`):
  iface 0/1 (controller 0, shared with system driver): event IN 0x82, ACL IN 0x81, ACL OUT 0x01.
  iface 2/3 (controller 1 = DualSense): 0x85/0x84/0x04. Both the system's `bt_hci` driver and
  the payload read the SAME controller-0 endpoints (race; ~1 system read vs many payload reads).
- **Injection into the kernel parser:** send HCI commands on the control endpoint WITHOUT opening
  the read endpoints → the controller's response events (Command Complete/Status) go entirely to
  the kernel's `bt_hci` parser, which sees completions for commands it never issued. This is the
  fuzz surface — unexpected/malformed completions into a Sony-custom parser.
- **probe34 `khcifuzz.elf`** (built+deployed): verifies transport (READ_BUFFER_SIZE=ok,
  READ_LOCAL_VERSION=ok) then fuzzes opcodes 0x0000..0x0FFF x plen {0,1,4,16,64} (skip HCI_Reset
  0x0C03). ~66ms per control transfer → full sweep ~20 min. No crash through op 0x0200 yet.

## CONFIRMED kernel panic via HCI vendor commands (2026-10-04, 3/3 reproducible)
Blind-fuzzing HCI vendor opcodes (0xFC00..0xFFFF) over the ugen control transfer
**panics the 4.03 kernel reliably** (3 separate fires, all ports down). Details:
- **probe34** (standard opcodes 0x0000..0x0FFF x plen{0,1,4,16,64}) — 20475 cmds, CLEAN.
- **probe35/36** (vendor opcodes 0xFC00..0xFFFF) — PANIC. O_SYNC log last line `send op=0xfc3d plen=4`.
- **probe37** (0xFC3D alone, 5x, 200ms apart) — CLEAN. So not a single-command crash.
- **probe38** (0xFC00..0xFC3C, rapid) — payload logged `done: no crash`, THEN panicked →
  **delayed UAF**: the crashing command's response leaves a dangling/corrupted pointer that
  the kernel derefs later. Culprit is in 0xFC00..0xFC3C (0xFC3D ruled out).
- Params used: `{0x5A,0x59,0x58,0x5F,...}` pattern (0x5A ^ (i*3)). plen in {0,1,4,16}.
- **This is a real kernel bug in the Sony-custom bt_hci parser, unclaimed publicly.**
  Next: binary-search the 0xFC00..0xFC3C range (with a post-send wait for the delayed crash)
  and/or capture the panic screen (fault addr + trap type) to identify the bug.
- **CULPRIT PINNED: op=0xFC01, plen=4** (params `5A 59 5C 53` — the 0x5A^(i*3) pattern). Binary search
  narrowed the opcode, then plen isolation: plen=0 (clean), plen=1 (clean), **plen=4 (PANIC)**. So the
  trigger is a single HCI vendor command `0xFC01` (OGF 0x3F vendor, OCF 0x01) carrying a 4-byte
  parameter, sent via the ugen control transfer on /dev/ugen0.2. Delayed kernel panic ~2s after.
- **FAULT CAPTURED (klog before halt):** `[WLC] IO Fault addr: 0x535c5958` + full WLC chip-register /
  DMA / descriptor dump. The fault address = my parameter as a little-endian u32 (`0x535C595A`) minus
  2. So the vendor command's 4-byte param is **interpreted as an address** and fed to the shared
  Marvell chip (WiFi/BT combo) → chip DMA/IO fault → WLC (WiFi) driver panics. **Bug class = chip-DMA
  fault → kernel panic (DoS), NOT a clean kernel UAF.** The param byte-for-byte controls the fault
  address — worth testing whether the address (and fault) is fully attacker-controlled (a possible
  chip DMA primitive).
- **CONTROLLED DMA READ CONFIRMED (2026-10-04):** param `{0x11,0x22,0x33,0x44}` → fault
  `0x44332210`; param `{0x5A,0x59,0x5C,0x53}` → `0x535C5958`. Fault addr = **param & ~0x7** (8-byte
  aligned), i.e. the vendor command's 4-byte parameter is a **fully attacker-controlled DMA READ
  address**. klog: `IO_PAGE_FAULT: tlsw0@000044332210, pasid:0x0, devid: 4007, [...READ...]` — the
  Marvell chip (devid 4007) issues a DMA READ from my address; the IOMMU faults on unmapped addrs and
  WLC panics. **Potential primitive:** point the DMA read at a VALID (IOMMU-mapped) kernel address
  and observe the read data (via a follow-up HCI response) → possible DMA-based kernel read. Next:
  test whether a mapped address (e.g. a kernel/phys address the chip can reach) yields data instead
  of a fault, and whether there's a corresponding WRITE opcode.

## Open questions (next steps)
1. **Reachability:** can a sandboxed (non-etaHEN) process open `/dev/ugen0.2` and inject HCI,
   or is it privileged? (Determines whether the vector is sandbox-reachable or needs a prior
   exploit stage.)
2. **Parser location:** locate `bt_hci`'s HCI event dispatch table in the data segment (function
   pointers → text) to identify the event handler(s) worth fuzzing.
3. **Fuzz surface:** craft malformed HCI events (short frames, oversized adv reports, bad
   lengths) and watch klog for panics — the OOB/UAF class.

## Constraint reminder (operator)
Do NOT re-derive public info. The aio family (Lapse = aio_multi_delete, Relapse = aio_multi_wait,
get_aio_debug_request_info) and IPV6/umtx UAFs are all public — skip. HCI is currently clean.
