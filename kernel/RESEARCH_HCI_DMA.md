# HCI DMA — chip identification & firmware command research

## Chip identification (confirmed)
- Marvell **Avastar 88W8897** (802.11ac + BT 4.0 + NFC combo), **PCIe** variant.
- Evidence: klog dump `reg_scratch_3 = 0xfedcba00` == Linux `FIRMWARE_READY_PCIE`.
- USB BT interface: `1286:2059` (Sony-specific; Linux btusb knows `1286:2044/2046`).

## The 0xFC01/0xFC02 commands are "memory access" debug commands
The Marvell **WiFi** firmware has an exact analog, `HostCmd_CMD_MEM_ACCESS = 0x0086`:

```c
struct host_cmd_ds_mem_access {
    __le16 action;   // HostCmd_ACT_GEN_GET (read) | HostCmd_ACT_GEN_SET (write)
    __le16 reserved;
    __le32 addr;
    __le32 value;
};
```

So the BT-side `0xFC01` (read 16-bit) / `0xFC02` (write 4 bytes) are the BT firmware's
equivalent "mem rd/wr" debug commands, exposed over HCI vendor opcodes (0xFC00-0xFFFF).
This is the Marvell production-test / debug command block (also contains `0xFC77` = LED).

## Implication for the descriptor-ring EIO
Both the WiFi `0x0086` and BT `0xFC01/0xFC02` are the firmware's *debug* memory access.
The descriptor-ring EIO (and the state-dependence after the RX-buffer write) is the
firmware's own address validation on this debug path — not the host driver, and not
something userland can bypass through the BT HCI interface.

## Remaining unexplored
- Other BT vendor opcodes in 0xFC00-0xFFFF (register access, firmware download) — would
  need the Marvell BT firmware binary to enumerate. Not public.
- The WiFi firmware's 0x0086 is only reachable from the WiFi host command channel
  (not the BT HCI channel), so it's not directly usable from our BT-side primitive.
