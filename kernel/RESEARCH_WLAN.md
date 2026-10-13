# wlan — Marvell/MediaTek WiFi drivers (Sony-original if_wlc core)

Source: `kernel_data.bin` string analysis. Source paths under `W:\Build\J01736804\sys\internal\modules\wlan\`.

## Structure (3 Sony-original drivers)
- **if_wlc** — shared WiFi core (emits the `[WLC] ...` dump strings: TX/RX/CMD/RSP/EVT `adma`
  register dump seen in the panic klog). Owns the DMA descriptor rings + the IOMMU fault handler
  (`[WLC] IO Fault addr:`).
- **mvwl** (Marvell) — `marvell/common/mvwl.c`, `mvwl_pcie.c`. `mvwl_exec_cmd`, `mvwl_assoc`,
  `mvwl:join`. This is the driver whose DMA window my `0xFC01`/`0xFC02` primitive reads/writes.
- **mtwl** (MediaTek) — `mediatek/common/mtwl.c`, `mtwl_pcie.c`. `mtwl_ctrl`, `mtwl:join`.
  (Second WiFi controller — the PS5 has both a Marvell and a MediaTek radio.)

Control/intr threads: `SceMvwlCtrl`, `SceMvwlAsync`, `SceMtwlCtrl`, `SceMtwlIntr`.

## Relevance
`mvwl_exec_cmd` is the Marvell WiFi HostCmd executor — the WiFi-side handler for commands like
`HostCmd_CMD_MEM_ACCESS (0x0086)` (see RESEARCH_HCI_DMA.md). The DMA descriptor rings live in
this driver's IOMMU window (≈0x10000000..0x1008c000). The `[WLC] IO Fault` handler is the
panic sink for unmapped `0xFC01`/`0xFC02` addresses.

## Parser surface — CORRECTION (2026-10-04)
The wlan driver is a **thin transport, NOT a frame parser.** String analysis of `kernel_data.bin`
found NO beacon/probe/mgmt/assoc/auth/IE strings in the kernel — the 802.11 frame parsing is in
the Marvell/MediaTek **firmware** (on-chip), not the kernel driver. The kernel-side attack surface
is limited to:
- `mvwl_exec_cmd` — HostCmd executor (MEM_ACCESS 0x0086 + other HostCmds)
- `mvwl_assoc`, `mvwl_hif_init/start`, `mvwl_hif_ps_awake` — association + host-interface
- `mvwl_pcie_tlsw(_pci)` — the PCIe TLSW/DMA fault handler (the `[WLC] IO Fault` panic sink)
- `mvwl:proc_ctrl` / `mvwl:proc_async` / `mtwl:join` / `mtwl:proc_intr` — control threads
- `bxe_sie_bbuf_*` — a separate network buffer engine (bxe/sie), possibly the SIE buffer path

So the "RF parser" angle is a **firmware** target (chip-level), not a kernel bug — the kernel
wlan surface is the HostCmd path + DMA ring handling, neither directly reachable from the renderer.

## Future angle
A malformed HostCmd → `mvwl_exec_cmd` bug, or a DMA-ring handling bug, is the kernel-side seam —
but it needs the HostCmd channel (kernel-internal, not a documented userland ioctl). Lower priority
than the kqueue race (PR 293382) for a renderer→kernel chain.
