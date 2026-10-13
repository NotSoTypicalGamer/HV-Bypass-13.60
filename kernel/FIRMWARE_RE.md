# FIRMWARE RE — Marvell 88W8897 BT firmware (0xFC01/0xFC02 handler hunt)

**Status:** firmware blob obtained (public), format + memory map fully reverse-engineered,
HCI dispatcher located. **KEY FINDING: 0xFC01/0xFC02 are NOT in the public Marvell firmware.**
**Author:** CaliperC0re kernel research (private)
**Date:** 2026-10-05

---

## 1. Where the firmware blob lives (confirmed)

- Kernel `.data` dumps (`kdata_761.bin`, `kdata_1160.bin`, `kernel_data_403.bin`) contain
  ONLY the WLC/`bt` driver debug strings — the firmware is loaded at runtime, NOT resident.
- `libSceMbus.sprx` / `libSceBluetoothHid.sprx` on this box are **0 bytes** (never pulled
  from the console). These are the sealed (encrypted) blobs that embed the actual PS5 BT
  firmware.
- The PUBLIC Marvell 88W8897 BT firmware is in linux-firmware: `mrvl/{usb,pcie,sd}8897_uapsta.bin`.
  Downloaded all three to `scratch/ps5/marvell_fw/`.

## 2. Firmware format (reverse-engineered)

`usb8897_uapsta.bin` = 638 sections, each a 16-byte header + data:

```
struct fw_section { u32 dnld_cmd; u32 base_addr; u32 data_len; u32 crc; };
// dnld_cmd == 1  -> load;  dnld_cmd == 6 -> terminator (EOF)
```

Parsed into 9 memory regions (download addresses from `base_addr`):

| region | download addr | size | contents |
|---|---|---|---|
| 0 | 0xa0000000 | 208 KB | main code + exception vectors + thunk/import table |
| 1,2 | 0xa4000000, 0xa400a960 | ~6 KB | small (config?) |
| 3 | 0xa9020000 | 64 KB | **BT RTOS: HCI_Q / TRAN_Q / HCI Thread / LM / LL / TRAN / TMSVR / MBOX** |
| 4 | 0xaa004000 | 9.6 KB | ? |
| 5 | 0xb0000600 | 31 KB | (referenced by thunk `thunk_EXT_FUN_b00006ec`) |
| 6-8 | 0xc0001300/1b00/2b00 | <1 KB each | tiny data |

## 3. Runtime base (critical correction)

The download `base_addr` is **NOT** the runtime address. The thunk table (`LDR PC,[PC,#-4]` +
32-bit target) points to `0x03f0xxxx` (region 0) and `0x03f4xxxx` (region 3). So:

- **region 0 runs at `0x03f00000`** (not 0xa0000000)
- **region 3 runs at `0x03f40000`** (not 0xa9020000)

Loading at the correct base collapses all `thunk_EXT_FUN_*` into real `FUN_*` (898 functions).
Tooling: Ghidra 12.1.4 headless, `ARM:LE:32:v7`, Thumb; scripts in `scratch/ps5/ghidra_scripts/`.
Combined flat image: `marvell_fw/usb8897_combined.bin` (region0 @0, region3 @0x40000, base 0x03f00000).

## 4. HCI command dispatcher (located)

`FUN_03f41908` = **HCI Thread** (region 3). Decompiled (`scratch/ps5/decomp_hci.txt`):

```
opcode = *(u16 *)(cmd + 1);
ogf = opcode >> 10;                 // OGF
ocf = opcode & 0x3FF;               // OCF
...
if (ogf == 0x3F) {                  // VENDOR commands
    if (ocf - 0x80 < 0x20)  -> table DAT_03f41af4 (OCF 0x80..0x9F)
    else if (ocf == 0x22)   -> FUN_03f49b7e
    else if (ocf == 0x71)   -> FUN_03f49b96
    else if (ocf == 0x74)   -> FUN_03f49b46
    else if (ocf == 0x75)   -> FUN_03f4a3ea
    else if (ocf == 0xe9)   -> FUN_03f4a41a
    else                    -> "unknown command" (LAB_03f41ab6)
}
```

## 5. KEY FINDING — 0xFC01/0xFC02 absent from public firmware

`0xFC01` = OGF 0x3F, **OCF 0x01**; `0xFC02` = **OCF 0x02**.

The public dispatcher's vendor (OGF 0x3F) set is **{0x22, 0x71, 0x74, 0x75, 0xe9, 0x80–0x9F}**.
OCF 0x01 / 0x02 fall through to the "unknown command" path — **the mem-read / mem-write
debug commands are NOT present in stock Marvell 88W8897 BT firmware.**

Conclusion: the PS5's `0xFC01`/`0xFC02` DMA primitives are **Sony-specific** — either added by
Sony or present only in a Marvell firmware version/build not shipped in linux-firmware. They
are NOT in `usb8897/pcie8897/sd8897_uapsta.bin`.

## 7. BREAKTHROUGH — PS5 firmware extracted from kernel .data dumps (2026-10-05)

The PS5's actual BT firmware **IS embedded in the kernel `.data` dumps** (all three: 4.03/7.61/11.60).
My earlier "not resident" conclusion was WRONG — I searched for the download-format section header
(`dnld=1, base=0xa0000000`) and `"8897"` strings, but the firmware is stored in a RELOCATED form.
The giveaway was the RTOS task-name table (`HCI_Q`/`TRAN_Q`/`TMSVR_Q`/`LM_Q`/`LL_Q`/`HCI Thread`/…),
identical in structure to the public firmware's region-3 task table.

- Firmware section headers live at: 11.60 `0x855d90`, 7.61 `0x7f5800`, 4.03 `0x792fb0` (dump file offsets).
- Section format identical to public mwifiex (`{dnld_cmd, base_addr, len, crc}`, 0x1fc spacing),
  but the PS5 firmware is built with base `0x00000000`/`0x00100000`/`0xc0000000`/`0xc0078000`
  (NOT the public `0xa0000000`/`0x03f00000`).

**Extracted regions (saved in `scratch/ps5/extracted_fw/`):**

| region | addr | 4.03 | 7.61 | 11.60 |
|---|---|---|---|---|
| r0 vectors/boot | 0x00000000 | 12.7 KB | 12.7 KB | 12.7 KB |
| r1 **main code** | 0x00100000 | **402.4 KB** | 407.0 KB | 407.5 KB |
| r2 data | 0xc0000000 | 21.7 KB | 21.7 KB | 21.7 KB |
| r3 data/code | 0xc0078000 | 37.5 KB | 37.3 KB | 37.3 KB |

The interrupt vector table in r0 points handlers at `0x0010a6xx` → **code runs at 0x00100000**.
Code grew 402→407 KB between 4.03 and 7.61 (consistent with the vendor surface change).

**0xFC01/0xFC02 CONFIRMED present in the 4.03 firmware.** In `403_r1_00100000.bin`, a command
table at offset `0x61de8` (= `0x00161de8`) contains:

```
0x00161de8: 01 fc 04 00 ...   -> opcode 0xFC01, plen 0x04
0x00161df8: 02 fc 04 00 22 ... -> opcode 0xFC02, plen 0x04 (+ field 0x22)
```

Adjacent standard-command handler table (8-byte entries `{opcode, handler_ptr}`): `0x00cd→0x00125bfd`,
`0x00ce→0x00125bd9`, `0x00cf→0x00125bad`, `0x00d0→0x00125c5f`, `0x00e9→0x00125b91` — all handlers
cluster in `0x00125b91..0x00125c5f`. The 0xFC01/0xFC02 handlers are NOT yet pinned; the vendor
dispatch does not use the public firmware's inline `cmp #0x3f` / `lsr #0xa` pattern, so the
Sony dispatch (likely a table lookup) still needs mapping. Ghidra project: `ps5marvell`
(`403_combined_01.bin`, 2,513 functions in the code region).

## 8. Vendor dispatch chain — LOCATED (4.03)

Full chain from HCI command to the 0xFC01/0xFC02 parameter handler:

```
FUN_00101194  (HCI command dispatcher — switch on *cmd_type)
  ├─ case 8/9 → FUN_00111064  (vendor command handler)
  │     movw r1,#0xfc01 / #0xfc02 / #0xfc03 / #0xfc04
  │     → FUN_0012bb14(param_1, opcode)  for each vendor opcode
  │         → FUN_0012bae4(param_1, opcode)  linked-list search of command descriptors
  │             node = { opcode u16, len u16, value u32, flags u32, *next }
  │         → returns node.value  (the 4-byte param = the DMA address for 0xFC01)
  │         → BUG-SHAPED CHECK:  if (node.len > 4) { while(1); }   (hang, not clean error)
  │     stores params in DAT_001110a4[]
  └─ → FUN_00100d78(...)  (consumes parsed params → actual DMA/bus read-write)
```

- `FUN_0012bae4` is the command-descriptor lookup (linear walk of a linked list, matching
  `node[0]==opcode && node[8] & (1<<param_1)`).
- `FUN_0012bb14` validates `len ≤ 4` then returns the 4-byte value at `node+4` — for `0xFC01`
  this is the attacker-controlled DMA **read** address; for `0xFC02` the write address.
- The actual bus/DMA access + any **address-window/bounds check** is in `FUN_00100d78` (and its
  callees), NOT yet decompiled. That is where a window-expansion / OOB bug would live.
- **CAVEAT (unresolved):** `FUN_00101194`/`FUN_00100d78` build TLV-heavy frames (tags `0x11f/0x101/0xdd/0x30`)
  that look WiFi-MAC-ish, so `FUN_00111064`'s `0xFC01..0xFC04` may be a *WiFi-side* vendor group
  rather than the BT-HCI vendor commands the 4.03 console actually answers on `/dev/ugen0.2`. The
  BT-HCI vendor dispatch may be a separate path. Also note the table lists `0xFC02` plen=4, while
  the black-box research recorded `0xFC02` plen=8 (addr+data) — worth reconciling. Do NOT treat the
  chain as the BT-HCI path until the DMA read/write primitive is actually pinned.

## 9. TWO firmware images + a correction on 0xFC01/0xFC02

The 4.03 kernel `.data` dump holds **two separate Marvell firmware images** (both sectioned,
`{dnld_cmd,base,addr,len,crc}`):

| image | code base | code size | data base | contents |
|---|---|---|---|---|
| **MAIN (combo)** | 0x00100000 | 402 KB | 0xc0000000 / 0xc0078000 | WiFi MAC/PHY + WiFi vendor commands |
| **BT RTOS** | 0x00080000 | 113 KB (0x80000+0x90000) | 0xd0000000 / 0x000c0000 | `HCI_Q`/`TRAN_Q`/LM/LL task table + HCI stack |

- **BT RTOS is ThreadX on ARM Cortex-M3** (Thumb/Thumb-2 only) — the TCB region `bt_r2_000c395c.bin`
  carries the string `Copyright (c) 1996-2010 Express Logic Inc. * ThreadX Cortex-M3/RVDS Version
  G5.3.5.2`. Import Ghidra in Thumb mode accordingly. BT RTOS code = `bt_r0` (base 0x00080000) +
  `bt_r1` (base 0x00090000); remaining regions (`bt_r2`–`bt_r9`: TCBs, data @0xd0000000, and
  small blobs @0xf0000e34/0xf0003a00) contain no 0xFC01/0xFC02 and no code.
- The BT RTOS (base 0x00080000) has the HCI vendor dispatchers `FUN_00099ce8` and `FUN_0009a1cc`;
  their vendor OCF sets are `{0x06,0x0f,0x20,0x23,0x2a,0x39,0x3d,0x3e,0x55,0x56,0x57,0x59,0x5a,0x5b,0x5e,
  0x65,0x66,0x6a,0x6b,0x6c,0x6d,0x6e,0xea,0xee,0xef,0xf0}` and `{0x62,0xf4,0x7f,0xf3,0xfd,0xfe,0x27,0x03,
  0x19,0x24,0x2e,0x61,0x153–0x159}` — **neither covers OCF 0x01/0x02**.
- **DEFINITIVE NEGATIVE RESULT — OCF 0x01/0x02 is in NEITHER image's vendor dispatch.** Full
  disassembly of the BT-RTOS HCI command dispatcher (`0x8184c`, vendor branch at `0x819d6`) shows
  its vendor OCF coverage is `0x80–0x9f` (via table @`0x81a6c`) + `0x71/0x74/0x75/0xe9` +
  `0x153–0x159` — **no OCF 0x01/0x02**. The MAIN image's `0xFC01–0xFC04` (`FUN_00111064`)
  consumers (`FUN_00100d78` → `FUN_0010db28`/`FUN_00100b12`/`FUN_0010099e`) are pure WiFi
  management-frame builders (TLVs `0x2d/0x101/0x48/0x7f/0xbf/199`), **not** a DMA read/write.
  So the black-box `0xFC01`/`0xFC02` DMA primitive is handled by a path **outside** the HCI vendor
  dispatch of both extracted images — candidates: a USB/transport-level handler, the chip boot
  ROM, or a third firmware component not resident in the `.data` dump.
- **Runtime-populated state:** `FUN_0012bae4` walks a command-descriptor linked list whose head
  (`*(0x0015bd44 + 0x14)`) is **NULL in the static image** — the list is built at runtime during
  init, so descriptor `value`/handler fields are not statically resolvable. Vendor params land in
  a BSS array at `*(0x001110a4) = 0x001715c8`.

## 10. Status & remaining work (updated after 3-pass parallel)

- **Done:** both firmware images located + extracted, memory maps resolved, both images' vendor
  dispatchers decompiled, and the MAIN image's `FUN_00111064`→`FUN_0012bb14`→`FUN_0012bae4`
  param-lookup machinery fully traced (node layout `{opcode,len,value,flags,next}` recovered).
- **Three parallel passes confirmed the negative and surfaced two new leads:**
  - *USB transport layer:* an exhaustive Thumb-2 scalar scan found **zero** `0xFC01`/`0xFC02`
    immediates and zero literal-pool words in the BT RTOS. The USB layer exists (`bt_usb` @0x8c0e8,
    `bt_hci` @0x81ebc, TRAN thread @0x82468) but does **not** dispatch 0xFC01/0xFC02. **KEY:** the
    BT RTOS's OGF-8 / OGF-0x3F handler tables (@0xca3ec / @0xca56c) point most entries into
    **unextracted low-address code** `0x0000b91b..0x0000daxx` (ThreadX-lib range, below the carved
    r0 base 0x80000) — i.e. the handler likely lives in code NOT present in the `.data` dump (chip
    ROM / a third image).
  - *Third-component scan:* found the **88W8897 "sys_patch" MCU firmware** — a raw (non-sectioned)
    blob in all three dumps: 4.03 @0x6a0b7d (~128KB), 7.61 @0x9ec7e0 (~211KB), 11.60 @0xc70369
    (~191KB). Strings: `patch/wf_wm/sys_patch_mcu.c`, `sys_patch_common_mcu.c`, `CONNSYS coredump`,
    `IDLM/ILM/DLM monitor`, `DEVAPC IRQ handler`, `Patch_wifi_rom_api_dispatcher`. Header begins
    `"Minghua…"` and the bulk is opaque (packed/encrypted); only the trailing string table is
    clear. Its instruction stream has abundant 0xFC01/0xFC02 byte patterns but on a non-ARM ISA.
  - *Cross-version diff:* 4.03/7.61/11.60 dispatch is byte-stable (relocation-only). **Sony did
    NOT gate/remove the mem-access path** across these versions — no security delta.
- **Correction:** the MAIN image's `movw #0xFC01..#0xFC04` are used as **memory-mapped register
  addresses** (STR writes), not HCI opcodes — so that chain was never the mem-access.
- **Remaining paths (in order of leverage):**
  1. Dump the chip ROM / low-address code (0x0000xxxx) — via the 0xFC01 read primitive if the
     whitelist permits, or on the sacrificial 7.61 console.
  2. Identify the sys_patch MCU ISA and RE its 0xFC01/0xFC02 pattern (needs unpack/decrypt first).
- **plen discrepancy:** MAIN-image table lists `0xFC02` plen 4; black-box research recorded plen 8
  (addr+data). Still unreconciled.
