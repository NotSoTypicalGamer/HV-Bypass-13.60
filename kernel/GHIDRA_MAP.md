# PS5 13.60 kernel `.data` — Ghidra map

Ghidra 12.1.4 headless import of the 13.60 kernel `.data` dump (`kdata_1360.bin`, 15 MB raw)
with the sysent table and the cdevsw (character-device switch) tables mapped as real structs, ready
for cross-referencing against FreeBSD 11.0 `releng/11.0` source.

## Image & project

| item | value |
|---|---|
| dump file | `C:\Users\USER\AppData\Local\kex\cache\scratch\ps5\kdata_1360.bin` |
| dump size | 15,728,640 bytes (0xF00000) |
| **data base VA** | `0xffffffffd0930000` (13.60 KASLR slide) |
| Ghidra project | `C:\Users\USER\AppData\Local\kex\cache\scratch\ps5\ghidra-proj\` |
| project name | `ps5_1360` |
| program | `kdata_1360.bin` (Raw Binary loader, `x86:LE:64:default:windows`) |

## sysent — syscall table

Location: **file offset `0x38` → VA `0xffffffffd0930038`**, **677 entries**.

**Layout correction (important):** the table is **24-byte stride, NOT 48**. Prior notes
(`cross-firmware-diff`) said "48-byte stride" because that is the size of *stock* FreeBSD 11.0
`struct sysent`; the **actual Sony layout is a 24-byte record** — verified by the fact that the
`sy_meta` pointer field is strictly monotonic and has **677 unique values** (one per syscall),
whereas a 48-byte interpretation would double the record count. Each 24-byte record:

| offset | size | field | value (observed) |
|---|---|---|---|
| +0 | 4 | `sy_argsize` | **constant `8`** in all 677 entries (NOT a per-syscall narg — do not trust stock `sy_narg` semantics) |
| +4 | 4 | pad | 0 |
| +8 | 8 | `sy_call` | function pointer → core text `0xffffffff80xxxxxx` |
| +16 | 8 | `sy_meta` | pointer → per-syscall 16-byte record in core text `0xffffffff81xxxxxx` |

Facts:

- `sy_call` range `0xffffffff804772b8` … `0xffffffff815c3678`, **347 unique** handlers (the rest are
  shared stubs — e.g. `0xffffffff814c2ca5` is shared by 633/661/662/663 and is almost certainly the
  ENOSYS/"not implemented" stub, so a 13.60-vs-14.00 diff should look at *which* numbers point at
  that stub, not at address movement).
- `sy_meta` range `0xffffffff81066fd0` … `0xffffffff81069a20`, **677 unique**, stride `0x10`
  (16-byte per-syscall metadata records, in the text/rodata mapping — not present in this `.data` dump).

> **Correction (2026-10-12):** disassembling the `+8` targets shows the field is **not** a uniform
> function pointer. Entries 0–5 (`0x8047xxxx`) sit in ciphertext/zero pages of `ktext_0.bin`;
> entry 20 → UTF-16 `"ongPress"`, entry 663 → `"iority={2}"` (so `0xffffffff814c2ca5` is a string,
> *not* the ENOSYS stub); but entry 97 (socket) → valid x86. The "347 unique handlers" count above
> is therefore suspect — it counts a mix of code, string, and zero pointers. The `+8` field's
> meaning (or whether `0x38` is the sysent at all) needs re-verification before use in a
> syscall-hijack. See `kernel/13.60_OFFSET_HUNT.md`.

- Sample entries (24-byte stride):

| syscall | file off | VA | sy_call |
|---|---|---|---|
| 0 | 0x38 | 0xffffffffd0930038 | 0xffffffff804772b8 |
| 97 socket | 0x950 | 0xffffffffd0930950 | 0xffffffff81505ede |
| 362 kqueue | 0x2228 | 0xffffffffd0932228 | 0xffffffff814a99db |
| 454 _umtx_op | 0x2ac8 | 0xffffffffd0932ac8 | 0xffffffff8154f2e8 |
| 632 thr_suspend_ucontext | 0x3b78 | 0xffffffffd0933b78 | 0xffffffff815ae03a |
| 633 thr_resume_ucontext | 0x3b90 | 0xffffffffd0933b90 | 0xffffffff814c2ca5 |
| 663 aio_multi_wait | 0x3e60 | 0xffffffffd0933e60 | 0xffffffff814c2ca5 |
| 676 (last) | 0x3f98 | 0xffffffffd0933f98 | 0xffffffff814b3b15 |

In Ghidra: the table is applied as `ps5_sysent[677]` with the `sysent` label + bookmark at
`0xffffffffd0930038`.

## cdevsw — character device switch tables

**33 tables** found by scanning for the FreeBSD 11.0 `D_VERSION_03` magic `0x17122009` at +0,
each 192 bytes (stock `struct cdevsw` layout, offsets below confirmed against the source).

`struct cdevsw` (192 B): `d_version`@0 · `d_flags`@4 · `d_name`@8 · `d_open`@16 · `d_fdopen`@24 ·
`d_close`@32 · `d_read`@40 · `d_write`@48 · `d_ioctl`@56 · `d_poll`@64 · `d_mmap`@72 ·
`d_strategy`@80 · `d_dump`@88 · `d_kqfilter`@96 · `d_purge`@104 · `d_mmap_single`@112 ·
`d_spare0[3]`@120 · `d_spare1[3]`@136 · `d_devs`@160 · `d_spare2`@176 · `d_gianttrick`@184.

All 33 are **Sony-specific drivers** (no stock mem/null/zero/console — those are compiled out or
moved). `d_name` points to a name string **inside `.data`** (e.g. `0xffffffffd0ee5a6e` →
`"pfsmgr"`); `d_open`/`d_read`/… point to a **KASLR-slid code region `0xffffffffcfxxxxxx`** (the
Sony driver text), *not* the fixed core text `0xffffffff80xxxxxx` that the sysent `sy_call`
pointers use. That two-region split (fixed core text vs. slid driver text) is the key thing to
remember when chasing any `d_*` function.

| label | file off | VA | name |
|---|---|---|---|
| cdevsw_pfsmgr | 0xdd21f8 | 0xffffffffd17021f8 | pfsmgr |
| cdevsw_authmgr | 0xdd26d0 | 0xffffffffd17026d0 | authmgr |
| cdevsw_bdemu | 0xdd3128 | 0xffffffffd1703128 | bdemu |
| cdevsw_devctl | 0xdd46c8 | 0xffffffffd17046c8 | devctl |
| cdevsw_sc_fw_update | 0xdd4aa0 | 0xffffffffd1704aa0 | sc_fw_update |
| cdevsw_lvd | 0xdd7d38 | 0xffffffffd1707d38 | lvd |
| cdevsw_pup_update | 0xdd9d68 | 0xffffffffd1709d68 | pup_update |
| cdevsw_icc_device_power | 0xdda270 | 0xffffffffd170a270 | icc_device_power |
| cdevsw_dngl | 0xdda960 | 0xffffffffd170a960 | dngl |
| cdevsw_dbggc | 0xddc170 | 0xffffffffd170c170 | dbggc |
| cdevsw_dbggc_wfdebug | 0xddcdd0 | 0xffffffffd170cdd0 | dbggc_wfdebug |
| cdevsw_fttrm | 0xdf5f68 | 0xffffffffd1725f68 | fttrm |
| cdevsw_crepo | 0xdf6dd8 | 0xffffffffd1726dd8 | crepo |
| cdevsw_dmem_cnt | 0xdf7260 | 0xffffffffd1727260 | dmem_cnt |
| cdevsw_dmem | 0xdf7360 | 0xffffffffd1727360 | dmem |
| cdevsw_kmbp | 0xdf8650 | 0xffffffffd1728650 | kmbp |
| cdevsw__noname_ | 0xdf8be0 | 0xffffffffd1728be0 | (d_name NULL) |
| cdevsw_ffs_susp | 0xdf9a70 | 0xffffffffd1729a70 | ffs_susp |
| cdevsw_icc_indicator | 0xe01ee8 | 0xffffffffd1731ee8 | icc_indicator |
| cdevsw_manuauth | 0xe022d8 | 0xffffffffd17322d8 | manuauth |
| cdevsw_av_control | 0xe050e0 | 0xffffffffd17350e0 | av_control |
| cdevsw_vcn | 0xe06600 | 0xffffffffd1736600 | vcn |
| cdevsw_s3da | 0xe06d88 | 0xffffffffd1736d88 | s3da |
| cdevsw_dldbg | 0xe0d6c8 | 0xffffffffd173d6c8 | dldbg |
| cdevsw_srtc | 0xe0db90 | 0xffffffffd173db90 | srtc |
| cdevsw_sbl_rp | 0xe0fc90 | 0xffffffffd173fc90 | sbl_rp |
| cdevsw_ncdt | 0xe13bc8 | 0xffffffffd1743bc8 | ncdt |
| cdevsw_auditpipe | 0xe13ed0 | 0xffffffffd1743ed0 | auditpipe |
| cdevsw_duid | 0xe17c10 | 0xffffffffd1747c10 | duid |
| cdevsw_notification | 0xe191a0 | 0xffffffffd17491a0 | notification |
| cdevsw_sbl_srv | 0xe266a8 | 0xffffffffd17566a8 | sbl_srv |
| cdevsw_a53io | 0xe271d0 | 0xffffffffd17571d0 | a53io |
| cdevsw_acm | 0xe284b0 | 0xffffffffd17584b0 | acm |

(`a53io` is the A53/PSP MP4 device — see `RESEARCH_A53MM.md`; `dmem`/`dmem_cnt`/`dbggc` are the
debug-memory surfaces.)

## filterops — NOT found in this dump

`struct filterops` (FreeBSD 11.0, 40 B: `f_isfd` int@0 + `f_attach`/`f_detach`/`f_event`/`f_touch`
function pointers @8/16/24/32) is **not present** in the `.data` dump, and neither is the
`sysfilt_ops[]` registration array (12×16 B of `{filterops*, for_nolock, for_refcnt}`). Exhaustive
scans for the stock signature (f_isfd ∈ {0,1} + NULL/core-text function pointers, every plausible
field order, stride 32/40/48/56, pointer target in both the core-text and slid-code ranges) all
return zero hits.

Implication: Sony either (a) compiled `kern_event.c`'s filterops into `.rodata`/the read-only text
mapping (so they are absent from a `.data`-only dump), or (b) restructured the kqueue filter
subsystem (consistent with the known kqueue deltas: PS4 `EVFILT_USER` = -7 vs stock -4). **Mapping
filterops requires the `.text`/`.rodata` dump (or single-stepping `kernel_copyout` of the
`0xffffffff80…` aliases), not this `.data` dump.** The `sysfilt_ops` targets would then be
recoverable from the `for_fop` pointers; that work is left open here.

## Re-opening the project

GUI (Windows): run `C:\Users\USER\AppData\Local\kex\cache\scratch\ps5\ghidra\ghidra_12.1.4_PUBLIC\ghidraRun.bat`,
File → Open Project → `C:\Users\USER\AppData\Local\kex\cache\scratch\ps5\ghidra-proj\` (project
`ps5_1360`), then open program `kdata_1360.bin`. Navigate: `G` → `ffffffffd0930038` (sysent) or
`ffffffffd17021f8` (first cdevsw). The structs `ps5_sysent` and `cdevsw` are in the Data Type
Manager; `sysent` and the `cdevsw_*` labels are in the symbol table, with ANALYSIS bookmarks on
each.

Headless re-run (data is already imported; re-applying the map):

```
cd C:\Users\USER\AppData\Local\kex\cache\scratch\ps5
MSYS_NO_PATHCONV=1 cmd.exe /c run_ghidra_1360_proc.bat      # -process + MapKernelData.java
```

Full re-import (fresh program, `-noanalysis`, relocate + map):

```
MSYS_NO_PATHCONV=1 cmd.exe /c run_ghidra_1360.bat
```

## Scripts / artifacts

- `ghidra_scripts/Relocate1360.java` — pre-script: moves the raw block to `0xffffffffd0930000`.
- `ghidra_scripts/MapKernelData.java` — post-script: defines `ps5_sysent` + `cdevsw`, applies
  `sysent[677]` and the 33 cdevsw tables, writes `ghidra_map_report.txt`.
- `run_ghidra_1360.bat` / `run_ghidra_1360_proc.bat` — launch wrappers.
- `ghidra_map_report.txt` — machine-readable cdevsw list (off / va / name).
