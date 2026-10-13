# FIRMWARE_DIFF.md — 7.61 vs 11.60 vs 13.60 (kernel `.data` dumps)

**Generated:** 2026-10-05 (offline, own console).
**Sources:** `kdata_761.bin`, `kdata_1160.bin`, `kdata_1360.bin` — all three present, 15,728,640 bytes each (raw kernel `.data` segment, absolute pointers).
**Method:** byte-level scan of all three dumps with the same script (Python `struct`), cross-checked against `SYSENT_LAYOUT.md`, `HV_WRAPPERS.md`, `IOMMU_CMDBUF.md`, `DATA_DIFF_761_1360.md`.

## Dump inventory (all three represented)

| firmware | `.data` base VA       | sysent file off | sysent VA            |
|----------|-----------------------|-----------------|----------------------|
| 7.61     | `0xffffffff95570000`  | `0x10018`       | `0xffffffff95580018` |
| 11.60    | `0xffffffffd4960000`  | `0x18`          | `0xffffffffd4960018` |
| 13.60    | `0xffffffffd0930000`  | `0x38`          | `0xffffffffd0930038` |

> **No `.data` dump is missing.** 7.61, 11.60 and 13.60 are all fully represented at the `.data`-segment level. What is *not* represented (see "Gaps" below): the XOM `.text`, the module/BSS KASLR region (`base − ~0x9B0000..0xA60000`), the hypervisor component itself, and every intermediate firmware (8.00/9.00/etc.).

---

## (a) sysent / syscall table

Stride **24 bytes** (verified): `{u32 sy_argsize=8, u32 pad=0, u64 sy_call, u64 sy_meta}`.

| field | 7.61 | 11.60 | 13.60 |
|---|---|---|---|
| table size (entries) | **917** (idx 0..916) | **909** (idx 0..908) | **909** (idx 0..908) |
| `nosys` stub (addr / slots) | `0xffffffff812337fd` / 194 | `0xffffffff812f5854` / 194 | `0xffffffff814c2ca5` / 194 |
| `lkmnosys` stub (addr / slots) | `0xffffffff812aaacf` / 34 | `0xffffffff8135fbc3` / 34 | `0xffffffff81530282` / 34 |
| 3rd Sony stub (addr / slots) | `0xffffffff81297f40` / 17 | `0xffffffff812be850` / 17 | `0xffffffff8148b082` / 17 |
| total stubs | 245 | 245 | 245 |
| live syscalls | **672** | **664** | **664** |

**Diff:**
- **11.60 vs 13.60 — identical.** Stub-status map (live vs stub per index) is byte-identical across all 909 entries. Same count, same order, same stub set.
- **7.61 vs 11.60/13.60 — 8 extra entries, nothing else.** 7.61 carries **8 extra Sony syscall entries at indices 532–539** whose `sy_call` does not point at a normal text handler but into a `0xc0`-byte-strided metadata table (`0xffffffff80ffac30 … 0xffffffff80ffb170`). These 8 are removed in 11.60. After shifting every 7.61 index `≥ 541` down by 8 (`7.61[i] ↔ 11.60/13.60[i−8]`), the live/stub maps are **identical** (symmetric difference = ∅). 672 − 664 = 8 accounts for the whole live-count delta.
- No syscall is added or re-stubbed across the three; the FreeBSD 11.0 base (~550 slots) is frozen, and Sony's own aio/acl/extattr/ksem/kmq/kse families are live on all three. (The earlier "74 changes / aio-added-in-11.60" in `SYSCALL_DIFF_761_1160.md` was a 48-byte-stride artifact; superseded by `SYSENT_LAYOUT.md`.)

---

## (b) hypercall wrapper strings + `hv_*` function VAs

String **identity is stable** across all three firmwares; only the file offset / VA moves. Every `hv_*` wrapper error-format string present in 13.60 is also present in 7.61 and 11.60 (same occurrence count per string). `hv_map_pt_tmr` and `hv_iommu_read_device_table` are **absent in all three** (0 hits) — `MAP_PT_TMR` / `IOMMU_READ_DEVICE_TABLE` have no named wrapper string in any dump.

| wrapper (hypercall #) | 7.61 off / VA | 11.60 off / VA | 13.60 off / VA |
|---|---|---|---|
| `hv_iommu_set_guest_buffers` (0x6) | `0x39aa24` / `…9590aa24` | `0x412608` / `…d4d72608` | `0x65236e` / `…d0f8236e` |
| `hv_iommu_enable_device` (0x7) | `0x3e917c` / `…9595917c` | `0x3cbc07` / `…d4d2bc07` | `0x609adb` / `…d0f39adb` |
| `hv_iommu_bind_pasid` (0x8) | `0x37e62c` / `…958ee62c` | `0x3a39f5` / `…d4d039f5` | `0x5e09de` / `…d0f109de` |
| `hv_iommu_unbind_pasid` (0x9) | `0x3d5995` / `…95945995` | `0x427120` / `…d4d87120` | `0x667a58` / `…d0f97a58` |
| `hv_iommu_check_evlog_regs` (0xb) | `0x3bf534` / `…9592f534` | `0x493e59` / `…d4df3e59` | `0x6d7452` / `…d1007452` |
| `hv_get_tmr_violation_error` (0xd) | `0x4328f9` / `…959a28f9` | `0x3c8d95` / `…d4d28d95` | `0x606e22` / `…d0f36e22` |
| `hv_unmap_pt_tmr` (≥0x11) | `0x3a2129` / `…95912129` | `0x3977e5` / `…d4cf77e5` | `0x5d42df` / `…d0f042df` |
| `hv_restore_pt_tmr` (≥0x11) | `0x398950` / `…95908950` | `0x38ed06` / `…d4ceed06` | `0x5cb0ce` / `…d0efb0ce` |
| `hv_startup_mp` (0xf) | `0x492272` / `…95a02272` | `0x43008a` / `…d4d9008a` | `0x6709a6` / `…d0fa09a6` |
| `hv_n_devices` (helper) | `0x37e67f` / `…958ee67f` | `0x3e9e8a` / `…d4d49e8a` | `0x628ba7` / `…d0f58ba7` |

(Full hypercall-number → wrapper map, `0x0`–`0x10` + the `*_PT_TMR` tail, is in `HV_WRAPPERS.md` §2 — it applies identically to all three.)

**`hv_*` function VAs: NOT recoverable from any of the three dumps.** The wrappers live in XOM text and are referenced only by RIP-relative `lea`; there is zero `.data` xref to any `hv_*` string, and the kernel symtab is stripped. This is a verified negative on 7.61, 11.60 **and** 13.60 (not a 13.60-specific gap). The one HV-interface handler that *is* resolvable is the deci5s/sdbgp `VMMCALL` debug-command handler (`HV_WRAPPERS.md` §4, 13.60 slid `0xffffffffcfeced70` / canonical `0xffffffff8046ed70`); its 7.61/11.60 counterparts were not resolved here and would need the same dispatch-table scan per dump.

---

## (c) IOMMU unit-context offsets

**MMIO window VAs (`softc->ctrl`) — stable physical layout, KVA region slides per firmware.** Physical base `0x01130000`, stride `0x4000`, same 21 windows (`N = −4 … +16`, i.e. `0x01120000 … 0x01170000`) in all three.

| firmware | MMIO KVA base (window N=0) | `.data` slot for N=0 |
|---|---|---|
| 7.61  | `0xffffdfbb01130000` | `0xe3a1c8` / VA `0xffffffff965aa1c8` |
| 11.60 | `0xffffc8d801130000` | `0xdfaf38` / VA `0xffffffffd495af38` |
| 13.60 | `0xffffec8c01130000` | `0xe0caf8` / VA `0xffffffffd173caf8` |

(Per-window file offsets for 13.60 are tabulated in `IOMMU_CMDBUF.md` §2; 7.61 and 11.60 windows follow the same `+0x4000` stride with the offsets shown in the table above shifted by the per-firmware base.)

**`iommudrv` module registration record** — anchored by the same magic `0x3454f8e9`, name `"iommudrv"`, and `count=4` in all three, but at shifted offsets. The *stable* invariant (name 8 bytes after magic, MMIO 8 bytes after name, count 8 bytes after MMIO) holds on all three:

| firmware | magic offset | name `"iommudrv"` | MMIO ctrl (window it points at) | count |
|---|---|---|---|---|
| 7.61  | `0xe3a3e8` | `0xe3a3f0` | `0xffffdfbb01134000` (N=1) | 4 |
| 11.60 | `0xdfacb8` | `0xdfacc0` | `0xffffc8d80112c000` (N=−1) | 4 |
| 13.60 | `0xe0d8b8` | `0xe0d8c0` | `0xffffec8c0113c000` (N=3) | 4 |

> **Correction to `DATA_DIFF_761_1360.md`:** its "name moved `+0x30`→`+0x20`, two leading fields gone" is an artifact of choosing two different struct bases. With a consistent base the layout `+0x00 ptr · +0x08 ptr · +0x10 ptr · +0x18 magic · +0x20 name · +0x28 MMIO · +0x30 count=4` is **stable across all three**; the only real drift is the number of leading pointer fields (two non-zero in 7.61/11.60, three in 13.60) and the specific MMIO unit each record points at.

**Command-buffer PA / `cmd_head` / `cmd_tail` / device-table PA** remain unrecoverable from `.data` alone on all three (they exist only in MMIO registers and page tables) — unchanged from `IOMMU_CMDBUF.md` §4.

---

## (d) module list / string-table drift

| anchor | 7.61 | 11.60 | 13.60 | meaning |
|---|---|---|---|---|
| a53mm build tag | `W:/Build/J02798634` | `W:/Build/J03675007` | `W:/Build/J03950001` | a53mm **rebuilt twice** (7.61→11.60 and →13.60) |
| `a53mm` string hits | 1310 | 1326 | 1368 | a53mm surface grows each rev |
| `DPFS2` filesystem | **absent** | 35 hits | 39 hits | DPFS2 **new in 11.60**, grown in 13.60 |
| `kMmcCmdRing*` MMC ring | **absent** | 4 hits | 4 hits | MMC cmd-ring priority **new in 11.60** |
| `LP#%04x` (SSD FTL) | 1 hit | 1 hit | 3 hits | FTL GC/trim format strings expanded in 13.60 |
| `sce_svmd.c` (svmd/SVM driver) | present | present | present | SVM driver present all three |
| `psp_mbox_send_sysmail` | present | present | present | psp_mbox path present all three |
| `TMR check violation` | present | present | present | TMR managed all three |
| `W:/Build/J` total hits | 774 | 799 | 821 | growing source-path/`__FILE__` string set (more modules) |

**Interpretation:** the Sony-original delta between 7.61 and 11.60 is the **a53mm rebuild + DPFS2 filesystem + MMC cmd-ring** (new I/O/filesystem code); between 11.60 and 13.60 it is a second **a53mm rebuild + FTL GC/trim format expansion**. The FreeBSD 11.0 base (vmspace, sysent, syscall handlers) is frozen and byte-stable. No full `linker_files`/module linked-list is present in these dumps — that list lives in the module/BSS KASLR region (see Gaps), so "module list" here is the string-anchor evidence, not the loader's list.

---

## Gaps — what is NOT represented, and what completes each row

| row | missing | needed to complete |
|---|---|---|
| sysent `sy_call` *handler identity* | text is recompiled per firmware, so `sy_call` addresses differ even for unchanged syscalls | the slid `.text` (or a symbol map) per firmware to map handler addresses → names |
| the 8 extra 7.61 entries (532–539) | what those 8 syscalls actually are | disassembly of `0xffffffff80ffac30…80ffb170` or the 7.61 `syscallnames[]` table |
| `hv_*` wrapper **VAs** | XOM text absent from all three dumps; no `.data` xref; symtab stripped | a slid-text read (NPT/DMAP) + `0F 01 D9` scan (`HV_WRAPPERS.md` §5) per firmware |
| IOMMU cmd-buf **PA** / head/tail | only in MMIO + page tables | MMIO read of `cmd.base` (needs IVRS/ECAM PA) or `pmap_kextract` of `0xffffffffd31e4000` |
| a53mm `context` / psp_mbox state / TMR config | live in module/BSS region `base − ~0x9B0000..0xA60000` | a second `kernel_copyout` of that region per firmware |
| full module linked-list | in module/BSS region | same region dump + walk `linker_files`/`modules` |
| 8.00 / 9.00 / intermediate deltas | no dumps present | a dump of any intermediate firmware to isolate the 8.00 HV change specifically |
