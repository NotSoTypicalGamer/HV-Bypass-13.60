# PS5 13.60 HV Dump — String/Symbol Map

**Scope:** 186 × 1 MiB guest-PA chunks `hvcluster_<hex>.bin` in `C:\Users\USER\Caliper-C0re\kernel\hv_dump\`.
**Method:** offline ASCII extraction (printable bytes 0x20–0x7E, run length ≥ 4), full-dump dedupe, cross-reference by (chunk, file-offset).
**Raw artifacts produced alongside this doc:**
- `hv_strings_raw.json` — full string → [(chunk, offset)…] map (341,615 unique strings from 1,779,673 total).
- `hv_strings_all.tsv` — one row per unique string (first location).
- `extract_strings.py`, `analyze2.py`, `analyze3.py`, `analyze4.py`, `analyze5.py` — reproducible extraction/analysis scripts.

---

## 0. Headline finding (read this first)

**The dumped chunks do NOT contain the AMD SVM hypervisor.** No `vmmcall`, `vmrun`, `vmload`, `vmsave`, `clgi`, `stgi`, `skinit`, `vmcb`, `npt`, `vmexit`, `vmentry`, `intercept`, `hypercall`, `hypervisor`, `iommu`, or `tmr` string exists anywhere in the 186 chunks (case-insensitive, word-boundary and substring search both). The one literal `\bSVM\b` hit is `<Svm` (2×) and `sVM(` (1×) — coincidental substrings inside opaque/encoded data, not identifiers.

What the dump **actually** contains is a live PS5 guest-physical snapshot: the FreeBSD-derived kernel + rtld, the RNPS/React-Native VSH UI, system module tables, telemetry JSON, fonts, and user/browser data (including the operator's own "Relapse" HV-RE tooling logs). The HV image itself is either not resident in these guest-PA ranges, or is packed/encrypted with no plaintext ASCII.

This is the single most important result: **a hypercall/VMCB/IOMMU string map of this dump is empty by construction.** The useful, real deliverables below are the kernel string set, the Sony build paths, and the module inventory.

---

## 1. Chunk inventory

- 186 files, 1 MiB each (187 MB total).
- **160 unique** 1 MiB images; **27 are byte-identical zero-fill** (unmapped/zero guest pages, all 0x00):
  `2e500000, 34900000, 39e00000, 3af00000, 3d900000, 3df00000, 3ee00000, 3ef00000, 3f600000, 3f700000, 40300000, 40700000, 42800000, 43a00000, 43b00000, 43c00000, 43e00000, 4c600000, 4cc00000, 4d500000, 4da00000, 4eb00000, 50d00000, 55f00000, 57600000, 5a400000, 5ff00000`.
- Guest-PA span observed: `0x07d00000` … `0x5ff00000` (and one `0x0e800000`).

### Kernel-resident chunks
The FreeBSD kernel/rtld/firmware-patch content lives in **8 chunks**, and the same 1 MiB region is aliased at multiple guest PAs (identical string offsets in each — e.g. `[%s:%d ERR]<%d>` at `+0xaa9f0` in all eight):

| guest-PA | file |
|---|---|
| 0x07d00000 | hvcluster_7d00000.bin |
| 0x09f00000 | hvcluster_9f00000.bin |
| 0x0cb00000 | hvcluster_cb00000.bin |
| 0x0dc00000 | hvcluster_dc00000.bin |
| 0x0e800000 | hvcluster_e800000.bin |
| 0x19a00000 | hvcluster_19a00000.bin |
| 0x1bc00000 | hvcluster_1bc00000.bin |
| 0x1f200000 | hvcluster_1f200000.bin |

---

## 2. Category (a) — Hypercall names / SVM feature strings

**None found.** Explicitly searched (case-insensitive, word + substring):
`vmmcall, vmrun, vmload, vmsave, clgi, stgi, skinit, vmgif, vintr, vmlaunch, vmresume, invd, wbinvd, invlpga, invlpg, clflush, vmcb, SVM, npt, nested paging, vmexit, vmentry, #VMEXIT, intercept, hypercall, hypervisor, hyp_, hyperv, iommu, dte, devtab, ppr, ivrs, interrupt remap, intremap, amdiommu, gcr3, iommu_reg, tmr`.

Only false-positive substrings (`<Svm`, `sVM(`, `Xd-TMR3`, `BEK4zTmR87w…`) matched; these are opaque/entropy data, not symbols. **Conclusion: no IOMMU/TMR/VMCB/hypercall machinery is nameable from this dump.**

---

## 3. Category (b) — Error / panic / format strings

The kernel/rtld string set (all in the 8 kernel chunks; offsets are within each chunk):

| string | occ | first chunk | first offset |
|---|---|---|---|
| `[%s:%d ERR]<%d>` | 174 | 19a00000 | 0xaa9f0 |
| `%s[%d]:panic:` | 51 | 19a00000 | 0xaac67 |
| `%d,%d` | 23 | 19a00000 | 0xaad50 |
| `%s:0x%x` | 21 | 19a00000 | 0xaad90 |
| `### %s : pid%d is not suspended.` | 16 | 19a00000 | 0xe0eb0 |
| ` (%s)` | 16 | 19a00000 | 0xe130a |
| `overflow. continue.` | 14 | 19a00000 | 0xaaa00 |
| `[rtld] <%d> ERROR %u:C: %s: No space available for static Thread Local Storage` | 14 | 19a00000 | 0xa8710 |
| `[rtld] <%d> ERROR %u:C: ERROR in .pltrela (i %d  offset 0x%lx)` | 14 | 19a00000 | 0xa8150 |
| `[rtld] <%d> ERROR %u:C: Unsupported DT tag %lx found in %s` | 14 | 19a00000 | 0xa84c0 |
| `[rtld] <%d> ERROR %u:C: type %d  val 0x%lx  addend 0x%lx` | 14 | 19a00000 | 0xa8610 |
| `[rtld] <%d> ERROR %u:C: segment not found (0x%lx)` | 14 | 19a00000 | 0xa8290 |
| `[rtld] <%d> ERROR %u:C: type %d  addend 0x%lx` | 14 | 19a00000 | 0xa89b0 |
| `[rtld] <%d> ERROR %u:C: sz %ld` | 14 | 19a00000 | 0xa8a60 |
| `INVALID` | 8 | 19a00000 | 0x3a234 |

The `[rtld]` prefix and `.pltrela` / `DT tag` / `TLS` wording identify the **FreeBSD runtime linker (rtld-elf)** and the `[%s:%d ERR]`/`panic:` wrappers identify the **FreeBSD-derived kernel** printf/panic paths. Offsets repeat at `+0x100000` stride across the aliased chunks (e.g. `0xaa9f0`, `0x7aa9f0`, `0x8aa9f0`, `0x9aa9f0`), confirming whole-1MiB aliasing.

Additional kernel-adjacent identifiers in the same chunks:
`dswload` (ACPI table loader), `_remap_`, `bt_usb`, `bt_hci`, `SIEIPMI`, `IccTask`, `>utmath` (FreeBSD soft-float), `stringify`.

---

## 4. Category (c) — Sony build paths & module names

### Build-server paths (highest value — leak the build layout)

| path | occ | chunk(s) |
|---|---|---|
| `W:/Build/J03950001/sys/build/integration/orbis-build_0005c/package/target/phase1/videoout_lvp/src/libSceVideoOut.prx` | 7 | 15900000, 15b00000, 17900000, 1d300000, 1e600000, 1f700000, 1ff00000 |
| `W:/Build/J03950001/sys/build/integration/orbis-build_0005c/package/target/phase1/net/libSceNet.prx` | 2 | 16c00000, 42400000 |
| `W:/Build/J03950001/sys/build/integration/orbis-build_0005c/package/target/phase1/av_cntl-lib/av_manager/libSceAvSetting.prx` | 1 | 1d700000 |
| `W:/Build/J03950001/sys/build/integration/orbis-build_0005c/package/target/phase2/usermode/src/agc_vsh/agc_vsh/internal/prx/libSceAgcVsh.prx` | 1 | 41500000 |
| `W:/Build/J03950001/sys/build/integration/orbis-build_0005c/package/target/phase2/usermode/src/agc_compositor/api/libSceComposite.prx` | 1 | 43700000 |
| `W:/Build/J03950001/sys/internal/usermode/src/libc/Prospero_Release/libSceLibcInternal.prx` | 1 | 42400000 |
| `W:/Build/J03950001/sys/internal/usermode/src/libsysutil/Prospero_Release/libSceSysUtil.prx` | 2 | 1f400000, 1f600000 |
| `W:\Build\J03950001\sys\internal\usermode\src\audio\audio_out2\audio3d\libaudio3d\src\user\core.cc` | 1 | 1a900000 |
| `W:\Build\J03950001\sys\internal\usermode\src\audio\audio_out2\audio3d\libaudio3d\src\user\port.cc` | 1 | 1a900000 |
| `W:\Build\J03950001\sys\internal\usermode\src\audio\audio_out2\audio3d\libaudio3d\src\user\object.cc` | 1 | 1a900000 |
| `W:\Build\J03950001\sys\internal\usermode\src\audio\audio_out2\audio3d\libaudio3d\src\common\audio3d\shm.cc` | 1 | 1a900000 |
| `W:/Build/J03950011/middleware/common_lib/becore_main/prospero/becore.elf` | 2 | 17f00000 |
| `W:/Build/J03950016/vsh/dist/fsroot/system_ex/common_ex/lib/Sce.Vsh.LncUtilWrapper.dll.prx` | 6 | 14e00000, 16c00000, 1dd00000 |
| `W:\Build\J03950016\vsh\dist\fsroot\system_ex\common_ex\lib\Sce.Vsh.LncUtilWrapper.dll.strip_tmp` | 3 | 14e00000, 16c00000, 1dd00000 |
| `W:/Build/J03950016/vsh/dist/fsroot/system_ex/common_ex/lib/Sce.PlayStation.Icu.dll.prx` | 1 | 15b00000 |
| `W:\Build\J03950016\vsh\dist\fsroot\system_ex\common_ex\lib\Sce.PlayStation.Icu.dll.strip_tmp` | 1 | 15a00000 |
| `W:/Build/J03950016/vsh/common_lib/Prospero_Release/libSceSystemLogger2Delivery.prx` | 1 | 41500000 |
| `C:\jnkd\workspace\rnps_ppr_releases_13.60\rnps\Libraries\PopupMenu\PopupMenuBase.ps.tsx` | 1 | 3e500000 / 45200000 (RNPS blob) |
| `C:\jnkd\workspace\rnps_ppr_releases_13.60\rnps\Libraries\Modal\Modal.ps.tsx` | 1 | RNPS blob |
| `../bluetooth/output/patch/hal/auto_gen/btsys17_a7972_pos/BT_Power_on_sequence_emi_rom.c` | 1 | 9f00000 |
| `patch/wf_wm/cal/hal_cal_flow_rom_patch.c` | 6 | kernel chunks |
| `patch/wf_wm/cal/hal_cal_manu_rom_patch.c` | 6 | kernel chunks |
| `../patch/common/sys_patch_common_mcu.c` | 1 | 9f00000 |

Notes:
- Build roots: **`W:/Build/J03950001`**, **`W:/Build/J03950016`**, **`W:/Build/J03950011`** (Sony Windows build servers), and **`C:\jnkd\workspace\…`** (RNPS/PPR release build tree for 13.60).
- The `J0395…` is the chip/build job id; `orbis-build_0005c` is the integration branch; `Prospero` is the PS5 codename used in release dirs; `rnps_ppr_releases_13.60` ties the RNPS UI build to firmware 13.60.
- `.cc` files under `libaudio3d` leak that the audio stack is C++ with named sources (core/port/object/shm).

### Kernel/system module inventory (`.prx`/`.sprx`/`.elf`)

| name | occ | chunk |
|---|---|---|
| `common/lib/libkernel.sprx` | 7 | kernel chunks |
| `/mini-syscore.elf:/orbis-itf-204.elf` | 3 | 1bd00000, dc00000, e800000 |
| `/mini-syscore-cronos.elf` | 3 | 1bd00000, dc00000, e800000 |
| `libSceLibcInternal.prx` / `.sprx` | 14 | 14e00000, 15900000, 15b00000, 16c00000, 17f00000, 1dd00000, 1e600000, 1f400000, 1f600000, 1f700000, 1ff00000, 42400000 |
| `libSceVideoCoreInterface.prx`, `libSceVideoStreamingEngine_sys.prx`, `libSceFont-module.prx`, `libSceFontFt-module.prx`, `libSceSystemService.prx` | 1 | 17f00000 |
| `libSceFsInternalForVsh.sprx`, `libSceAbstractYoutube.sprx`, `libSceMediaFrameworkUtil.sprx`, `libSceAppInstUtil.sprx`, `libSceVdecSvp9.native.sprx`, `libSceSysmodule.sprx`, `libSceCdlgUtilServer.sprx`, `libSceGvMp4Parser.sprx`, `libSceOrbisCompat.sprx`, `libSceContentListController.sprx`, `libSceHidControl.sprx`, `libSceWebmParserMdrw.sprx`, `libSceNpGameIntent.sprx`, `libSceVnaInternal.sprx`, `libSceAppDbShellCoreClient.sprx`, `libSceBackupRestoreUtil.sprx`, `libSceShareInternal.native.sprx`, `libSceUserService.sprx`, `libSceVdecSavc2.native.sprx`, `libSceWebKit2Secure.sprx`, `libSceVnaWebsocket.sprx`, `libSceVoiceCommand.sprx`, `libSceEmbeddedTts.sprx`, `libScePosixForWebKit.sprx`, `libSceSystemLogger2Delivery.sprx`, `libSceAgcVshDebug.sprx`, `libSceAjm.native.sprx`, `libSceNpRemotePlaySessionSignaling.sprx`, `libSceNpWebApi2.sprx`, `libSceSocialScreen.sprx`, `libSceAgcResourceRegistration.sprx`, `libSceGifParser.sprx`, `libSceJitBridge.sprx`, `libScePngParser.sprx`, `libSceBgsStorage.sprx`, `libSceCommonDialog.sprx`, `libSceSystemTts.sprx`, `libSceAvSetting.sprx`, `libSceRnpsAppMgr.sprx`, `libSceVisionManager.sprx`, `libSceAsyncStorageInternal.sprx`, `libSceLibreSsl3.sprx`, `libSceOpusCeltEnc.sprx`, `libSceGpuCapture.sprx`, `libSceRemotePlayClientIpc.sprx`, `libSceAudiodecCpuDtsHdMa.sprx`, `libSceSystemLogger2Game.sprx`, `libSceOpusSilkEnc.sprx`, `libSceResourceArbitrator.sprx`, `libSceVdecShevc.native.sprx`, `libSceAbstractTwitter.sprx`, `libSceCompositeExt.sprx`, `libSceNpManager.sprx`, `libSceAbstractLocal.sprx`, `libSceKbEmulate.sprx`, `libSceMetadataReaderWriter.sprx`, `libSceLoginMgrServer.sprx`, `libSceRazorCpu_debug.sprx`, `libSceSulphaDrv.sprx`, `libSceDataTransfer.sprx`, `libSceMediaFrameworkInterface.sprx`, `libSceAgcDriver.sprx`, `libSceVdecCore.native.sprx`, `libSceAudiodecCpuTrhd.sprx`, `libSceHttpCache.sprx`, `libSceJpegParser.sprx`, `libSceSystemService.sprx`, `libSceAudioSystem.sprx`, `libSceEmbeddedTtsCoreG3.sprx`, `libSceSystemLogger2.sprx`, `libSceAbstractStorage.sprx`, `libSceTEEClient.sprx`, `libSceJxrParser.sprx`, `libSceSystemLogger2NativeQueueClient.sprx`, `libSceImageUtil.sprx`, `libSceComposite.sprx` … | 1 | 42400000 (module table) |
| `libSceRnpsNKInjectedBundle.sprx` | 2 | 37f00000 |
| `Sce.Vsh.SysBridge.dll`, `Sce.Vsh.UILib.dll`, `Sce.Vsh.UserServiceWrapper.dll`, `Sce.Vsh.SystemLoggerWrapper.dll`, `Sce.Vsh.LncUtilWrapper.dll` (each with `.sprx` variants + per-title random-dir prefixes `/Pyb1J2ViX0/`, `/oOomYhYm6r/`, `/ZO4qfSTZLa/`, `/2VrFNJtzgp/`) | — | 14e00000, 17f00000, 1d800000, 1f600000 |

`hvcluster_42400000.bin` (guest-PA 0x42400000) is a **module-name table** (long contiguous run of `libSce*.sprx` names) — a good anchor for SceKernel module-list recovery.

---

## 5. Category (d) — Function-name-like identifiers

No C++-mangled or exported symbol names survive in plaintext (the kernel text is not symbol-bearing). The only identifier-shaped strings are the module/feature names above and the RNPS JS identifiers (React/VirtualizedList/accessibility_controller/psfx_* — thousands, mostly VSH UI, not HV). Notable non-UI identifier strings:

- `dswload`, `_remap_`, `INVALID`, `IccTask`, `SIEIPMI`, `>utmath`, `stringify` (kernel chunks)
- `PlayingTitleStateNotHavingNptitleId` (VSH, 58500000/59c00000 — note: "Np" = PlayStation Network, **not** nested-paging NPT)
- `GetApprovedInvestigationList`, `mapProfileToCriteria`, `NetCtlGetInfoHttpProxyServer/Config` (VSH)

---

## 6. Notable: operator's own HV-RE tooling ("Relapse") — *user data, not HV code*

The web-browser cache in the dump contains the operator's PS5 hypervisor-exploitation tooling logs (a public "Relapse" payload host), including telemetry/beacon URLs carrying exploit state. These are **guest userland/browser data**, not hypervisor text — but they corroborate the machine's purpose and may be useful context for the parent task:

- `https://soniciso1.github.io/relapse/log/REP-s14-PAIR-UP main=0x1000e1c220-worker=0x1000e1c2e0-home=0x100096f500-mode=0x0-sid=0x17eb0-released=13-history-cleared=true` (chunk 5df00000)
- `…/relapse/log/LT-s16-[1] PREDECESSOR-FILLED qwords=65536-fake=0x10008e8f10` (5df00000)
- `…/relapse/log/LT-s31-PAIR-IDENTITY main-cell=proved-main-buffer=proved-worker=proved` (5df00000)
- `…/relapse/log/REP-s9-PAIR-IDENTITY …`, `LT-s26-PAIR-CELLS …`, `REP-s4-PAIR-CELLS …` (5df00000)
- Relapse HTML/JS payload + `relapse.auto-retry` session keys (20000000, 34600000)

Also present (unrelated browsing): wololo.net PSP homebrew articles and GoldHEN/etaHEN payload download links (chunk 1d800000).

---

## 7. Bottom line

1. **No SVM/hypercall/VMCB/IOMMU/TMR strings exist in the dump** — the AMD SVM monitor is not recoverable from these chunks via string analysis; it is encrypted/packed or not resident at the captured guest-PAs.
2. The dump is a **guest-physical snapshot**: FreeBSD-derived kernel + rtld (8 aliased chunks), a `libSce*.sprx` module table (0x42400000), RNPS/VSH UI, telemetry, and user/browser data.
3. Highest-value recoverables are the **Sony build-server paths** (`W:/Build/J03950001|J03950011|J03950016`, `C:\jnkd\workspace\rnps_ppr_releases_13.60`) and the **module inventory** — useful for later disassembly anchoring, but unrelated to the HV proper.
4. To actually map HV symbols, the hypervisor image must be dumped from its own (very high, non-guest) physical range or decrypted first; these 186 chunks cannot provide it.
