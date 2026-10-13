# A53MM / psp_mbox secure-IPC audit — PSP command/response path

**Scope:** offline, strings-only. Source = `kdata_1360.bin` (13.60 `.data`, base
`0xffffffffd0930000`) printable-string graph + the FreeBSD 11.0 source tree + the public
`astrelsky/mp4rw` / `cragson/a53-code-exec` artifacts. The `psp_mbox_*` / `a53mm_*` **code is in
the XOM text region** — the strings below are the rodata anchors the code references, so this is an
*inference* from string adjacency + the AMD-PSP mailbox analog, **not** a disassembly. Confidence is
marked per claim.

**FreeBSD analog: none.** FreeBSD 11.0 has no AMD-Vi/CCP/PSP driver (`sys/x86/iommu/` is Intel-only,
and there is no `ccp`/`psp`/`sev` device anywhere in `sys/`). The whole `a53mm`/`psp_mbox`/`svmd`
family is **Sony-original**. The closest public analog for the mailbox *shape* is Linux
`drivers/crypto/ccp/psp-dev.c` (AMD PSP mailbox: a fixed-size command buffer + doorbell + reply
timeout, `sev_issue_cmd`, and the TMR/`SEV` command set) — use it as the protocol template, not the
source of truth.

---

## 1. The three processors and who owns what

The dump names three secure-world actors the x86 kernel talks to:

| name | identity | evidence (string) | owned surface |
|---|---|---|---|
| **PSP** | Oberon A53 / AMD Platform Security Processor (ARM EL3) | `Oberon PSP`, `[PSP] …`, `sceSblPspPrivateDataExport`, `mmDIO_PSP_INTERRUPT_CLEAR/STATUS`, `PSP doesn't reply message(…)`, `PSP private region violation` | XOM text encode, TMR config, GPU/CPU MMU VMIDs, the a53mm mailbox |
| **MP1** | AMD SMU (System Management Unit, power/clock) | `[MP1ERROR]`, `MP1_C2PMSG_90/91/…`, `mp1fw_waitmsg`, `sceSblMp1Initialize/DumpContext/EnableErrorDetection`, `mp1_bapm_logger_ioctl`, `MP1_IOCTL_GET_CLK` | power/clocks + **`SecReg(MP1 Dump TMR)`** (TMR register dump) |
| **MP4** | the A53 debug/complex (`/dev/mp4/dump`, DECI5S endpoint) | `SceMp4CdevMtx`, `SceMp4CoredumpThread`, `mp4_intdev_*`, `mp4_to_deci5s_write_mbox`, `MP4_C2PMSG_C2P_CORE0_REQ` | DECI5S/sdbgp debug protocol → EL3 memory R/W + HV tracing |

`svmd` (`sce_svmd.c`, `svmd mtx`, `svmd_stop_handler`) is the AMD SVM driver that fronts the
hypervisor; the `hv_*` strings are its VMMCALL surface.

---

## 2. (a) The psp_mbox structure (inferred)

### 2.1 The mailbox pool — 16 slots, bitmap-allocated

The mailbox layer is a **fixed pool of 16 mailbox slots (id 0–15)**, allocated by id:

```
STATE (SBL->x86, #0-14,#15(Pol)): bmp_0x%x (rcvd bmp_0x%x)   @0x5d5d86
make_mbox: too large id                                      @0x5c4c54
ERROR: %s(%d) no free mbox                                   @0x5d5d45
ERROR: %s(%d) psp_mbox_send_sysmail                          @0x5d5d61
```

- `make_mbox(id)` builds a mailbox with `id < 16` (the `#0-14,#15(Pol)` string says slot 15 is the
  **Policy** mailbox — reserved). `make_mbox: too large id` = the bounds check.
- The pool is tracked by a **bitmap** (`bmp_0x%x` / `rcvd bmp_0x%x`); `no free mbox` is the
  exhaustion path inside `psp_mbox_send_sysmail` (the two strings are adjacent in rodata — the
  `no free mbox` error is emitted by `psp_mbox_send_sysmail`).
- Accounting counters (each mailbox has request/free/nop counts):
  `mbox_req_count = 0x%08x` @0x5e23f9, `mbox_free_count = 0x%08x` @0x69e09d,
  `mbox_nop_count = 0x%08x` @0x69e0b9, `mbox req/free/nop = 0x%08x/0x%08x/0x%08x` @0x6886b5.

### 2.2 Send/receive flow

```
Mbox Is Busy(0x%X, 0x%X). Send(Cmd 0x%X)                     @0x5ac7f1
PSP doesn't reply message(0x%X) (Cmd 0x%X)                   @0x631176
Recovery Flag detected, ignore the command(Cmd 0x%X)         @0x631140
ERROR: %s(%d) mailbox err%08x                                 @0x69ab06
```

Semantics (inferred, MEDIUM confidence): `psp_mbox_send_sysmail(cmd)` → pick a free slot
(`no free mbox` on exhaustion) → if busy, spin/log `Mbox Is Busy` → write the command into the
mailbox ring (`mp4_to_deci5s_write_mbox` is the write primitive) → ring the doorbell
(`MP4_C2PMSG_C2P_CORE0_REQ` / `MP1_C2PMSG_*`) → block on the reply → `PSP doesn't reply message`
on timeout. The message carry both a **mailbox id** (`message(0x%X)`) and a **command id**
(`Cmd 0x%X`).

### 2.3 The ring + per-core mailbox

The transport ring is per-core, two cores:

```
dtmc_mp4_mbox_c2t_core0 %p - 0x%08x                           @0x6a080f
dtmc_mp4_mbox_c2t_core1 %p - 0x%08x                           @0x68018b
mp4_to_deci5s_write_mbox                                      @0x63a3ac
a53ring_set_mailbox()                                         @0x61f5e4
otherMailbox                                                  @0x67a679
```

`c2t` = "core-to-target"; the mailbox is a ring (`a53ring_*`) with a doorbell mailbox. `a53ring_set_mailbox`
ties the a53mm input ring to the PSP mailbox. The SBL wrapper is the "SysMail" service:

```
sceSblServiceSysMailSend / sceSblServiceMailbox / sceSblServiceMailbox() %d
SysMail failed: %d  ·  SBL SysMail size(%d) %d,%d  ·  sysMailSuspend
```

### 2.4 `psp_mbox_encode_kernel_text` — the XOM setup path

```
psp_mbox_encode_kernel_text           @0x665952
send_encode_kernel_text_cmd           @0x6d82e3
PSP private region violation          @0x665147
```

- `send_encode_kernel_text_cmd` is the **SysMail command builder**; `psp_mbox_encode_kernel_text`
  is the caller. Together they ask the PSP to *encode* (encrypt + mark execute-only) a range of
  kernel text. This is the kernel-side of the **XOM** mechanism: at boot/update the kernel requests
  the PSP to encode a page/range, and the PSP returns the encoded text or flips the SLAT/NPT
  bit-58 ("nda") for it. `PSP private region violation` is the PSP-side guard when the encode range
  touches the PSP's private region (HIGH confidence this pair is the XOM path — it matches the
  `XOM_BYPASS.md` finding that XOM is SLAT bit-58 and the skill's note that
  `psp_mbox_encode_kernel_text` = the XOM path).

### 2.5 `psp_mbox_map_tmr` — the TMR map command

```
psp_mbox_map_tmr                     @0x66fad9
sceSblTmrMap(%d, %lx, %lx)=%d        @0x69d4c1    (id, paddr, size)
sceSblTmrUnmap(%d)=%d                @0x69d4e0    (id)
```

`psp_mbox_map_tmr` is the PSP-mailbox command that maps a **Trusted Memory Region** `(id, paddr,
size)` through the PSP. `sceSblTmrMap` is its SBL wrapper with the same `(id, paddr, size)`
signature. See §4 for the full TMR path.

---

## 3. (b) The a53mm device / ioctl surface

### 3.1 Character devices

| device | evidence | what it is |
|---|---|---|
| `/dev/a53mmsys` | `a53mmsys`, `failed to careate a53mmsys dev` (a53mm.c:306) | the a53mm control device — VMID/priv-mode/page-table/migration ioctls |
| `/dev/a53mm` | module name + `a53mm_context` | the a53mm context/control path |
| `/dev/a53io` | `A53IO_CTRLR`, `a53io driver is loaded`, `fake a53io ctrlr is loaded` | the **NVMe SSD front-end** (`a53io_proc_nvme1_attach`, `a53io_proc_read_block/write/encrypt_block/delete_lp/trim_blocks/invalidate_block_range/change_mode`). The internal SSD (`m2storage`, `BFS_A53IO_*`, `M2BFS_A53IO_*`) runs through it. |
| `/dev/mp4/dump` | `open /dev/mp4/dump` (mp4rw), `mp4_dump_syscore_ioctl_cmd` | the A53 coredump/DECI5S endpoint — **this is the code-exec/R-W door** (mp4rw + cragson) |
| `mp1bapmlog` / MP1 | `mp1_bapm_logger_ioctl`, `MP1_IOCTL_GET_CLK`, `mp1bapmlog` | SMU power/thermal telemetry ioctl surface |

### 3.2 The `/dev/mp4/dump` ioctl commands (from mp4rw `deci.h`)

```
MP4_DUMP_SYSCORE_START_MP4DUMP   = 0x800c410b   // _IOW, starts the mp4 syscore dump
MP4_DUMP_SYSCORE_START_CPDUMP    = 0x8014410d
MP4_DUMP_SYSCORE_FINISH          = 0x8008410f
MP4_DUMP_SYSCORE_UNKNOWN_ALTER_STATE = 0x40184115
```

mp4rw's proven sequence (needs kernel R/W for the `kernel_copyin`/authid swap): `open(/dev/mp4/dump)`
→ `kevent` EVFILT_READ → `ioctl(START_MP4DUMP)` → write a **DECI5S** packet into the mp4 coredump
buffer → `MSI C2P command 0x20303000` into `zcn_bar2 + 0xf6000` (args at `+0xf7000/+0xf8000/+0xf9000`)
→ PSP executes the SDBGP command → reply lands back in the coredump buffer (`+0xf8` = nread, `+0x108`
= data). This is the *mechanism* behind the a53mm/mp4 path, and it already yields **EL3 read/write**.

### 3.3 The devpfs a53ioc surface (SSD metadata ioctls)

`devpfs_a53ioctl.c` exposes `DEVPFS_A53IOC_*` on the `devpfs`/`devpfs.ctl` filesystem:
`BUILDMETADATA`, `FREEMETADATA`, `SET_PKGIDX`, `BUILDNAPSMTDATA`, `INIT_NAPCACHE`,
`REBUILD_NAPCACHE`, `FLUSH_NAPCACHE`, `UPDATENAPSMETADATA`, `DUMPMETADATA`, `GCMETADATA`,
`VERIFY_NAPCACHE`, `NAPSCACHE_RESOLVE`, `GET_STAT`, `GET_OUTEROFFSET`, `SET_VALIDFLAG`,
`IGET`, `UPDATE_SPARSEFILE`, `CONVMEM2SIZE`, `GET_APRDBGINFO` — all SSD/NAPS-cache metadata ops,
**not** a PSP/TMR path (a dead end for this task, listed for completeness).

### 3.4 The DECI5S / sdbgp protocol (the real R/W surface)

The `deci5s` subsystem (`sys/internal/modules/deci5s/…`) is the debug transport. The
`deci5s_main_intdev_sdbgp_context_handle_*` handlers are the command surface:

```
handle_trace_hv_save / hv_status / hv_create / hv_start / hv_delete / hv_stop   <-- HV tracing
handle_trace_set / get / status / pm_get / pm_set / pm_status / pmc_* / ioc_status
handle_tool_memory / tool_memory2 / get_phy_shmem / get_shmem / get_map / get_fmem
handle_get_netif / get_netsocket / get_intr / set_software_breakpoint / func
mp4_deci5s_sdbgp_context_alloc / get_reg / set_reg / read_memory_cmd / break / continue / …
```

**Key:** `trace_hv_*` handlers exist — the A53 can *trace* (save/status/create/start/delete/stop)
the **hypervisor** state. This is the direct answer to "reach the hypervisor config without reading
XOM text": ask the A53 to do it at EL3.

---

## 4. (c) `psp_mbox_map_tmr` ↔ the TMR, and the HV-defeat target

### 4.1 What the TMR is (from the strings)

```
TMR check violation · TMR range is illegal. · One TMR param, id, paddr, or size is invalid
TMR violation, Count %d (PPRREQ-33273) · Detect TMR Violation · TMR Interrupts:
tmr_violation_worker · tmr_viol_spin · tmr_check_on_boot · init_tmr() · PreTmr
=== TMR regions · Excess nummber of TMR regions. · tmr0..tmr7 · tmrDumpReg · tmrdump
hv_get_tmr_violation_error() · hv_restore_pt_tmr[%d] · hv_unmap_pt_tmr(%d)
```

The TMR is a **hardware-enforced Trusted Memory Region**: a set of `(id, paddr, size)` ranges
guarded by the PSP/MP1 (`tmr0..tmr7` config registers) *and* mirrored into the hypervisor's nested
page tables (`hv_restore_pt_tmr` / `hv_unmap_pt_tmr` = VMMCALLs that map/unmap a TMR region in the
HV's NPT). A data access violating a TMR raises a PSP/SMU interrupt → `tmr_violation_worker` →
`hv_get_tmr_violation_error()`.

### 4.2 The map path — YES, there is a kernel→PSP→TMR path

```
psp_mbox_map_tmr                    (PSP mailbox command)
  └─ sceSblTmrMap(id, paddr, size)   (SBL wrapper, @0x69d4c1)
       └─ SecReg("map TMR")          (sbl_secreg dispatch, @0x699b66 "SecReg(map TMR) failed")
            └─ SysMail → PSP/SMU      (psp_mbox_send_sysmail)
                 └─ PSP programs tmr0..tmr7 config registers
hv_restore_pt_tmr[id] / hv_unmap_pt_tmr[id]   (HV NPT side, VMMCALL)
```

The full SecReg operation set (`sbl_secreg`): `map TMR`, `unmap TMR`, `export TMR`,
`enc AMM PT TMR`, `dec AMM PT TMR`, `MP1 Dump TMR`, `export PSP Private Data`,
`MP4 SetDvmSdpCtrl2`, `terminate`. `sceSblTmrExport/EncAmmPt/DecAmmPt/DumpReg` map 1:1 onto these.

**Relationship to the HV-defeat:** the `TMR_CFG_PERMISSIVE = 0x3F07` relaxation that
`hv_defeat_0304` writes (TMR config idx **5, 16, 17, 18**) is **the content of the `tmr0..tmr7`
config registers** that this path programs. In other words: the TMR config the HV-defeat relaxes is
the same config that `psp_mbox_map_tmr`/`sceSblTmrMap` set up, and that `sceSblTmrDumpReg` /
`SecReg(MP1 Dump TMR)` can **read back out of the PSP/MP1**. So the answer to the task's (c)
question is **yes** — and it is two-sided:

- **PSP/MP1 side** (config registers): `sceSblTmrMap/Unmap/DumpReg` via `SecReg`/SysMail.
- **HV side** (NPT mapping): `hv_restore_pt_tmr` / `hv_unmap_pt_tmr` / `hv_get_tmr_violation_error`.

---

## 5. (d) Concrete plan — reach the TMR / hypervisor config via a53mm/psp_mbox

**Why this is needed:** the TMR config registers and the HV's VMCB/NPT are not readable from the
kernel — TMR/HV state is hypervisor-private, and the "second region"
`0xffffffffcfed0000` (`REGION_ACCESS.md`) is slid **XOM text**, not data. `kernel_copyout` on it
returns −1. The a53mm/psp_mbox path is the *alternative*: it reaches the PSP/MP1/A53 at a privilege
level that is **outside** the kernel+hypervisor boundary, so the A53 can read what the kernel cannot.

### Plan A — DECI5S `trace_hv_*` handlers (no new primitive needed, uses mp4rw's transport)

1. Reproduce mp4rw's `/dev/mp4/dump` channel (open → kqueue → `START_MP4DUMP` → DECI5S packet →
   `MSI C2P 0x20303000`). This already gives **EL3 memory read/write**
   (`mp4_memory_type` = `PA_TO_EL3_VA 0x020000` / `EL3_VA_TO_EL3_VA 0x430000` /
   `EL0_VA_TO_EL3_VA 0x400000`).
2. Instead of `READ_MEMORY`/`WRITE_MEMORY`, send the SDBGP `trace` commands that the
   `deci5s_main_intdev_sdbgp_context_handle_trace_hv_save/status/create/start/delete/stop` handlers
   serve — these trace the **hypervisor** state (VMCB save/status) from the A53 side.
3. This reads the HV's VMCB/NPT **without** the root-0-NPT lead and **without** touching XOM text.
   (Confidence: HIGH that the handlers exist and are HV-named; MEDIUM on the exact command encoding —
   it must be reverse-engineered from the `trace_hv_*` handler bodies via single-stepping, since the
   code is XOM.)

### Plan B — A53 EL3 code-exec (cragson, known-unpatched as of 13.60)

1. cragson/a53-code-exec already runs **arbitrary code at A53 EL3** via the DECI5S `sdbgp` protocol
   (`SDBGP_WRITE_MEMORY` patches a `sdbgp` context handler; writes flush the icache). Not patched on
   13.60 (14.00 unverified).
2. From EL3, read the **TMR config registers** (`tmr0..tmr7` — their MMIO is visible to the PSP/SMU)
   and the **HV VMCBs/NPT** directly — both are below EL3 in the A53's own view of the SoC.
3. This is the strongest form of "reach the TMR / hypervisor config": full read *and* write of the
   config that `hv_defeat_0304` had to relax via the IOMMU write primitive.

### Plan C — the psp_mbox/SecReg readback (least invasive)

1. From kernel R/W (post-KEX), call the SBL service: `sceSblTmrDumpReg` →
   `SecReg(MP1 Dump TMR)` (or `sceSblTmrExport` → `SecReg(export TMR)`).
2. These **read the current TMR config out of the PSP/MP1** and return it to the caller — a
   register-level dump of `tmr0..tmr7` including the `TMR_CFG_PERMISSIVE`-style values — without any
   XOM access. This pins the exact config-register values to relax.
3. To *map* a region of your choosing: `sceSblTmrMap(id, paddr, size)` (or `psp_mbox_map_tmr`),
   which is the PSP-side config write; pair it with `hv_restore_pt_tmr[id]` to force the HV NPT
   update. (This is the kernel's *legitimate* TMR config path — using it to map a region that aliases
   the HV's own pages is the abuse.)

### Plan D — keep the IOMMU write primitive, but drive it via the mbox path

`hv_defeat_0304`'s COMPLETION_WAIT write (opcode 0x05, `store_addr = VMCB_PA + 0x90`, `store_data =
0`) needs the VMCB PA. Combine with Plan A/B: use the A53 EL3 read to **find the VMCB PA** (instead
of the `hvscan` physical sweep that already panicked the 11.60), then enqueue the IOMMU command to
clear the VMMCALL intercept at VMCB+0x90, then `vmmcall` on every core. The mbox/a53mm path supplies
the *recon* the XOM block denied.

### Ordering & prerequisites

1. **Prereq:** kernel R/W on 13.60 (Relapse → elfldr). mp4rw needs `kernel_copyin`/authid swap
   (`SYSCORE_ID`) to stage the DECI5S packet — it is a **post-KEX** primitive, not a sandbox entry.
2. Open question to resolve first (already flagged in the skill): is `/dev/mp4/dump` /
   `/dev/a53mm` **sandbox-openable without** kernel R/W? If yes, Plan A/B becomes a pre-KEX route
   into EL3; if no, it stays a chained stage.
3. Do the `trace_hv_*` command-encoding RE via single-stepping (sleirsgoevy method) — the handlers
   are XOM, but their offsets/semantics are recoverable.

---

## 6. Evidence table (all offsets = `kdata_1360.bin`, VA = `0xffffffffd0930000 + off`)

| string | file off | VA |
|---|---|---|
| `no free mbox` / `psp_mbox_send_sysmail` | `0x5d5d45` / `0x5d5d61` | `…d0f05d45` / `…d0f05d61` |
| `STATE (SBL->x86, #0-14,#15(Pol))` | `0x5d5d86` | `…d0f05d86` |
| `Mbox Is Busy(…). Send(Cmd 0x%X)` | `0x5ac7f1` | `…d0edc7f1` |
| `make_mbox: too large id` | `0x5c4c54` | `…d0ef4c54` |
| `PSP doesn't reply message(…) (Cmd 0x%X)` | `0x631176` | `…d0f61176` |
| `psp_mbox_encode_kernel_text` | `0x665952` | `…d0f95952` |
| `send_encode_kernel_text_cmd` | `0x6d82e3` | `…d10082e3` |
| `psp_mbox_map_tmr` | `0x66fad9` | `…d0f9fad9` |
| `PSP private region violation` | `0x665147` | `…d0f95147` |
| `sceSblTmrMap(%d, %lx, %lx)=%d` / `sceSblTmrUnmap(%d)=%d` | `0x69d4c1` / `0x69d4e0` | `…d0fcd4c1` / `…d0fcd4e0` |
| `SecReg(map TMR) failed` | `0x699b66` | `…d0fc9b66` |
| `SecReg(MP1 Dump TMR) failed` | `0x622d1b` | `…d0f52d1b` |
| `hv_restore_pt_tmr[%d] failed` | `0x5cb0ce` | `…d0efb0ce` |
| `hv_unmap_pt_tmr(%d) failed` | `0x5d42d1` | `…d0f042d1` |
| `tmr0/tmr6/tmr7` · `tmrDumpReg` · `tmrdump` | `0x5aeb7d` · `0x683fb5` · `0x5beeed` | — |
| `mp4_to_deci5s_write_mbox` | `0x63a3ac` | `…d0f6a3ac` |
| `deci5s_main_intdev_sdbgp_context_handle_trace_hv_save` | `0x5c35ae` | `…d0ef35ae` |
| `deci5s_main_intdev_sdbgp_context_handle_trace_hv_status` | `0x60ae9b` | `…d0f3ae9b` |
| `kA53C_MboxCmdHalt/Reset/Start` | `0x6643ae` / `0x66e711` / `0x6ec69a` | — |
| `mp1_bapm_logger_ioctl` / `MP1_IOCTL_GET_CLK` | `0x5b9caa` / `0x5e7420` | — |
| `sce_svmd.c` / `svmd mtx` / `svmd_stop_handler` | `0x5e0f0a` / `0x63dc78` / `0x648166` | — |

---

## 7. Open items / next steps

1. **Resolve the sandbox-openability of `/dev/mp4/dump` + `/dev/a53mm`** (no KEX) — this flips
   Plans A/B from "chained stage" to "entry point".
2. **RE the `trace_hv_*` command encoding** by single-stepping the `deci5s_main_intdev_sdbgp_*`
   handlers (XOM — recover offsets/semantics, not bytes).
3. **Pin `sceSblTmrMap`'s syscall/ioctl number** so Plan C can be driven without an in-kernel
   function pointer (check the SBL service syscall table / `sceSbl*` ioctls in `devpfs.ctl`).
4. **Dump the MP1 SMU mailbox** (`mp1bapmlog` / `MP1_C2PMSG_*`) — the `SecReg(MP1 Dump TMR)`
   register dump is the cheapest read of the live TMR config.
