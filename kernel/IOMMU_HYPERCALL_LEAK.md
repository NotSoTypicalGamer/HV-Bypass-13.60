# IOMMU_HYPERCALL_LEAK.md — do the hv_iommu_* hypercalls leak the HV physical base?

**Date:** 2026-10-06
**Scope:** pin the exact input/output of the 8.00+ IOMMU hypercalls (0x6–0xc) and answer the
specific question: *does `IOMMU_READ_DEVICE_TABLE` (0xc) or `IOMMU_CHECK_EVLOG_REGS` (0xb) — or any
other `hv_iommu_*` call — RETURN HV-owned data (a host-PA into the HV carve-out) that would leak the
8.00+ HV physical base deterministically?*
**Companion docs (do not re-derive):** `HV_WRAPPERS.md` (wrapper-string inventory + hypercall-number
map), `KERNEL_HYPERCALLS.md` (vmmcall ABI + the "wrappers are in XOM, unrecoverable offline" proof),
`HYPERCALL_PROBE.md` (ring-0 probe design), `KERNEL_AMDVI.md` / `IOMMU_CMDBUF.md` / `IOMMU_MMIO_PA.md`
(guest iommudrv buffer analysis), `HV_LAYOUT.md` §4 + `ROOT0_NPT_TRIGGER.md` §5.5 (the raw-MMIO
DTRB/CBRB path), `amdvi_src/{amdvi_priv.h,amdvi_hw.c,amdviiommu.c,ivrs_drv.c}` (FreeBSD layout oracle).

---

## 0. Verdict (TL;DR)

**No. The IOMMU hypercalls do not provide a deterministic HV-base leak.**

- They are a **para-virtualized IOMMU interface**: the guest allocates its *own* command buffer /
  device table / event log and registers them with the HV via `IOMMU_SET_GUEST_BUFFERS` (0x6). Every
  subsequent call (0x7–0xc) operates on, and returns, **guest-visible IOMMU state** — status codes,
  event-log head/tail indices, and the guest's *own* device-table entries (whose page-table root is a
  **guest** physical address). None of them returns the HV's device-table base (DTRB), command-buffer
  base (CBRB), or event-log registers, which are the values that actually live in the HV carve-out.
- The HV-owned DTRB/CBRB/EVNTB are **hardware MMIO registers**, not hypercall outputs. The one
  deterministic path that reads them (raw MMIO at `0xffffec8c01130000 + N*0x4000`, offsets `+0x00` /
  `+0x08` / `+0x10`) is already documented in `HV_LAYOUT.md` §4 and `ROOT0_NPT_TRIGGER.md` §5.5 — and
  it has its own known caveat (all-zero read on a JB'd boot, §6 below), which is unrelated to the
  hypercalls.
- **One residual, low-probability exception** is worth a single probe (§5): if `IOMMU_READ_DEVICE_TABLE`
  returns the HV's *shadow* (host-PA) DTE rather than the guest's, and the guest can enumerate a
  device-id that maps to an HV-owned device, the returned DTE's page-table root could be an HV PA.
  No evidence supports this; treat it as the "one probe to close it" case, not a plan.

---

## 1. Correction to the task premise (read first)

The task lists `hv_iommu_set_guest_buffers VA 0xffffffffd0f8236e` etc. as "wrapper VAs". **Those are
the `.rodata` format-string addresses, not the wrapper function addresses.** From `HV_WRAPPERS.md`:

| string | VA | file off | role |
|---|---|---|---|
| `hv_iommu_set_guest_buffers completion error:%d` | 0xffffffffd0f8236e | 0x65236e | **format string** |
| `hv_iommu_enable_device error:%d 0x%x` | 0xffffffffd0f39adb | 0x609adb | **format string** |
| `hv_iommu_bind_pasid completion error:%d 0x%x %d 0x%lx` | 0xffffffffd0fe0dd2 | 0x6b0dd2 | **format string** |
| `hv_iommu_unbind_pasid error:%d 0x%x %d` | 0xffffffffd0f97a58 | 0x667a58 | **format string** |
| `hv_iommu_check_evlog_regs` (bare tag) | 0xffffffffd1007452 | 0x6d7452 | **tag string** |
| `hv_get_tmr_violation_error() error %d` | 0xffffffffd0f36e22 | 0x606e22 | **format string** |

The `hv_*` **wrapper functions** are compiled from `sys/freebsd/sys/kern/sce_svmd.c` into the **core
kernel XOM `.text`** (`0xffffffff80xxxxxx`). `HV_WRAPPERS.md` §3 and `KERNEL_HYPERCALLS.md` §1 proved
their addresses are **not recoverable from any dump** (zero data xrefs, no symbol table, no
`vmmcall`/`mov eax,imm` sites in the captures). Do not treat the string VAs as call targets.

---

## 2. vmmcall ABI (confirmed)

From `ps5-linux-loader shellcode_kernel/boot_linux.c` (the authoritative in-the-wild consumer),
recaptured in `KERNEL_HYPERCALLS.md` §2:

```c
static inline uint64_t vmmcall(uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2)
    __asm__ volatile("vmmcall" : "=a"(ret)
                     : "a"(nr), "b"(a0), "c"(a1), "d"(a2) : "memory");
```

| register | role |
|---|---|
| **RAX** | hypercall number (the `VMMCALL_HV_*` index) |
| **RBX** | arg0 |
| **RCX** | arg1 |
| **RDX** | arg2 |
| RSI/RDI/R8–R15 | args 3+ (whether the HV reads them is **unverified**) |
| **RAX (ret)** | status/error code |

Opcode `0F 01 D9`, **CPL0-only** (user-mode `vmmcall` → #UD/SIGILL), VMEXIT code `0x81`
(`VMEXIT_VMMCALL`). The HV dispatches by indexing a jump table with RAX. All addresses the guest
passes are **guest-physical addresses (GPAs)** — the guest cannot even name host PAs (the NPT hides
them), so every "buffer PA" argument and every DTE page-table root returned is a GPA.

---

## 3. Per-hypercall input/output (verified vs inferred)

Hypercall numbers and names are **verified** (psdevwiki `Hypervisor` page + `sce_svmd.c` wrapper
strings, `HV_WRAPPERS.md` §2). Argument *semantics* are **inferred** from (a) the wrapper format
strings, (b) the FreeBSD `amdvi` source as a layout oracle (`amdvi_priv.h`, `amdvi_hw.c`), and (c) the
`kdata_1360.bin` DTE/debug strings (`HYPERCALL_PROBE.md` §3). Nothing public documents the exact
semantics; the HV binary is not available to confirm.

| # | name | wrapper string | input (inferred) | output (inferred) | leaks HV data? |
|---|---|---|---|---|---|
| 0x6 | IOMMU_SET_GUEST_BUFFERS | `…set_guest_buffers completion error:%d` | RBX/RCX/RDX = **GPAs of the guest's command buffer, device table, event log** (the `"iommu cmd"` / `"iommu dt"` / `"iommu evt"` buffer names) | status (completion) | **No** — registers guest buffers, returns status only |
| 0x7 | IOMMU_ENABLE_DEVICE | `…enable_device error:%d 0x%x` | RBX = **device id (BSF)** = `bus<<8\|dev<<3\|func` (the `0x%x`) | status + device id echo | **No** |
| 0x8 | IOMMU_BIND_PASID | `…bind_pasid completion error:%d 0x%x %d 0x%lx` | RBX = **device id** (`0x%x`), RCX = **PASID** (`%d`), RDX = **guest page-table / GCR3 root GPA** (`0x%lx`) | status | **No** — the root is a *guest* GPA |
| 0x9 | IOMMU_UNBIND_PASID | `…unbind_pasid error:%d 0x%x %d` | RBX = **device id**, RCX = **PASID** | status | **No** |
| 0xa | IOMMU_CHECK_CMD_COMPLETION | — (no string) | (device id? / none) | completion status (head==tail / count) | **No** |
| **0xb** | **IOMMU_CHECK_EVLOG_REGS** | `hv_iommu_check_evlog_regs` (bare) | (unit index? / none) | **event-log head/tail/status register *values*** (19-bit indices + flags) | **No — indices, not a PA** |
| **0xc** | **IOMMU_READ_DEVICE_TABLE** | — (inlined into DTE dump) | RBX = **device id (BSF)**, RCX = **out buffer (GPA)** (hypothesis A/B/C in `HYPERCALL_PROBE.md` §3.1) | 256-bit (32-byte) **DTE** for that device id | **No — the DTE's page-table root is a *guest* GPA** (§4) |

Key reading of the format strings:

- `bind_pasid`'s 3-argument signature (`0x%x %d 0x%lx` = device id, PASID, base) is the AMD-Vi
  **guest-translation (GCR3) bind** — the guest hands the HV a *guest* page-table root for a PASID.
- `unbind_pasid`'s 2-argument signature (`0x%x %d`) is the mirror.
- `enable_device` takes a single device id and echoes it back in the error path.
- `check_evlog_regs` has **no format string** — it returns simple values the caller uses directly
  (head/tail/status), consistent with a register read-back, not a PA.

---

## 4. Why 0xc and 0xb do NOT return HV-owned data

The decisive structural fact: **the guest allocates the device table, command buffer, and event log
itself and hands them to the HV** (`IOMMU_SET_GUEST_BUFFERS`, the `"iommu dt"`/`"iommu cmd"`/`"iommu evt"`
strings). This is the same shape as a hypervisor para-virtualized IOMMU (cf. the Hyper-V paravirtual
IOMMU driver): the guest owns stage-1 translation state, the HV consumes it. Consequences:

1. **`IOMMU_READ_DEVICE_TABLE` (0xc) returns the guest's DTE.** The DTE (`struct amdvi_dte`,
   `amdvi_priv.h`, 32 bytes) carries a `pt_base` field (bits [51:12] of the page-table root). In the
   FreeBSD `amdvi` model the guest sets `pt_base = vtophys(domain->ptp) >> 12` (`amdvi_hw.c:
   amdvi_set_dte`) — a **guest** PA into the guest's own IOMMU page-table tree. The decode strings
   (`'domain_id: %04x'`, `'    pml4:0x%016lx'`, `' raw dte[%d]:0x%08x'`) confirm the read-back is the
   guest's table, decoded in guest terms. Even if the HV *shadows* the DTE and re-translates `pt_base`
   through the NPT to a host PA before programming the real hardware, the read-back interface returns
   the **guest's** view — and a guest page-table root lives in guest RAM, **below** the HV carve-out,
   so it is not an HV-base leak either way.
2. **`IOMMU_CHECK_EVLOG_REGS` (0xb) returns register *values*, not addresses.** The event-log registers
   are the 19-bit head/tail pointers and the status word (`struct amdvi_ctrl` offsets `0x2010/0x2018/
   0x2020`, `amdvi_priv.h`). These are indices into the guest's event-log buffer, in the range
   `[0, 1<<len)`. They are **not** the event-log *base* (EVNTB, MMIO `+0x10`), which is the field that
   holds a PA. The hypercall name "check … regs" + the absence of any format string (so nothing
   PA-shaped is ever logged) matches a head/tail/status read-back.
3. **`IOMMU_CHECK_CMD_COMPLETION` (0xa) returns a boolean/count**, not a PA.
4. The **HV-owned** device-table base / command-buffer base / event-log base are the **hardware MMIO
   registers** DTRB (`+0x00`), CBRB (`+0x08`), EVNTB (`+0x10`) — the exact three values that *do* land
   in the HV carve-out per `HV_LAYOUT.md` §4. Those are **not exposed through any hypercall's return
   path**; they are only reachable by reading the MMIO window directly (§6). The hypercall and MMIO
   surfaces are disjoint: the guest drives IOMMU state via hypercalls, and the raw MMIO registers are
   HV-programmed and (in the JB'd-boot observation) not mirrored back to the guest.

**Net:** by construction, every value an `hv_iommu_*` call returns is guest-visible IOMMU state
(status, indices, guest DTEs with guest-PA roots). There is no register/field in the return path that
carries an HV-carve-out pointer.

---

## 5. The one residual possibility (speculative, one probe to close it)

The above assumes `IOMMU_READ_DEVICE_TABLE` reads the **guest's** table (hypothesis A/B) or the
pre-registered guest buffer (hypothesis C). The only scenario in which it leaks HV data is if the HV
instead returns its **own shadow DTE** — i.e. the entry as programmed into the real hardware, with
`pt_base` already translated to a **host** PA — **and** the guest can name a device id whose DTE the HV
itself owns (e.g. a TMR/secure device whose IOMMU page table lives in the carve-out). Then the returned
`pt_base`/`pml4` field would be an HV PA.

- **Probability: low.** The interface is named around *guest* buffers, and the decode strings dump the
  guest's table. No evidence the HV leaks its shadow table.
- **Cheap test (on the 7.61 workhorse, klog captured):** issue `vmmcall(0xc, dev_id, out_gpa, 0)` over
  a *wide* device-id sweep (0x0–0xFFFF), log the 8 dwords of each DTE, and look for a `pt_base` (q1/q2
  low 52 bits) that is 4-KiB-aligned and falls in `0x60000000..0x70000000` (the HV carve-out). Also try
  the pre-registered-buffer form (`vmmcall(0x6, cmd_gpa, dt_gpa, evt_gpa)` first, then
  `vmmcall(0xc, dev_id, 0, 0)`) and read `dt_gpa` back. One sweep settles it; do **not** build a plan
  on it.
- Even on success this only yields the HV's *IOMMU page-table root* (if it is in the carve-out), which
  then anchors the base the same way DTRB/CBRB would.

---

## 6. The actual deterministic path (already on record, not the hypercalls)

For completeness — the hypercall lane is a dead end for the base; the real lane is:

- **Raw MMIO read** of DTRB (`+0x00`) / CBRB (`+0x08`) / EVNTB (`+0x10`) at VA
  `0xffffec8c01130000 + N*0x4000` (N=0..7), single 8-byte `kernel_copyout` reads (`HV_LAYOUT.md` §4,
  `ROOT0_NPT_TRIGGER.md` §5.5). These registers hold the host-PAs the HV programmed and are asserted to
  land inside the carve-out (`0x60000000..0x70000000`).
- **Known caveat:** on a JB'd boot the MMIO window read **all-zero** — because the guest `iommudrv`
  drives the IOMMU via `hv_iommu_*` hypercalls rather than raw MMIO, the window may not be live. This
  is *why* the hypercall question was raised, but the two surfaces are separate: the hypercalls being
  the guest's interface does **not** imply they return the HV's MMIO register contents.

---

## 7. Reachability: does the kernel's own iommudrv call these?

**Yes — confirmed at the string level, but the wrapper addresses are not resolvable offline.**

- The `sce_svmd.c` wrapper strings (`hv_iommu_set_guest_buffers`, `hv_iommu_enable_device`,
  `hv_iommu_bind_pasid`, `hv_iommu_unbind_pasid`, `hv_iommu_check_evlog_regs`) are present in the
  kernel `.rodata`, i.e. the kernel's own `iommudrv` (Sony's port of FreeBSD `amdvi`) *does* invoke
  these hypercalls at runtime (`HV_WRAPPERS.md` §1.1; `ROOT0_NPT_TRIGGER.md` §5.5 states the guest
  drives the IOMMU via `hv_iommu_*` hypercalls, not raw MMIO).
- **But the wrapper functions live in core XOM `.text`** and their addresses are a verified negative in
  every dump (`KERNEL_HYPERCALLS.md` §3, `HV_WRAPPERS.md` §3). A payload therefore cannot cheaply "call
  the existing wrapper" from the dumps.
- **What a payload should actually do** (unchanged from `KERNEL_HYPERCALLS.md` §7): issue `vmmcall`
  **directly** from a ring-0 code cave — `RAX=nr, RBX/RCX/RDX=args` — with the numbers from §3. To
  locate a wrapper at runtime instead, scan slid text for `0F 01 D9` preceded by `B8 imm32`
  (`HV_WRAPPERS.md` §5). Either way, the hypercall numbers are known and the calls are reachable; the
  blocker is the *returned data is guest-visible*, not that the calls are unreachable.

---

## 8. Conclusion

| question | answer |
|---|---|
| Do any `hv_iommu_*` hypercalls return HV-owned data? | **No** (verified-by-construction; §4) |
| Does `IOMMU_READ_DEVICE_TABLE` return the HV's device-table base? | **No** — returns the guest's DTE (guest-PA root) |
| Does `IOMMU_CHECK_EVLOG_REGS` return the HV's event-log base/registers? | **No** — returns head/tail/status indices |
| Is this a deterministic HV-base leak? | **No.** The deterministic path is the raw-MMIO DTRB/CBRB read, a separate surface |
| Are the hypercalls reachable from a payload? | **Yes** — direct `vmmcall` from ring-0 (numbers known); wrappers in XOM, unrecoverable offline |
| Residual worth one probe? | Only the shadow-DTE / HV-owned-device-id case in §5 — low probability |

---

## 9. Sources

- `HV_WRAPPERS.md` — wrapper-string inventory, hypercall-number map, XOM-address negative.
- `KERNEL_HYPERCALLS.md` — vmmcall ABI (boot_linux.c), no-real-vmmcall proof.
- `HYPERCALL_PROBE.md` — DTE/TMR debug strings, ring-0 probe design, VA-vs-GPA open question.
- `KERNEL_AMDVI.md`, `IOMMU_CMDBUF.md`, `IOMMU_MMIO_PA.md` — guest iommudrv buffer/MMIO analysis;
  DMAP base `0xffffec8c00000000`, MMIO PA `0x1130000`, cmd/evt KVA `0xffffffffd31e4000/6000`.
- `HV_LAYOUT.md` §4, `ROOT0_NPT_TRIGGER.md` §5.5/§6.4 — the raw-MMIO DTRB/CBRB base-leak path and the
  all-zero-on-JB'd-boot caveat.
- `amdvi_src/amdvi_priv.h` (`struct amdvi_dte`, `struct amdvi_ctrl` register offsets) and
  `amdvi_src/amdvi_hw.c` (`amdvi_init_cmd/event/dte`, `amdvi_set_dte`) — FreeBSD AMD-Vi layout oracle.
- Web: psdevwiki `Hypervisor` page (hypercall table 0x0–0x10; "IOMMU moved to the Hypervisor"),
  PS5Dev `ps5-wiki`/`Byepervisor` (jump-table class ≤2.70 only; IOMMU mediated by HV). No public source
  documents the hypercall argument semantics — flagged as inferred in §3.

## Change log
- 2026-10-06: created. Corrected the string-VA-vs-wrapper-VA confusion; tabulated the per-hypercall
  I/O (verified numbers, inferred semantics) from the wrapper format strings + FreeBSD `amdvi` oracle;
  established that the IOMMU hypercalls are a guest-buffer (para-virtualized) interface whose returns
  are guest-visible state (status/indices/guest-PA DTEs), so they do not leak the HV base; separated the
  hypercall surface from the raw-MMIO DTRB/CBRB surface (the actual deterministic path); documented the
  kernel-side reachability and the one residual shadow-DTE probe.
