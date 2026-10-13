# HV_WRAPPERS.md — hypercall wrapper string/xref analysis of kdata_1360.bin

**Goal:** locate the kernel's `hv_*` hypervisor-call wrappers (the functions that issue AMD SVM
`vmmcall`) so a ring-0 payload can either call them directly or know the exact hypercall-number
argument each one passes.

**Sources (all offline):** `kdata_1360.bin` (15 MB kernel `.data`, base VA `0xffffffffd0930000`,
file offset → VA = base + offset). KASLR slide = **+0x4FA60000**; canonical text = slid − 0x4FA60000.
psdevwiki `Hypervisor` page hypercall table (as already captured in `HYPERCALL_PROBE.md`).

**Bottom line (read this first):**

- The hypercall **numbers** are recovered (psdevwiki) and mapped to the wrapper names below.
- The named `hv_*` wrapper **function addresses are NOT recoverable from this dump** — see §3. They
  live in XOM text and are referenced from code only by RIP-relative addressing; there is **zero
  data xref** to any `hv_*` format string or name, and the kernel symbol table is absent (Sony
  stripped it). This is a verified negative, not a gap to re-chase.
- The **one HV-interface function address that IS resolvable** is the deci5s/sdbgp debug-context
  `VMMCALL` command handler (§4) — a real, in-text function that issues `vmmcall`.
- A payload that needs a specific hypercall is better off issuing `vmmcall` **directly** (single
  instruction, ABI in `HYPERCALL_PROBE.md` §2) with the number from §2 below, rather than hunting a
  wrapper. To locate a *wrapper* at runtime, scan slid text for `0F 01 D9` preceded by `mov eax, imm32`
  (the hypercall-number load) — §5.

---

## 1. String inventory — every `hv_`/`vmmcall`/hypercall-name string (VA + file offset)

Base VA `0xffffffffd0930000`; **VA = 0xffffffffd0930000 + file_offset**. All offsets are hex file
offsets into `kdata_1360.bin`.

### 1.1 Hypercall-wrapper error/format strings (the real `hv_*` wrappers)

| file off | VA                  | string                                                | wrapper                     |
|----------|---------------------|-------------------------------------------------------|-----------------------------|
| 0x5d42df | 0xffffffffd0f042df  | `hv_unmap_pt_tmr(%d) failed: %d`                      | hv_unmap_pt_tmr (UNMAP_PT_TMR)   |
| 0x5fc796 | 0xffffffffd0f2c796  | `hv_unmap_pt_tmr failed: %d`                          | hv_unmap_pt_tmr (UNMAP_PT_TMR)   |
| 0x6a6a0d | 0xffffffffd0fd6a0d  | `hv_unmap_pt_tmr() failed0x%x`                        | hv_unmap_pt_tmr (UNMAP_PT_TMR)   |
| 0x5cb0ce | 0xffffffffd0efb0ce  | `hv_restore_pt_tmr[%d] failed: %d`                    | hv_restore_pt_tmr (RESTORE_PT_TMR) |
| 0x5cb9af | 0xffffffffd0efb9af  | `hv_restore_pt_tmr() failed0x%x`                      | hv_restore_pt_tmr (RESTORE_PT_TMR) |
| 0x6b8ba7 | 0xffffffffd0fe8ba7  | `hv_restore_pt_tmr failed: %d`                        | hv_restore_pt_tmr (RESTORE_PT_TMR) |
| 0x6ed961 | 0xffffffffd101d961  | `hv_restore_pt_tmr(%d) failed: %d`                    | hv_restore_pt_tmr (RESTORE_PT_TMR) |
| 0x606e22 | 0xffffffffd0f36e22  | `hv_get_tmr_violation_error() error %d`               | hv_get_tmr_violation_error (GET_TMR_VIOLATION_ERROR) |
| 0x65236e | 0xffffffffd0f8236e  | `hv_iommu_set_guest_buffers completion error:%d`      | hv_iommu_set_guest_buffers (IOMMU_SET_GUEST_BUFFERS) |
| 0x609adb | 0xffffffffd0f39adb  | `hv_iommu_enable_device error:%d 0x%x`                | hv_iommu_enable_device (IOMMU_ENABLE_DEVICE) |
| 0x691b6d | 0xffffffffd0fc1b6d  | `hv_iommu_enable_device completion error:%d 0x%x`     | hv_iommu_enable_device (IOMMU_ENABLE_DEVICE) |
| 0x5e09de | 0xffffffffd0f109de  | `hv_iommu_bind_pasid completion error:%d 0x%x %d 0x%lx` | hv_iommu_bind_pasid (IOMMU_BIND_PASID) |
| 0x6b0dd2 | 0xffffffffd0fe0dd2  | `hv_iommu_bind_pasid error:%d 0x%x %d 0x%lx`         | hv_iommu_bind_pasid (IOMMU_BIND_PASID) |
| 0x667a58 | 0xffffffffd0f97a58  | `hv_iommu_unbind_pasid error:%d 0x%x %d`              | hv_iommu_unbind_pasid (IOMMU_UNBIND_PASID) |
| 0x6b0dfe | 0xffffffffd0fe0dfe  | `hv_iommu_unbind_pasid completion error:%d 0x%x %d`   | hv_iommu_unbind_pasid (IOMMU_UNBIND_PASID) |
| 0x6d7452 | 0xffffffffd1007452  | `hv_iommu_check_evlog_regs` (bare name, no fmt)       | hv_iommu_check_evlog_regs (IOMMU_CHECK_EVLOG_REGS) |
| 0x6709a6 | 0xffffffffd0fa09a6  | `hv_startup_mp(%d) failed!`                           | hv_startup_mp (STARTUP_MP)   |
| 0x628ba4 | 0xffffffffd0f58ba4  | `%s hv_n_devices:%d`                                  | hv_n_devices (helper; no known hypercall #) |

(Some of the above strings are preceded in memory by a `%s`-or-`ERROR:` prefix that is a *separate*
adjacent string, e.g. `%s: ` before `hv_get_tmr_violation_error()`, `ERROR: %s(%d) ` before the
`hv_unmap_pt_tmr`/`hv_restore_pt_tmr` formats, `[core spm] ` before the `...() failed0x%x` ones.
Those prefixes are themselves xref'd by their callers, not by the hv wrappers.)

### 1.2 NOT hypercall wrappers — do not confuse

| file off | VA                  | string      | what it actually is                                   |
|----------|---------------------|-------------|-------------------------------------------------------|
| 0x66aa68 | 0xffffffffd0f9aa68  | `vmmcall`   | x86 **disassembler mnemonic** (FreeBSD `db_disasm.c`/DTrace `dis_tables.c` instruction table — sits between `reboot,` and `cmpxchg8b`, `fyl2xp1`, `invept`, `verw`, `sfence`…) |
| 0x6c72da | 0xffffffffd0ff72da  | `VMMCALL`   | **deci5s/sdbgp debug-context command name** (see §4)   |
| 0x66c1e5 | 0xffffffffd0f9c1e5  | `hv_vendor` | substring coincidence inside an unrelated device-name cluster (`camera`, `hmd`, …) |
| 0xa4a438 | 0xffffffffd137a438  | `hv_`       | 3-byte coincidence inside a non-ASCII (encrypted/opaque) blob |

The canonical ALL-CAPS psdevwiki hypercall names (`GET_MESSAGE_CONF`, `IOMMU_READ_DEVICE_TABLE`,
`GET_TMR_VIOLATION_ERROR`, …) are **NOT present as strings anywhere in the dump** — they live in
the HV (separate component) or in XOM `.rodata`. Only the lowercase wrapper-function substrings
(`hv_iommu_…`, `hv_get_tmr_…`) are present.

### 1.3 Correction to a prior note

`HYPERCALL_PROBE.md` §1 claims a `hv_map_pt_tmr` wrapper string exists. **It does not.** A byte-level
search for `hv_map` returns **0 hits**; every `map_pt_tmr` hit is the `map` inside `unmap`
(`hv_unmap_pt_tmr`). So `MAP_PT_TMR` has no error-format wrapper string in this dump (its wrapper is
either unnamed here or has no debug string). `hv_unmap_pt_tmr`, `hv_restore_pt_tmr`, and
`hv_get_tmr_violation_error` are the only TMR wrappers with strings.

---

## 2. Hypercall number → wrapper table (the deliverable)

psdevwiki `Hypervisor` page (as captured in `HYPERCALL_PROBE.md` §1) gives numbers `0x0`–`0x10`;
the TMR `*_PT_TMR` hypercalls extend past `0x10` with **numbers not determinable offline** (marked
`>=0x11`). `XOM` in the offset column = wrapper is in XOM text, address not present in the dump (§3).

| hypercall name            | #     | wrapper (from string)          | canonical text offset | string VA            | string file off |
|---------------------------|-------|--------------------------------|------------------------|----------------------|-----------------|
| GET_MESSAGE_CONF          | 0x0   | — (no wrapper string)          | XOM                    | —                    | —               |
| GET_MESSAGE_COUNT         | 0x1   | —                              | XOM                    | —                    | —               |
| START_LOADING_SELF         | 0x2   | —                              | XOM                    | —                    | —               |
| FINISH_LOADING_SELF        | 0x3   | —                              | XOM                    | —                    | —               |
| SET_CPUID_PS4             | 0x4   | —                              | XOM                    | —                    | —               |
| SET_CPUID_PPR             | 0x5   | —                              | XOM                    | —                    | —               |
| IOMMU_SET_GUEST_BUFFERS    | 0x6   | hv_iommu_set_guest_buffers     | XOM                    | 0xffffffffd0f8236e   | 0x65236e        |
| IOMMU_ENABLE_DEVICE        | 0x7   | hv_iommu_enable_device         | XOM                    | 0xffffffffd0f39adb   | 0x609adb        |
| IOMMU_BIND_PASID           | 0x8   | hv_iommu_bind_pasid            | XOM                    | 0xffffffffd0fe0dd2   | 0x6b0dd2        |
| IOMMU_UNBIND_PASID         | 0x9   | hv_iommu_unbind_pasid          | XOM                    | 0xffffffffd0f97a58   | 0x667a58        |
| IOMMU_CHECK_CMD_COMPLETION | 0xa   | —                              | XOM                    | —                    | —               |
| IOMMU_CHECK_EVLOG_REGS     | 0xb   | hv_iommu_check_evlog_regs      | XOM                    | 0xffffffffd1007452   | 0x6d7452        |
| IOMMU_READ_DEVICE_TABLE    | 0xc   | —                              | XOM                    | —                    | —               |
| GET_TMR_VIOLATION_ERROR    | 0xd   | hv_get_tmr_violation_error     | XOM                    | 0xffffffffd0f36e22   | 0x606e22        |
| VMCLOSURE_INVOCATION       | 0xe   | —                              | XOM                    | —                    | —               |
| STARTUP_MP                 | 0xf   | hv_startup_mp                  | XOM                    | 0xffffffffd0fa09a6   | 0x6709a6        |
| DISABLE_STARTUP_MP         | 0x10  | —                              | XOM                    | —                    | —               |
| MAP_PT_TMR                 | >=0x11| — (no wrapper string, §1.3)    | XOM                    | —                    | —               |
| UNMAP_PT_TMR               | >=0x11| hv_unmap_pt_tmr                | XOM                    | 0xffffffffd0f042df   | 0x5d42df        |
| RESTORE_PT_TMR             | >=0x11| hv_restore_pt_tmr              | XOM                    | 0xffffffffd0efb0ce   | 0x5cb0ce        |

Note: `IOMMU_READ_DEVICE_TABLE` (0xc) has **no wrapper string** in the dump either — the `## Device
Table …` / `raw dte[%d]` debug formats exist (§3 of `HYPERCALL_PROBE.md`) but no `hv_iommu_read_device_table`
named string. Its wrapper is either named differently or inlined into the DTE-dump path.

---

## 3. Why the wrapper addresses are NOT in this dump (verified)

For each `hv_*` string in §1.1 I scanned the **entire 15 MB dump for 8-byte pointers** equal to the
string's VA (exact + small window) and for the bare names (`hv_iommu_check_evlog_regs`,
`SceSvmd`, `svmd`, `svmd_start/stop_handler`, `sce_svmd.c` path). **Result: zero xrefs.**

- The wrappers reference their format strings via **RIP-relative `lea`** inside XOM text. XOM text is
  not in this dump, so the displacement (and hence the wrapper address) is invisible.
- The kernel **symbol table is absent** (bare function names like `hv_iommu_check_evlog_regs` sit in
  `.rodata` as debug/tag strings, not in a packed `strtab`; the neighbouring strings are format
  strings like `Replying`/`Parameter port…`, proving it is not a symtab).
- The `SceSvmd` module (`svmd`, `svmd_start_handler`, `svmd_stop_handler`,
  `svmd_check_workaround_title`, mutex `svmd mtx`, `__FILE__`
  `W:/Build/J03950001/sys/freebsd/sys/kern/sce_svmd.c`) is likewise not xref'd from `.data` — the
  module struct / handler pointers live outside the dumped range.

Conclusion: **wrapper canonical offsets = unknown from this dump.** Do not fabricate them. The two
legitimate paths to call targets are §4 (resolved deci5s handler) and §5 (runtime scan / raw vmmcall).

---

## 4. The ONE resolvable HV-interface function: deci5s/sdbgp `VMMCALL` command handler

`kdata_1360.bin` contains the **deci5s / sdbgp debug-context command dispatch table** at `.data`
`0xffffffffd16e4d00` (file off `0xdb4d00`), 0x20-byte entries `{name_ptr @+0, 0 @+8, 0 @+0x10,
handler_ptr @+0x18}`. It maps named debug-command strings to handler function pointers **in slid
text** (these are the `0xffffffffcfed…` pointers the `.data` segment stores). Selected rows:

| name               | handler (slid)       | handler (canonical) | notes                              |
|--------------------|----------------------|---------------------|------------------------------------|
| WRITE_CR           | 0xffffffffcfeced68   | 0xffffffff8046ed68  |                                    |
| **VMMCALL**        | **0xffffffffcfeced70** | **0xffffffff8046ed70** | deci5s debug cmd that issues a `vmmcall` |
| RDTSCP             | 0xffffffffcfeced78   | 0xffffffff8046ed78  |                                    |
| GET_APPLICATION_INFO | 0xffffffffcfeced80 | 0xffffffff8046ed80  |                                    |
| … (GET_* / SET_REG / DDB_* / TRACE_*) | … | … | 58 total commands                |
| TRACE_HV_CREATE    | 0xffffffffcfeceeb0   | 0xffffffff8046eeb0  |                                    |
| TRACE_HV_DELETE    | 0xffffffffcfeceeb8   | 0xffffffff8046eeb8  |                                    |
| TRACE_HV_START     | 0xffffffffcfeceec0   | 0xffffffff8046eec0  |                                    |
| TRACE_HV_STOP      | 0xffffffffcfeceec8   | 0xffffffff8046eec8  |                                    |
| TRACE_HV_SAVE      | 0xffffffffcfeceed0   | 0xffffffff8046eed0  |                                    |
| TRACE_HV_STATUS    | 0xffffffffcfeceed8   | 0xffffffff8046eed8  |                                    |

The handler pointers are **8-byte-adjacent** (`…ec68, ec70, ec78, …`): each 8-byte slot in slid text
is a short stub / jump-table entry, not a full function body. The `VMMCALL` entry at canonical
`0xffffffff8046ed70` (slid `0xffffffffcfeced70`) is a real vmmcall-issuing site reachable through
the kernel (this is the table cragson's `a53-code-exec` patches via `SDBGP_WRITE_MEMORY`). A ring-0
payload that already has kernel R/W can read the slid pointer at `0xffffffffd16e4d20+0x18` to
resolve the live address at runtime (KASLR-independent).

---

## 5. Runtime method to locate a specific `hv_*` wrapper (XOM text)

The wrappers are small: load hypercall number into RAX, set RBX/RCX/RDX, `vmmcall`, check RAX. In
slid text (`0xffffffffcf000000…`, i.e. canonical `0xffffffff80200000…` + slide) each wrapper's
`vmmcall` is preceded by an immediate load:

```
B8 <imm32>          ; mov eax, <hypercall_number>       (or: 41 B8 / 48 C7 C0 imm32)
... arg setup ...
0F 01 D9            ; vmmcall
```

A payload with the ability to read slid text (single-step, or NPT/DMAP read of the text's physical
pages — not `kernel_copyout`, which returns −1 on XOM) scans for `0F 01 D9` and back-references the
preceding `B8 imm32` to key each wrapper by hypercall number. This recovers every wrapper address
at runtime and cross-checks §2. **Simpler:** a ring-0 code-cave stub can issue `vmmcall` directly
(`RAX=nr, RBX/RCX/RDX=args`, ABI in `HYPERCALL_PROBE.md` §2) with no wrapper at all — the wrapper
is only needed if you want the kernel's own arg-formatting/error-checking.

---

## Change log
- 2026-10-05: created. Full `hv_`/`vmmcall` string inventory with VA+offset; mapped hypercall
  numbers (psdevwiki) to wrapper names; proved the named `hv_*` wrapper addresses are absent from
  the dump (zero xrefs, no symtab); extracted the deci5s/sdbgp dispatch table incl. the `VMMCALL`
  command handler (slid + canonical); corrected the false `hv_map_pt_tmr` claim.
