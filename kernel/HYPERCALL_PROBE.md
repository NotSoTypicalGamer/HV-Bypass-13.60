# HYPERCALL_PROBE — vmmcall READ primitive for the IOMMU device table + TMR state

**Scope:** design (NOT executed — offline, no console) a ring-0 probe that issues the PS5
hypervisor's `IOMMU_READ_DEVICE_TABLE` (hypercall `0xc`) and `GET_TMR_VIOLATION_ERROR` (`0xd`) via
the AMD SVM `vmmcall` instruction, as a clean READ of the HV's IOMMU/TMR state that does **not**
touch XOM (`.text` / slid `.text`) or guess at MMIO — the two paths `kernel_copyout` cannot reach
(`REGION_ACCESS.md`, `XOM_BYPASS.md`).

**Sources (all offline):** FreeBSD `sys/amd64/vmm/amd/{vmcb.h,svm.c}` (VMCB intercept/exit-code
layout); `kdata_1360.bin` (15 MB `.data` dump, base `0xffffffffd0930000`) string table for the
`sce_svmd.c` hypercall wrappers; public RE: psdevwiki Hypervisor page, `PS5Dev/Byepervisor`
(`_old_jump_table_exploit/`), `ps5-linux/ps5-linux-loader` (`hv_defeat_0304.c` / `hv_defeat_0506.c`
/ `shellcode_kernel/boot_linux.c`), `cragson/ps5-hen/hv_defeat.h`, AMD IOMMU spec Rev 2.0.

---

## 1. The hypercall surface (public + discovered extensions)

psdevwiki `Hypervisor` page (the 16 "known" vmmcalls, `VMMCALL_HV_*`):

| # | name | notes |
|---|---|---|
| 0x0 | GET_MESSAGE_CONF | |
| 0x1 | GET_MESSAGE_COUNT | |
| 0x2 | START_LOADING_SELF | |
| 0x3 | FINISH_LOADING_SELF | |
| 0x4 | SET_CPUID_PS4 | kernel wrapper gadget exists (`Byepervisor` `KERNEL_GADGET_HYPERCALL_SET_CPUID_PS4`) |
| 0x5 | SET_CPUID_PPR | |
| 0x6 | IOMMU_SET_GUEST_BUFFERS | registers the guest command-buffer / device-table / event-log buffers |
| 0x7 | IOMMU_ENABLE_DEVICE | wrapper `hv_iommu_enable_device error:%d 0x%x` |
| 0x8 | IOMMU_BIND_PASID | wrapper `hv_iommu_bind_pasid ...:%d 0x%x %d 0x%lx` |
| 0x9 | IOMMU_UNBIND_PASID | wrapper `hv_iommu_unbind_pasid error:%d 0x%x %d` |
| 0xa | IOMMU_CHECK_CMD_COMPLETION | |
| 0xb | IOMMU_CHECK_EVLOG_REGS | wrapper `hv_iommu_check_evlog_regs` |
| **0xc** | **IOMMU_READ_DEVICE_TABLE** | **target — read back the device table (DTE)** |
| **0xd** | **GET_TMR_VIOLATION_ERROR** | **target — TMR violation state** |
| 0xe | VMCLOSURE_INVOCATION | ≥3.00 |
| 0xf | STARTUP_MP | wrapper `hv_startup_mp(%d) failed!` |
| 0x10 | DISABLE_STARTUP_MP | |

**The public table is incomplete.** `kdata_1360.bin` carries Sony's `sce_svmd.c`
(`W:/Build/J03950001/sys/freebsd/sys/kern/sce_svmd.c`) wrapper strings for hypercalls **not** in
the table — `hv_map_pt_tmr`, `hv_unmap_pt_tmr`, `hv_restore_pt_tmr`
(`'ERROR: %s(%d) hv_unmap_pt_tmr(%d) failed: %d'`, `'[core spm] hv_unmap_pt_tmr() failed0x%x'`,
…). `ps5-linux-loader` `hv_defeat_0506.c` confirms these are *hypercalls* — it calls
`FUN_HV_UNMAP_PT_TMR` to "corrupt NESTED_CTRL in vmcb **via hv_unmap_pt_tmr hypercall**". So the
HV's real dispatch table extends past 0x10 with TMR map/unmap/restore entries. Numbering unknown
(offline); relevant only to note that the HV's jump table has ≥ ~0x14+ entries and that a probe can
enumerate them.

---

## 2. vmmcall ABI (AMD SVM)

### 2.1 Instruction + trap

- **Opcode:** `VMMCALL` = `0F 01 D9` (AMD SVM, guest → hypervisor). In gas/Clang: `vmmcall`
  (`.byte 0x0f, 0x01, 0xd9` if the assembler lacks the mnemonic).
- **Privilege:** CPL-0 only. Executing `vmmcall` in user mode raises **#UD** (SIGILL) — this is
  *exactly* what `ps5-linux-loader` `stage3_force_vmcb_reload()` exploits: it issues a bare
  `__asm__ volatile("vmmcall")` from userland and **catches SIGILL** when the VMMCALL is not
  intercepted. ⇒ the probe's `vmmcall` **must execute in ring-0**.
- **Intercept:** VMCB control-area `intercept[4]` bit 1 (`VMCB_INTCPT_VMMCALL`, FreeBSD
  `vmcb.h`). When set, a guest `vmmcall` triggers a **#VMEXIT with exit code 0x81 (VMEXIT_VMMCALL)**
  (AMD APM Vol 2 Appendix C). The HV exit handler reads the guest GPRs out of the VMCB guest-state
  save area and dispatches.

### 2.2 Register convention

AMD SVM / KVM-x86 style, confirmed by `ps5-linux-loader` `shellcode_kernel/boot_linux.c`:

```c
static inline uint64_t vmmcall(uint64_t nr, uint64_t a0, uint64_t a1, uint64_t a2, ...)
    __asm__ volatile("vmmcall" : "=a"(ret)
                     : "a"(nr), "b"(a0), "c"(a1), "d"(a2) : "memory");
```

| register | role |
|---|---|
| **RAX** | **hypercall number** (the `VMMCALL_HV_*` index) |
| **RBX** | arg0 |
| **RCX** | arg1 |
| **RDX** | arg2 |
| RSI, RDI, R8–R15 | args 3+ (whether the HV reads them is **unverified**) |
| **RAX** (ret) | status/error code (the kernel wrappers check it, e.g. `hv_get_tmr_violation_error() error %d`) |

**Dispatch:** the HV indexes a jump table by the hypercall number (RAX). `Byepervisor` hijacked the
`VMMCALL_HV_SET_CPUID_PS4` entry to get HV code-exec: `KERNEL_SYM_HV_JMP_TABLE = 0x245BEE0` (2.50,
in-kernel HV), and the SET_CPUID_PS4 entry sat at `HV_JMP_TABLE + 0x70`, stored as a `uint32_t`
offset-from-table (`uint32_t *ent = (uint32_t*)mirror; orig = *ent`). That guest-shared jump table
is ≤2.70 only; on 13.60 the HV is a separate component and the table is HV-private (the 13.60 lead
is the NPT alias, `HV_RESEARCH.md`). The dispatch *principle* (RAX → table index) carries over.

### 2.3 How a payload issues vmmcall from ring-0

The WebKit/IPV6 KEX gives a kernel-R/W payload; the payload must run its vmmcall **in ring-0**.
Two routes:

1. **Kernel code cave (primary).** Copy a small ring-0 stub into a writable kernel page (the
   `hen/` flat-binary model — "copied into a kernel code cave … runs in supervisor/kernel mode"),
   pin to a core, and execute it. The stub does the inline-asm `vmmcall` directly.
2. **Call the existing kernel wrapper (safer).** Resolve `hv_get_tmr_violation_error` /
   `hv_iommu_read_device_table` from the slid `.data` (KASLR slide = **+0x4FA60000**,
   `REGION_ACCESS.md`) and invoke it through a kernel-mode call gadget. The wrapper already loads
   `RAX = nr` and formats the args, so the probe can't get the register order wrong.

The payload runs in **guest** ring-0, so `vmmcall` traps to the HV and returns to the stub with the
result in RAX — no HV context is entered beyond the handler.

---

## 3. Expected argument format — 0xc and 0xd (evidence, unverified)

### 3.1 IOMMU_READ_DEVICE_TABLE (0xc)

`kdata_1360.bin` debug formats in the amd_iommu/`sce_svmd.c` path:

```
'## Device Table.  device_id(bsf):0x%x %s\n'     ← header: input device_id (bus:slot:func)
'## Raw Device Table.\n'                          ← raw (undecoded) dump variant
'AMD IOMMU\n'
'domain_id: %04x\n'                              ← DTE decoded field: domain id (16-bit)
'    pml4:0x%016lx\n'                            ← DTE decoded field: page-table root (64-bit)
' raw dte[%d]:0x%08x\n'                          ← raw DTE words (32-bit each)
'IOMMU MMIO Command and Log Registers:\n'
'IO_PAGE_FAULT'  'DEV_TAB_HARDWARE_ERROR'  'EV_TAB_HARDWARE_ERROR'
```

The AMD-Vi **device table entry (DTE) is 256 bits = 32 bytes = 8 dwords**, indexed by device id.
`device_id(bsf)` = the bus/slot/function id (16-bit, `bus<<8 | dev<<3 | func`); the sibling strings
`'iommu bsf'`, `'IOMMU device_id:0x%x is too big. Please increase IOMMU_NDTE:0x%x!'` pin it as a
plain integer id. The decoded dump (`domain_id` + `pml4`) maps onto the DTE's Domain ID and
page-table-root fields (AMD IOMMU spec Rev 2.0 §2.5.2).

`IOMMU_SET_GUEST_BUFFERS` (0x6) registers the guest's **command buffer ("iommu cmd"), device table
("iommu dt"), and event log ("iommu evt")** with the HV (those literal strings are the buffer
names). So the most likely shape of 0xc is either:

- **hypothesis A (per-call buffer):** `vmmcall(0xc, device_id /*RBX*/, out_buf /*RCX*/)` → HV writes
  the 32-byte DTE for `device_id` into `out_buf`, returns status in RAX; **or**
- **hypothesis B (pre-registered buffer):** `vmmcall(0xc, device_id /*RBX*/)` → HV copies the DTE
  out of its registered "iommu dt" buffer and returns it (in registers, or via that buffer).

**Open question — VA vs GPA:** the HV sees the guest through the NPT, so a buffer argument may need
to be a **guest-physical address (GPA)**, not a guest virtual address. The probe must try both
forms (`out_buf` VA and its `DMAP_BASE + pa` physical form) and compare.

### 3.2 GET_TMR_VIOLATION_ERROR (0xd)

`'%s: hv_get_tmr_violation_error() error %d\n'` — the wrapper takes (apparently) **no arguments**
and returns a status/error code in RAX. Related TMR strings pin what "violation" means:

```
'  TMR check violation'        'Detect TMR Violation'        'PPRREQ-33273 TMR violation, Count %d'
'tmr_violation_worker'         'tmr_viol_spin'               '=== TMR: fail=%d'
'TMR Interrupts:'              'failed to resume tmr thread'  'tmr_check_on_boot'
```

TMR = Trusted Memory Region, the HV's hardware-backed memory-range protection (the thing
`hv_defeat_0304` relaxes via `TMR_CFG_PERMISSIVE=0x3F07` on TMR CONFIG indices 5/16/17/18).
`GET_TMR_VIOLATION_ERROR` most likely returns the current TMR violation status/count (e.g. the
"Count %d" value) — i.e. a cheap read of TMR state **without** touching the TMR MMIO ports
(index 0x80 / data 0x84) or `sceSblTmrDumpReg`.

---

## 4. Concrete probe (C) — ring-0 vmmcall reader

Runs in a kernel code cave (route 1) or via the wrapper call (route 2). Logs to `/data/tmp/` with
`O_SYNC` and a per-line `fflush` so the last line survives a panic (klog is the fault reader —
`ps5-kernel-research`). First run on the **7.61 workhorse**, capture card + klog live.

```c
// hypercall_probe.c — ring-0 vmmcall probe (DESIGN, not yet built/run)
typedef unsigned long long u64; typedef unsigned int u32;

/* --- vmmcall primitive: RAX=nr, RBX=a0, RCX=a1, RDX=a2, ret in RAX --- */
static inline u64 vmmcall3(u64 nr, u64 a0, u64 a1, u64 a2) {
    u64 ret;
    __asm__ volatile("vmmcall"
        : "=a"(ret)
        : "a"(nr), "b"(a0), "c"(a1), "d"(a2)
        : "rsi","rdi","r8","r9","r10","r11","memory","cc");
    return ret;
}

#define HC_IOMMU_READ_DEVICE_TABLE 0xc
#define HC_GET_TMR_VIOLATION_ERROR 0xd

extern void log(const char *fmt, ...);   /* O_SYNC write to /data/tmp/hcprobe.log + klog */

/* Probe A — GET_TMR_VIOLATION_ERROR (0xd): no-arg read of TMR violation state. */
static void probe_tmr(void) {
    log("== 0xd GET_TMR_VIOLATION_ERROR ==");
    u64 r0 = vmmcall3(HC_GET_TMR_VIOLATION_ERROR, 0, 0, 0);
    log("vmmcall(0xd, 0,0,0)      ret=0x%llx", r0);
    /* signature discovery: if it ignores args, these all return the same value */
    u64 r1 = vmmcall3(HC_GET_TMR_VIOLATION_ERROR, 1, 0, 0);
    u64 r2 = vmmcall3(HC_GET_TMR_VIOLATION_ERROR, 0, 0x40, 0);  /* maybe a TMR id */
    log("vmmcall(0xd, 1,0,0)      ret=0x%llx", r1);
    log("vmmcall(0xd, 0,0x40,0)   ret=0x%llx", r2);
}

/* Probe B — IOMMU_READ_DEVICE_TABLE (0xc): dump DTEs over a device-id range. */
static void probe_iommu_dte(void) {
    log("== 0xc IOMMU_READ_DEVICE_TABLE ==");
    static __attribute__((aligned(64))) u32 dte[8];   /* 256-bit DTE = 8 dwords */

    /* B1: per-call out-buffer hypothesis — device_id in RBX, out VA in RCX. */
    for (u64 dev = 0; dev < 0x40; dev++) {
        for (int i = 0; i < 8; i++) dte[i] = 0xDEAD0000u | (u32)dev;
        u64 r = vmmcall3(HC_IOMMU_READ_DEVICE_TABLE, dev, (u64)dte, 0);
        log("dev 0x%02llx ret=0x%llx dte=%08x %08x %08x %08x %08x %08x %08x %08x",
            dev, r, dte[0],dte[1],dte[2],dte[3],dte[4],dte[5],dte[6],dte[7]);
    }

    /* B2: GPA out-buffer hypothesis — pass the DMAP/physical form of the buffer in RCX. */
    /*   (DMAP_BASE = 0xfffff80000000000; gpa = dmap_va - DMAP_BASE for the low 16 GB)      */
    /*   vmmcall3(0xc, dev, gpa_of(dte), 0);  — compare against B1.                        */

    /* B3: pre-registered-buffer hypothesis — register via 0x6 first, then vmmcall(0xc,dev,0,0). */
    /*   vmmcall3(0x6, cmd_buf_gpa, dt_buf_gpa, evt_buf_gpa);  then read dt_buf_gpa.       */
}

/* DTE decode helper (log after a successful read): */
static void log_dte(u32 *d) {
    /* AMD IOMMU spec Rev 2.0 §2.5.2:
       q0 bit0 V(valid), bit1 TV, bits[7:6] Mode,
       Domain ID in bits [21:8] (16-bit) -> 'domain_id: %04x'
       q1 = page-table root (PML4)       -> '    pml4:0x%016lx'
       then raw q2..q7  (SMI/IntCtl/IOTLB/…) */
    log("    V=%u TV=%u mode=%u domain_id=%04x pml4=0x%016llx",
        d[0]&1, (d[0]>>1)&1, (d[0]>>6)&3, (d[0]>>8)&0xffff,
        ((u64)d[3]<<32) | d[2]);
}

void probe_main(void) { probe_tmr(); probe_iommu_dte(); }
```

---

## 5. Caveats

1. **CPL-0 required.** `vmmcall` from userland #UDs (SIGILL) — the probe stub must run in ring-0
   (code cave or kernel-wrapper call). A userland `vmmcall` will not reach the HV.
2. **Bad args may fault the HV.** An unknown hypercall number or malformed args can make the HV
   inject **#GP** into the guest (kernel panic) rather than return an error. Byepervisor's SIGILL
   catch is for the *userland* #UD, not for a ring-0 bad-hypercall #GP. Run on the 7.61 workhorse,
   klog captured, expect a possible panic; recover = cold-boot + re-JB. Do NOT fire on the 11.60 Pro.
3. **Caller context may matter.** The IOMMU hypercalls may require the guest buffers to be
   registered first via `IOMMU_SET_GUEST_BUFFERS` (0x6), and/or require execution on the core that
   owns the target IOMMU unit (8 units ↔ 8 MMIO windows, `IOMMU_AUDIT.md`). `GET_TMR_VIOLATION_ERROR`
   (0xd) is the safest first probe (no args, pure read).
4. **Exact arg format is unverified.** The register convention (RAX/RBX/RCX/RDX) is high-confidence;
   the *semantics* of 0xc/0xd (device-id width, VA-vs-GPA buffer, DTE-vs-status return) are inferred
   from the `sce_svmd.c` debug formats + the AMD-Vi DTE layout, not from the HV binary. The probe
   enumerates both buffer hypotheses (B1/B2/B3) and logs every return code so the real signature can
   be pinned from observed behavior.
5. **Return-code semantics.** FreeBSD `syscall()`-style: expect a raw status (0 = success, positive
   = error code). `hv_get_tmr_violation_error() error %d` shows the kernel treats non-zero as an
   error.
6. **HV jump table is ≥ 0x14 entries** (TMR map/unmap/restore are unlisted hypercalls). A generic
   `vmmcall(n, 0,0,0)` sweep over `n = 0..0x20` is a natural extension to map the real table — but
   do it *after* 0xc/0xd are understood, one `n` at a time, because unknown `n` is the panic-prone
   case.

---

## 6. Change log
- 2026-10-05: created. Pinned vmmcall opcode `0F 01 D9`, VMEXIT code 0x81, RAX/RBX/RCX/RDX
  convention (boot_linux.c + Byepervisor jump-table exploit); extracted the `sce_svmd.c` wrapper +
  DTE/TMR debug formats from `kdata_1360.bin`; documented the unlisted TMR hypercalls; wrote the
  ring-0 probe design + caveats.
