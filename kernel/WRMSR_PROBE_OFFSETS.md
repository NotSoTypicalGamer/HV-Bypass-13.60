# WRMSR_PROBE_OFFSETS.md — 13.60 resume-#GP ROP delivery offsets

Date: 2026-10-06 · Console: 10.0.0.x (13.60, fw 0x13600007) · Method: live read-only
kernel_copyout VA dumps (64 KB chunks), analyzed offline. Nothing was written to the
kernel; no panics.

Replicates ps5-linux-loader `hv_defeat_0607.c` delivery (resume #GP -> ring-0 ROP ->
wrmsr(MSR_APICBASE)) on 13.60 to test whether the APICBASE MSR intercept still gives a
controllable HV-side effect.

---

## 0. Runtime kernel bases (THIS boot)

| name | value | source |
|---|---|---|
| kdata (data base) | `0xffffffffcae90000` | `payload_get_args()->kdata_base_addr` (live) |
| ktext (text base) | `0xffffffffca1d0000` | klog (unverified independently; consistent with IDT handlers at `0xffffffffca43xxxx`) |
| dmap (direct map) | `0xffffaded00000000` | klog; CONFIRMED live — the FACS pointer value is `0xffffaded7fd6e000` |

NOTE: the task brief's `kdata=0xffffffffcbc2d000` is STALE. The live runtime kdata is
`0xffffffffcae90000`. Trust `payload_get_args()->kdata_base_addr` at runtime, never the
brief or any hardcoded SDK constant. Text and data are KASLR-slid INDEPENDENTLY per boot,
so express globals as **kdata + offset** (data slides uniformly); do NOT assume a fixed
ktext<->kdata delta.

---

## 1. AcpiGbl_FACS  —  VERIFIED

- **Address:** `0xffffffffcdb99490`  =  **kdata + 0x2D09490**
- **Contents:** `0xffffaded7fd6e000`  =  dmap + `0x7fd6e000`
- **FACS physical address:** `0x7fd6e000`  (~2.0 GB, in the ACPI reserved region)

Found by the ACPICA chain (all in the core-kernel .bss, ACPICA is statically linked):

| global | VA | kdata offset | contents |
|---|---|---|---|
| `AcpiGbl_FADT` (FACP copy) | `0xffffffffcdb99320` | `+0x2D09320` | FADT; `FIRMWARE_CTRL@+0x24 = 0x7fd6e000` (FACS PA), `X_FIRMWARE_CTRL@+0x84 = 0` |
| `AcpiGbl_DSDT` | `0xffffffffcdb99460` | `+0x2D09460` | `0xffffaded7fd89000` (DSDT PA `0x7fd89000`) |
| `AcpiGbl_OriginalDsdtHeader` | `0xffffffffcdb99468` | `+0x2D09468` | "DSDT" header copy |
| **`AcpiGbl_FACS`** | **`0xffffffffcdb99490`** | **`+0x2D09490`** | **`0xffffaded7fd6e000`** |

This matches ACPICA `tbdata.c`/`tbutils.c` (`acglobal.h` lines 56-68): `AcpiTbParseFacs`
sets `AcpiGbl_FACS = AcpiOsMapMemory(FADT.Facs)` = DMAP + FACS_PA, exactly the observed
value. There is exactly ONE u64 in the .bss window holding DMAP+0x7fd6e000, and it sits
immediately after the DSDT/OriginalDsdtHeader block — this is the ACPICA global the
`AcpiSetFirmwareWakingVector` suspend path dereferences. The ps5-linux-loader corruption
`*(AcpiGbl_FACS) = AcpiGbl_FACS - 8` applies here verbatim.

---

## 2. Kernel IDT  —  VERIFIED

- **Address:** `0xffffffffcdd84300`  =  **kdata + 0x2EF4300**  (256 x 16-byte gate descriptors)
- 256 consecutive gates, selector `0x20`, type `0xE/0xF`, P=1 — byte-verified live.

Key vectors (gate offset = lo16 | hi<<16 | (bytes[8:12] << 32)):

| vector | handler (this boot) | ist | notes |
|---|---|---|---|
| 0  (div)    | `0xffffffffca43a300` | 0 | |
| 1  (dbg)    | `0xffffffffca43a070` | 4 | |
| 2  (NMI)    | `0xffffffffca43a308` | 2 | |
| 8  (DF)     | `0xffffffffca43a330` | 1 | |
| **13 (#GP)**| **`0xffffffffca43a358`** | **0** | `IDT_GP` — the ROP delivery rewrites this gate (ist 0 -> 6, offset -> `add rsp,0x28;pop rbp;ret`) |
| 14 (PF)     | `0xffffffffca43a360` | 0 | |
| 30 (SX)     | `0xffffffffca43a388` | 5 | Sony-reserved; 0607 uses it for the shellcode IST7 path |

IDT_GP gate entry (to patch): **`0xffffffffcdd843d0`** (= IDT + 13*16).

---

## 3. COMMON_TSS (per-CPU TSS array)  —  VERIFIED

- **Address:** `0xffffffffcdd86fe0`  =  **kdata + 0x2EF6FE0**  =  **IDT + 0x2CE0**
- **Struct size / stride:** **0x68 bytes** per CPU (NOT 0x100 — the GDT TSS descriptors are
  exactly 0x68 apart). MAXCPU entries.
- Located via the GDT TSS descriptors (system-segment type `0xB`) whose `base` field points
  at `&common_tss[cpu]`; per-CPU GDT stride 0x68, TSS descriptor at +0x38 within each.

`common_tss[0]` fields (this boot):

| field | offset | value |
|---|---|---|
| tss_rsp0 | `+0x04` | `0xffffff80a50e7a40` (kernel stack) |
| tss_ist1 | `+0x24` | `0xffffffffcdd8ca60` |
| tss_ist2 | `+0x2C` | `0xffffffffcdd90a50` |
| tss_ist4 | `+0x3C` | `0xffffffffcdd94a50` |
| tss_ist5 | `+0x44` | `0xffffffffcdd98a50` |
| **tss_ist6** | **`+0x4C`** | `0` (== COMMON_TSS[0] + 0x4C = `0xffffffffcdd8702c`) |
| **tss_ist7** | **`+0x54`** | `0` (== COMMON_TSS[0] + 0x54 = `0xffffffffcdd87034`) |
| tss_iobase | `+0x66` | `0x4069` |

The 0607 sequence writes `tss_ist6` (GP ROP stack) and `tss_ist7` (SX shellcode stack) of
`common_tss[0]` to `pa_to_dmap(alloc_page()) + 0x1000`. Offsets `+0x4C`/`+0x54` are the
FreeBSD `struct amd64tss` layout (confirmed identical to `sys/amd64/include/tss.h`).

---

## 4. Kernel .text gadgets  —  NOT RECOVERED (XOM)

`kernel_copyout` returns -1 on kernel .text (XOM / NPT bit-58 "NDA" blocks all DATA reads of
text pages). MemDBG's `KERNEL_READ` (0x0801) is the SAME `kernel_copyout` underneath
(`pal_kernel.c`), and its "fast" rwpipe path (`pal_kernel_fast.c`, `setup_pipe` -> read(2)
on the kernel pipe) is also a data read and is equally XOM-gated — neither reads text bytes.
The DMAP alias of text is the low 0-0x7d00000 guest-PA window, which is a documented panic
edge (trapped firmware page), so a physical read of text is NOT safe either.

To get real 13.60 gadget addresses: single-stepping (sleirsgoevy "On offsets": bootstrap
`doreti_iret`, find `wrmsr_ret`, `rep movsb;pop rbp;ret`, `cpu_switch`, then trace) — this
is a multi-step exploit-dev effort, out of scope for this read-only pass. No scene-shared
13.60 kernel text dump is known locally (Relapse's `offsets_13.60.js` only carries WebKit
`wk_gadgetmap` + libkernel `syscall_map`, userland, NOT kernel text).

For reference only — ps5-linux-loader `offsets.c` 7.61 values (link-time, relative to
`0xFFFFFFFF80210000`; **unverified and almost certainly shifted on 13.60 — do NOT use
directly**):

| gadget | 7.61 link-time offset |
|---|---|
| pop rdi; ret      | `+0x1E1D78` |
| pop rsi; ret      | `+0x1A28B0` |
| pop rdx; ret      | `+0x3BD6B4` |
| pop rcx; ret      | `+0x2D2231` |
| pop rax; ret      | `+0x1FE9D0` |
| pop rsp; ret      | `+0x24A850` |
| wrmsr; ret (0F 30)| `+0x241D04` |
| add rsp,0x28; pop rbp; ret | `+0x98DA44` |
| iretq             | `+0x24480D` |
| memcpy            | `+0x283600` |

---

## 5. Delivery summary (offsets the probe needs)

Read `kdata = payload_get_args()->kdata_base_addr` at runtime, then:

- **AcpiGbl_FACS** = `kdata + 0x2D09490`   (corrupt to `AcpiGbl_FACS - 8`)
- **IDT base**    = `kdata + 0x2EF4300`    (rewrite gate 13 -> `add rsp,0x28;pop rbp;ret`, ist 6)
- **COMMON_TSS**  = `kdata + 0x2EF6FE0`    (write `tss_ist6@+0x4C` = GP ROP stack, `tss_ist7@+0x54` = SX stack)
- **Gadgets**     = UNKNOWN on 13.60 (XOM) — blocked on single-stepping or a text dump.

FACS_PA = `0x7fd6e000`, DSDT_PA = `0x7fd89000` (context only; the exploit corrupts the
pointer, not the table).

Artifacts: `scratch/ps5/wrmsr_dump/` — `wrmsr_dump.elf` (configurable VA dumper),
`rdump_idt.bin` (256 KB around IDT), `rdump_wide.bin` (2.75 MB .bss window containing the
ACPICA globals), `ftp.py`.
