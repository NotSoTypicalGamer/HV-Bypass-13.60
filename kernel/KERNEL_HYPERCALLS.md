# KERNEL_HYPERCALLS.md — vmmcall wrapper recovery from the 13.60 .text dump

**Date:** 2026-10-05
**Input:** `kernel/hv_dump/hvdump_0x26000000_600MB.bin` (guest-PA base `0x26000000`, 608 MiB =
`0x26000000` bytes, contiguous).
**Method:** offline only — exhaustive byte scan for `0F 01 D9` (+ the full SVM `0F 01 D8..DF`
family), capstone-5.0.7 disassembly of every hit and of the code regions.
**Result:** the kernel-side `vmmcall` **wrapper addresses are NOT recoverable from this dump**.
The dump contains readable kernel-module code but **zero** real `vmmcall` instructions; the `hv_*`
wrappers live in the core kernel's XOM `.text`, which this dump captured only as opaque/ciphertext
(see §4). The vmmcall **ABI** and the hypercall **number**→**wrapper-name** map are recoverable and
are given in §2–§3.

---

## 1. Bottom line

| question | answer |
|---|---|
| vmmcall ABI | **RAX = hypercall number; RBX = arg0; RCX = arg1; RDX = arg2; status returned in RAX** (AMD SVM `vmmcall` `0F 01 D9`, CPL0-only, #VMEXIT exit code `0x81`) |
| hypercall # → wrapper VA | **NOT recoverable** — no `hv_*` wrapper function is present in plaintext in this dump |
| real `vmmcall` sites in dump | **0** (18 byte-level `0F 01 D9` matches, all false positives in data — §5) |
| one resolvable vmmcall-issuing site | deci5s/sdbgp debug `VMMCALL` command handler at **`0xffffffffcfeced70`** (from the `.data` xref, `HV_WRAPPERS.md` §4 — not an `hv_*` wrapper) |

---

## 2. vmmcall ABI (confirmed)

From `ps5-linux-loader` `shellcode_kernel/boot_linux.c` (the authoritative in-the-wild consumer):

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
| RSI/RDI/R8–R15 | args 3+ (unverified whether the HV reads them) |
| **RAX (ret)** | status/error code — the kernel wrappers check it, e.g. `hv_get_tmr_violation_error() error %d` |

Opcode `0F 01 D9`, CPL0 only (user-mode `vmmcall` → #UD/SIGILL), VMEXIT code `0x81`
(`VMEXIT_VMMCALL`). The HV dispatches by indexing a jump table with RAX.

---

## 3. Hypercall number → wrapper name (numbers are recoverable; addresses are not)

psdevwiki `Hypervisor` page + the `sce_svmd.c` wrapper strings (`kdata_1360.bin`,
`HV_WRAPPERS.md` §2):

| # | name | kernel wrapper (from string) | wrapper VA |
|---|---|---|---|
| 0x0 | GET_MESSAGE_CONF | — (no string) | **unrecovered** |
| 0x1 | GET_MESSAGE_COUNT | — | **unrecovered** |
| 0x2 | START_LOADING_SELF | — | **unrecovered** |
| 0x3 | FINISH_LOADING_SELF | — | **unrecovered** |
| 0x4 | SET_CPUID_PS4 | (Byepervisor `KERNEL_GADGET_HYPERCALL_SET_CPUID_PS4`) | **unrecovered** |
| 0x5 | SET_CPUID_PPR | — | **unrecovered** |
| 0x6 | IOMMU_SET_GUEST_BUFFERS | `hv_iommu_set_guest_buffers` | **unrecovered** |
| 0x7 | IOMMU_ENABLE_DEVICE | `hv_iommu_enable_device` | **unrecovered** |
| 0x8 | IOMMU_BIND_PASID | `hv_iommu_bind_pasid` | **unrecovered** |
| 0x9 | IOMMU_UNBIND_PASID | `hv_iommu_unbind_pasid` | **unrecovered** |
| 0xa | IOMMU_CHECK_CMD_COMPLETION | — | **unrecovered** |
| 0xb | IOMMU_CHECK_EVLOG_REGS | `hv_iommu_check_evlog_regs` | **unrecovered** |
| **0xc** | **IOMMU_READ_DEVICE_TABLE** | — (inlined into DTE dump; no named string) | **unrecovered** |
| **0xd** | **GET_TMR_VIOLATION_ERROR** | `hv_get_tmr_violation_error` | **unrecovered** |
| 0xe | VMCLOSURE_INVOCATION | — | **unrecovered** |
| 0xf | STARTUP_MP | `hv_startup_mp` | **unrecovered** |
| 0x10 | DISABLE_STARTUP_MP | — | **unrecovered** |
| ≥0x11 | MAP_PT_TMR / UNMAP_PT_TMR / RESTORE_PT_TMR | `hv_unmap_pt_tmr`, `hv_restore_pt_tmr` (no `hv_map_*` string) | **unrecovered** |

Every `hv_*` wrapper is compiled from `sys/freebsd/sys/kern/sce_svmd.c` and lives in the **core
kernel XOM `.text`** (fixed `0xffffffff80xxxxxx`), not in the KASLR-slid driver text
(`0xffffffffcfxxxxxx`) and not in `.data`. `IOMMU_READ_DEVICE_TABLE` (0xc) and
`GET_TMR_VIOLATION_ERROR` (0xd) are the two targets the parent needs; neither has a recoverable
wrapper address here.

---

## 4. What this dump actually is (evidence)

### 4.1 Structure

608 MiB file = guest-PA `0x26000000 .. 0x4C000000`. Per-1 MiB classification (prologue
`55 48 89 e5` + `41 57 41 56` density, REX.W `0x48` density, Shannon entropy, zero fraction):

- **`0x00000000 .. ~0x21a00000`** — mixed: high-entropy (≈8.0) ciphertext/opaque data at offset 0,
  large zero runs (e.g. `0x1a0–0x1b3`, `0x1f0–0x210`), sparse data. This is where the **core kernel
  `.text` (XOM, ciphertext) and its `.data`/`.rodata`** sit — not disassemblable.
- **`~0x21a00000 .. 0x25e00000`** — **readable x86-64 kernel-module code** (see §4.2).
- **`0x25e00000 .. end`** — tail: data, certificates (`-----BEGIN CERTIFICATE-----`), timestamps.

The dump is a **partial/aliased capture**: the readable code references `.rodata` addresses
(e.g. `lea rsi,[rip+0x771a9e]` at `0x24200024` → `0x29B1AC9`) that are **zeroed** in this dump —
so the code's data section was not captured.

### 4.2 The readable code region is kernel modules, not the hv text

- Real prologue density: `AWAVAUATSH` (push r15/r14/r13/r12/rbx…) ×14099, `[A\A]A^A_]`
  (pop rbx/r12/r13/r14/r15…) ×12557 across the region.
- Kernel-mode opcodes inside the region: `syscall` ×452, `sysret` ×420, `iretq` ×226, `rdmsr`
  ×233, `wrmsr` ×237, `wbinvd` ×320, `cpuid` ×196, `swapgs` ×2 (a real entry/exit stub at
  `0x22bbbfee`, `… 0f 01 f8 39 ca 75 cb 5b 41 5e 41 5f c3 …`).
- The region's own RIP-relative calls/leas (`call 0x24550ad0`, `lea → 0x29B1AC9` from `0x24200000`)
  are self-consistent with **file_offset → VA `0xffffffff80200000` + file_offset**, i.e. code at
  `0x24200000` = VA `0xffffffffa2600000` — a **kernel-module** VA, not core text and not the
  `0xffffffffcfed0000` slid driver text.
- Mixed-in userland/library strings (`Roku Ultra 4K`, `_airplay`, certs) → this region also holds
  non-kernel content; it is not a pure kernel-text image.

### 4.3 No hv / SVM strings

Whole-file search: `hv_iommu`, `hv_get_tmr`, `hv_unmap_pt_tmr`, `hv_restore_pt_tmr`,
`hv_startup_mp`, `hv_map_pt_tmr`, `sce_svmd`, `svmd`, `vmmcall`, `VMMCALL`, `tmr_violation` →
**0 hits** (only generic `TMR` ×54 in data). The `sce_svmd.c` wrapper strings live in the core
kernel `.rodata`/`.data`, which this dump does not contain in plaintext.

---

## 5. vmmcall site scan — exhaustive negative

- `0F 01 D9` occurrences in all 608 MiB: **18**. Every one sits in a **data** region and
  disassembles to garbage (false positive):
  `0x02068e36, 0x052ca508, 0x0555e508, 0x062f2508, 0x074a384e, 0x07964fce, 0x07e45537,
  0x08cc1fa0, 0x0a211fa0, 0x0a6e57ee, 0x0bee722a, 0x0ca6722a, 0x119357c6, 0x13ee1cfe,
  0x157fb04b, 0x1fafb04b, 0x1fbe166c, 0x239332c3`.
  Identical-prefix pairs (`…1fa0`, `…722a`, `…fb04b`) at differing offsets prove these are
  repeated **data tables**, not code (same artifact as `HV_LAYOUT.md` §1.1).
- **`mov eax, imm32` (`B8`) immediately preceding a `vmmcall` (the wrapper's number-load): 0
  candidates** in the whole file.
- SVM family counts (all false positives in data, none in the code region): VMRUN 56, VMMCALL 18,
  VMLOAD 30, VMSAVE 28, STGI 39, CLGI 39, SKINIT 24, INVLPGA 53.

**Conclusion:** there are **no real `vmmcall` instructions in this dump**, therefore no kernel
`vmmcall` wrapper to recover. The `hv_*` wrappers are in XOM core text that is either absent or
encrypted here (consistent with `HV_IOMMU_HYPERCALLS.md` and `HV_LAYOUT.md`).

---

## 6. Address-mapping notes (for the parent)

- **Core kernel text** is **fixed** (NOT KASLR-slid) at `0xffffffff80200000` — the sysent
  `sy_call[]` pointers are `0xffffffff80xxxxxx` (`GHIDRA_MAP.md`). Its physical base is
  `0x26000000` (this dump's base), so `VA = 0xffffffff80200000 + file_offset` for the core image;
  the core `.text` itself appears here only as ciphertext/XOM (offset 0 region).
- **Slid driver text** (`cdevsw d_*` targets) is `0xffffffffcfxxxxxx` — the task's
  "slid text base `0xffffffffcfed0000`" refers to **this** region. It is **not present** in this
  dump: `0xffffffffcfed0000 − 0xffffffff80200000 = 0x4FCD0000` = ~1.34 GB file offset, far beyond
  the 608 MiB file.
- The task's phrase "canonical text `0xffffffff80200000` + KASLR slide `+0x4FA60000`" conflates the
  data-segment slide (`0x4FA60000`, from `kdata_1360.bin`, base `0xffffffffd0930000`) with the text
  slide. `0xffffffff80200000 + 0x4FA60000 = 0xffffffffcfc60000`, **not** `0xffffffffcfed0000`; the
  stated `0xffffffffcfed0000` implies a text slide of `0x4FCD0000`. The core text is fixed, so no
  text slide applies to it; only the **slid driver text** (`0xffffffffcfxxxxxx`) slides.

---

## 7. What a payload should do instead

The wrapper addresses being unrecoverable, a ring-0 payload should **issue `vmmcall` directly**
(RAX=nr, RBX/RCX/RDX=args) from a kernel code cave — the ABI in §2 is sufficient and avoids
hunting the wrapper. Targets of interest:

- **`0xc` IOMMU_READ_DEVICE_TABLE** — `vmmcall(0xc, device_id /*RBX*/, out_buf /*RCX, VA or GPA*/, 0)`;
  returns a 32-byte (256-bit) DTE. See `HYPERCALL_PROBE.md` §3.1 for the buffer hypotheses.
- **`0xd` GET_TMR_VIOLATION_ERROR** — `vmmcall(0xd, 0, 0, 0)`; no-arg read of TMR violation state.
  Safest first probe.

To recover a wrapper address at runtime (if needed): scan slid text for `0F 01 D9` preceded by
`B8 imm32` (`HV_WRAPPERS.md` §5), or read the deci5s dispatch table's `VMMCALL` handler pointer at
`0xffffffffd16e4d20+0x18` (resolves to `0xffffffffcfeced70` on the dumped boot).

---

## 8. Artifacts

- `hv_dump/scan_vmmcall.py` — byte scan for `0F 01 D9` (18 hits).
- `hv_dump/dis_vmmcall.py` — capstone disassembly of each hit + number-load recovery (all garbage).
- `hv_dump/scan_ops.py` — SVM-family + privileged-opcode counts; `mov eax,imm → vmmcall` proximity.
- `hv_dump/scan_structure.py` — per-1 MiB code/entropy/zero classification.
- `hv_dump/scan_strings.py` — hv/svmd string search (0 hits) + code-region identity.
- `hv_dump/check_anchor.py` — RIP-relative anchor check (code region → VA `0xffffffff80200000`+off).

## Change log
- 2026-10-05: created. Exhaustive `vmmcall` scan of the 608 MiB `.text` dump → 18 data
  false-positives, 0 real sites, 0 `mov eax,imm → vmmcall` sequences; confirmed the `hv_*` wrappers
  (core XOM text) and the slid driver text (`0xffffffffcfed0000`) are absent from this dump; pinned
  the ABI (RAX/RBX/RCX/RDX) and the hypercall-number→wrapper-name table; flagged the
  `0xffffffffcfed0000` vs `0xffffffffcfc60000` slide discrepancy.
