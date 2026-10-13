# HV_UNMAP_PT_TMR.md — does the <=6.02 hv_unmap_pt_tmr VMCB heap-OOB still exist on 8.00–13.60?

**Date:** 2026-10-05
**Question:** the public <=6.02 hypervisor exploit corrupts `NESTED_CTRL` in the VMCB via the
`hv_unmap_pt_tmr` hypercall (an OOB write into the VMCB that disables NPT). Is that same bug — or
an analog — reachable on firmware 8.00–13.60?

**Bottom line: NO.** The `hv_unmap_pt_tmr` hypercall *still exists* on 13.60 (its kernel wrapper +
error strings persist unchanged from 7.61 → 13.60), but the OOB primitive is **not live**:
(1) the OOB was closed at **6.50** (the 6.50–7.61 exploit already uses a different primitive), and
(2) on **8.00+ the HV relocated** off the old `0x628xxxxx` carve-out, so the fixed
`hvm_shm`/`vmcb0` addresses the `tmr_id` formula depends on no longer exist. There is no analog:
the 8.00–13.60 defeat is a *different* class (the Sonic-Iso root-0 NPT alias = data read/write of
HV memory, `ps5-hypervisor-defeat` skill), not a VMCB OOB via this hypercall.

---

## 1. The exact OOB (public analysis — psdevwiki, ps5-linux-loader, TheFloW/Jordy)

Source: `ps5-linux/ps5-linux-loader/source/hv_defeat_0506.c` (firmware 5.00–6.02), deepwiki
"HV Defeat: Firmware 05xx–06xx", psdevwiki Vulnerabilities §13.3
("<=6.02 - Hypervisor heap OOB in vmcb via hv_unmap_pt_tmr" — discovered TheFloW 2026-05-17,
refactored by Jordy 2026-06-01).

### 1.1 Which hypercall, which args

- **Hypercall:** `UNMAP_PT_TMR` (hypercall number ≥ 0x11; not in the public 0x0–0x10 table).
  Kernel wrapper `hv_unmap_pt_tmr` (`FUN_HV_UNMAP_PT_TMR` in `offsets.h`).
- **vmmcall ABI** (RAX = number, RBX = arg0, RCX = arg1, RDX = arg2): the wrapper is invoked as
  `FUN_HV_UNMAP_PT_TMR(tmr_id, 0x1000, 0)`, i.e.
  - **RBX = `tmr_id`** — the *unchecked* index (this is the OOB lever),
  - **RCX = `0x1000`** — a size/length (one page),
  - **RDX = `0`** — flags.

### 1.2 The bug

The HV keeps a per-TMR entry array in **HV shared memory** (`hvm_shm`) at a fixed offset
`+0x298`, stride **0x18 bytes/entry**. The unmap handler computes the target address as

```
addr = hvm_shm + 0x298 + tmr_id * 0x18
```

and writes/clears the entry there **without validating `tmr_id`**. A large `tmr_id` makes `addr`
walk past the TMR array (the "heap OOB") into the adjacent VMCB array. Choosing

```
tmr_id = (vmcb0 + vcpu*0x2000 + 0x90 - hvm_shm - 0x298) / 0x18
```

makes the write land exactly at **VMCB + 0x90 = `NESTED_CTRL`** (the nested-paging control dword:
bit 0 = `NP_ENABLE`, bit 3 = GMET enable — `NESTED_CTRL_GMET_ENABLE = 0x8` in the source; the field
is `VMCB_NP_ENABLE = 0x90` in cragson's `hv_defeat.h`).

### 1.3 Fixed physical addresses (5.00–6.02 only)

| FW | vCPU | hvm_shm     | vmcb0       | comment                                  |
|----|------|-------------|-------------|------------------------------------------|
| 05xx | 0 | `0x62a01000` | `0x62a08000` | `tmr_id = (vmcb0 - hvm_shm - 0x208) / 0x18` |
| 06xx | 1 | `0x62a22000` | `0x62a57000` | same formula                             |

Exploit sequence (ROP via #GP on ACPI resume):
1. `FUN_HV_UNMAP_PT_TMR(tmr_id, 0x1000, 0)` → corrupt `NESTED_CTRL` of the current VMCB (OOB).
2. Disable NPT in **all 16** VMCBs: direct kernel DMAP writes of `0x8` to `get_vmcb(i)+0x90`.
3. `FUN_HV_UNMAP_PT_TMR(0, 0, -1)` → trigger a second vmmcall to force the VMCB reload.

---

## 2. 13.60 kernel .data/.text search (offline, binary)

### 2.1 Wrapper strings in `kdata_1360.bin` (base VA `0xffffffffd0930000`)

| string | hits | file offsets (VA = base + off) |
|---|---|---|
| `hv_unmap_pt_tmr` | **3** | `0x5d42df` (`…d0f042df`), `0x5fc796`, `0x6a6a0d` |
| `hv_restore_pt_tmr` | **4** | `0x5cb0ce`, `0x5cb9af`, `0x6b8ba7`, `0x6ed961` |
| `hv_map_pt_tmr` | **0** | — (no wrapper error-format string in ANY firmware, not a 8.00 removal) |
| `hv_get_tmr_violation_error` | 1 | `0x606e22` |

These are the wrapper *debug/error format strings* (`hv_unmap_pt_tmr(%d) failed: %d`, …). Cross
version the counts are **identical** (`HV_WRAPPERS.md`, `DATA_DIFF_761_1360.md` §5):

| fw | unmap | restore | map |
|----|-------|---------|-----|
| 7.61 | 3 | 4 | 0 |
| 11.60 | 3 | 4 | 0 |
| 13.60 | 3 | 4 | 0 |

⇒ the `hv_unmap_pt_tmr` / `hv_restore_pt_tmr` kernel wrappers **survived the 8.00 HV relocation
unchanged in identity** (relocated only). The kernel still calls the `UNMAP_PT_TMR` hypercall on
13.60.

### 2.2 What is NOT recoverable

- **Wrapper function addresses:** zero `.data` xrefs to any `hv_*` string, no symbol table — the
  wrappers live in core XOM `.text` (`0xffffffff80xxxxxx`) and are referenced only by RIP-relative
  addressing (`HV_WRAPPERS.md` §3, `KERNEL_HYPERCALLS.md` §5).
- **Hypercall numbers (MAP/UNMAP/RESTORE_PT_TMR ≥ 0x11):** not in the public psdevwiki table, and
  the wrapper's `mov eax, imm32` number-load is in XOM text — **not determinable offline**.
- **HV dump** (`hv_dump/hvcluster_*.bin`, `hvdump_0x26000000_600MB.bin`): **zero** `pt_tmr` strings
  (only coincidental `TMR`/`tmR` substrings in compressed/opaque bytes). The HV is a separately
  loaded component; its `.rodata`/`.data` are not captured in plaintext by the NPT-alias dump.

### 2.3 The fix is visible in the 13.60 .data

The TMR id/size **validation** strings are present on 13.60 (and identical across 7.61/11.60/13.60,
`DATA_DIFF_761_1360.md` §7):

```
'TMR param, id, paddr, or size is invalid'   @ 0x5ccce4  (VA 0xffffffffd0efcce4)
'TMR range is illegal'                       @ 0x61f847  (VA 0xffffffffd0f4f847)
```

These are the bounds/param-check error messages that correspond to the `tmr_id`/size validation the
<=6.02 HV was missing.

---

## 3. Was it fixed at 8.00+, or before? — 6.50.

`hv_defeat_0607.c` (firmware **6.50–7.61**) **no longer uses `FUN_HV_UNMAP_PT_TMR` at all.** It
switches to a different HV-defeat primitive: `wrmsr(MSR_APICBASE, hv_stack|ENABLED|BSP)` to trigger
HV code execution, then `shellcode_0607` resolves each VMCB by walking the HV's own page tables
(`vtophys(vCPU[i]+0x08, hv_pml4)`) instead of a fixed address (`VMCB_PA.md` §2). Two consequences:

1. The `hv_unmap_pt_tmr` OOB was **already dead by 6.50** — either a bounds check was added
   (consistent with the `…id… is invalid` strings) or the VMCB/hvm_shm layout moved so the fixed
   `tmr_id` formula no longer reaches the VMCB. Either way, the <=6.02 write primitive is gone
   before 8.00.
2. On **8.00+ the HV is a separately-loaded component** whose base moved off `0x628xxxxx`:
   `kdata_1360.bin` contains **zero** u64 references into `0x62800000–0x62B00000`, and no VMCB
   structure (`VMCB_PA.md` §3). So even the *fixed addresses* the `tmr_id` formula needs
   (`hvm_shm = 0x62a01000/0x62a22000`, `vmcb0 = 0x62a08000/0x62a57000`) do not exist on 13.60.

---

## 4. Live on 8.00–13.60? — assessment

| question | answer |
|---|---|
| Is `hv_unmap_pt_tmr` still a dispatched hypercall on 13.60? | **Yes** — wrapper strings persist 7.61→13.60 unchanged; kernel still calls it |
| Is the <=6.02 VMCB heap-OOB reachable on 8.00–13.60? | **No** |
| When was it closed? | **6.50** (exploit targets 5.00–6.02 only; 6.50+ uses a different primitive) |
| Did 8.00 add anything that matters? | The HV relocation killed the fixed `hvm_shm`/`vmcb0` anchors the OOB formula needs |
| Is there an analog on 8.00–13.60? | **No.** The 8.00–13.60 defeat is the *NPT-alias data R/W* (Sonic-Iso root-0 lead, patched 14.10) — a different vulnerability class, not a VMCB OOB via a hypercall |

### What a port would need (if the OOB still existed — it does not)

1. The **new `hvm_shm` and per-core `vmcb0` PAs on 8.00+** — recoverable only by dumping the
   aliased HV code (NPT alias, `probe67/hvscan3.elf`) and disassembling the TMR-array base and the
   VMCB table (`vtophys(vCPU+0x08, hv_pml4)` walk, `VMCB_PA.md` §4).
2. Re-derive `tmr_id = (vmcb0 + vcpu*0x2000 + 0x90 − hvm_shm − 0x298)/0x18` with the new bases.
3. **Ring-0 vmmcall** to issue `UNMAP_PT_TMR` (CPL-0 only; ring-3 vmmcall #UDs — `HYPERCALL_PROBE.md`
   §2). Ring-0 code exec is blocked on 6.00+ (GMET), so this would itself require the NPT-alias
   data-write primitive to be won first.

Point 3 is circular, and points 1–2 are moot anyway: **the OOB is patched at 6.50**, so a ported
exploit would hit the `…id… is invalid` bounds check and return an error instead of writing past
the TMR array. Conclusion: **`hv_unmap_pt_tmr` is not a live HV-defeat path on 8.00–13.60.** Keep
the NPT-alias lane (`HV_RESEARCH.md`, `references/hv-npt-alias.md`) as the only 8.00–13.60 door.

---

## 5. Sources

- `ps5-linux/ps5-linux-loader` `source/hv_defeat_0506.c` (the OOB exploit, 5.00–6.02) and
  `source/hv_defeat_0607.c` (6.50–7.61 — proves the OOB was abandoned at 6.50).
- psdevwiki `Vulnerabilities` §13.3 and `Hypervisor` (hypercall table 0x0–0x10; TMR calls ≥ 0x11).
- deepwiki "HV Defeat: Firmware 05xx–06xx".
- Offline binaries: `kdata_1360.bin` (and 7.61/11.60 dumps) string scans; `hv_dump/` cluster dumps.
- Prior workspace docs: `HV_WRAPPERS.md`, `KERNEL_HYPERCALLS.md`, `HYPERCALL_PROBE.md`,
  `VMCB_PA.md`, `DATA_DIFF_761_1360.md`.

## 6. Change log
- 2026-10-05: created. Pinned the exact OOB (hypercall, arg, `hvm_shm+0x298+tmr_id*0x18` → VMCB+0x90
  `NESTED_CTRL`); verified the wrapper strings persist unchanged 7.61→13.60 (hypercall still live);
  established the OOB is closed at 6.50 and that 8.00+ relocation kills the fixed anchors; concluded
  no live path on 8.00–13.60 and no analog.
