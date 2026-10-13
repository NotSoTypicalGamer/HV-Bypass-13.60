# S3-Resume AP-Launch — 13.60 port plan

Source write-up: `s3-resume-startup_mp-ap-launch.md` (the S3-resume `khv_startup_mp`
hypercall-`0x0f` AP-launch bug, proven on 10.00). This is the deterministic replacement for
the stochastic "lucky boot": S3 resume reopens the one-shot AP-startup window, letting an
AP run under root 0 (host view) and read/write all 16 live VMCBs in plaintext.

## The chain

1. **Relapse** (aio_multi_wait, syscall 663) -> GameOS kernel R/W + kcall/ROP. (Have it.)
2. Stage a 4 KiB position-independent payload at `0x3ffff000` (root-0-executable identity
   page, ends at `0x40000000`; survives S3 clean).
3. Arm a `#DB` breakpoint at `acpi_sleep_machdep+0x18e` -> suspend -> resume -> the #DB
   fires inside the window (after `resumectx`, before `acpi_wakeup_cpus`).
4. The #DB ROP chain executes `HCALL 0x0f(core=15, RIP=0x3ffff000, CR3=0x68000)`
   (`khv_startup_mp`: RAX=id, RBX=core, RCX=RIP, RDX=CR3; guards: `core < 16` + one-shot
   bitmap).
5. The AP starts at `0x3ffff000` and never fetches GameOS kernel text, so it never climbs
   to root 1 -> it stays at `cur_npt == 0` (root 0) and runs with HV memory mapped.
6. The AP walks `pcpus[]`, converts VA->PA via `hv_heap_offset`, finds all 16 VMCBs, and
   writes `NESTED_CTRL = 0x8` (clear bit 0 NP_ENABLE, keep bit 3 GMET).

## Known offsets (from the write-up)

| thing | 10.00 (proven) | 13.60 (static) |
|---|---|---|
| `hv_heap_offset` | `0x2a048` | `0x2a028` |
| `pcpus[].m_vmcb` | `+0xa8` | `+0xa8` (unchanged) |
| `pcpus[].core_id` | `+0x138` | `+0x138` (unchanged) |
| `vcore_t.cur_npt` | `+0xe8` | — |
| HCALL `0x0f` handler | `0x105B0` (`hypercall.cpp:446`) | dispatches via table @ inner `0x183e8` |
| BSP root-1 promotion | inner `0x0150d6` (writes `cur_npt=1`) | — |

VMCB (one page each, `sizeof(vmcb_t)=0x1000`):

| field | offset | value |
|---|---|---|
| `NESTED_CTRL` | `+0x90` | `9` (NP_ENABLE \| GMET) -> write `0x8` to clear NP |
| `NESTED_CR3` | `+0xb0` | active nested page table root |
| `Control2` | `+0xb8` | `1` |

VMCB physical = `pcpu[core].m_vmcb - hv_heap_offset` (the same conversion
`virtualmachine_loop` uses for VMLOAD/VMRUN/VMSAVE).

## What still needs deriving on 13.60

Offline dump reality (2026-10-08): the ktext dumps are XOM-scrambled (not code), the hv_dump
is ciphertext/pointers (0/312 clusters are genuine code), and `.data` has no
`acpi_sleep_machdep` pointer. So the offsets come from the write-up's static notes, not our
dumps.

Per the write-up, the 13.60 port needs exactly these, and the write-up publishes only one:

1. **`hv_heap_offset` = `0x2a028`** (moved from `0x2a048` on 10.00). Known — the only offset
   the write-up actually gives.
2. **`pcpus[]` base — REQUIRED.** The payload walks `pcpus[]` directly (`pcpu[core].m_vmcb`
   at `+0xa8`, `core_id` at `+0x138`; both strides unchanged). The *base* VA is the inner-HV
   global the write-up does NOT publish ("derive its aliases dynamically") — it is not
   bypassable.
3. **`acpi_sleep_machdep` offset — AVOIDABLE.** The `#DB` at `acpi_sleep_machdep+0x18e`
   (Sonic-Iso's timing) can be replaced by the public ≤6.02 **#GP-via-ACPI-FACS** trigger
   (see the "Public reference" section below). Both need 13.60 kernel offsets, but the FACS
   path goes through a `.data` global pointer rather than a static text function — more
   likely recoverable from `kdata_1360`.

VMCB addresses are derived at runtime: `VMCB phys = pcpu[core].m_vmcb − hv_heap_offset`.
Do NOT hardcode them (allocation geometry differs).

## Public reference (≤6.02) — `ps5-linux-loader/hv_defeat_0506.c`

The public ≤6.02 HV defeat confirms the strike and gives a portable resume trigger:

- **Strike confirmed**: writes `NESTED_CTRL_GMET_ENABLE = 0x8` to `VMCB+0x90` on all 16 cores.
- **VMCB stride confirmed**: `0x62a08000` (05xx) / `0x62a57000` (06xx) at `core * 0x2000` —
  so VMCBs sit 0x2000 apart (`sizeof(vmcb_t)=0x1000`, one page gap). Matches the write-up's
  `0x62a57000…0x62a75000` span.
- **Resume trigger (portable)**: `kwrite64(ACPIGBL_FACS, ACPIGBL_FACS - 8)` — corrupt the
  ACPI FACS waking-vector so resume raises `#GP`, which runs a ROP chain off the IDT/TSS
  (`IDT_GP`, `COMMON_TSS.tss_ist6`). Replace the ROP body with `HCALL 0x0f(...)`.
- **Offsets needed** (all 13.60): `ACPIGBL_FACS`, `IDT`, `COMMON_TSS`, and the `GAD_*`
  gadgets. `ACPIGBL_FACS` is a `.data` global (recoverable from `kdata_1360`); the gadgets
  are text (XOM — not in dumps). The public `offset_list` stops at 7.61 (`off_0761`).

## AP payload (root-0, position-independent, 4 KiB)

Pseudo (runs with root-0 identity mapping, no libc):

```text
// hv_heap_offset = 0x2a028 (13.60); pcpus base = <derive>
for core in 0..15:
    vmcb_va = read(pcpus + core*sizeof(pcpus_t) + 0xa8)      // m_vmcb (VA)
    vmcb_pa = vmcb_va - hv_heap_offset                        // VA -> PA
    // sanity: NESTED_CTRL@+0x90 == 9, Control2@+0xb8 == 1, NESTED_CR3@+0xb0 aligned+nonzero
    if not (ctrl==9 and ctrl2==1 and cr3_aligned(cr3)): continue
    write(vmcb_pa + 0x90, 0x8)                                // clear NP_ENABLE
    if read(vmcb_pa + 0x90) != 0x8: fail(core)
emit success marker only after all 16 verify
```

The write-up's proof used the *inert* `+0x100` for write/read-back/restore; the real strike
targets `+0x90` (NESTED_CTRL). `+0x100` is the safe dry-run before flipping the live field.

## Build/verify order

1. **Dry-run first**: replicate the write-up exactly — walk `pcpus[]`, validate all 16 VMCBs
   (`NESTED_CTRL==9`, `Control2==1`, aligned nonzero `NESTED_CR3`), write/read-back/restore
   the inert `+0x100`. This proves root-0 reach + the VA->PA conversion without touching the
   boundary.
2. **Then strike**: change the write to `NESTED_CTRL = 0x8` and drop the restore.
3. Validate post-strike: guest physical reads no longer fault on HV-band addresses; VMRUN
   continues (GMET still on).

## Risks

- Wrong `hv_heap_offset` or `pcpus[]` base -> the AP writes garbage physical addresses ->
  likely a clean panic (recoverable: cold boot + re-JB). Derive, never guess.
- Flipping `NESTED_CTRL` live is the point of no return for that boot; keep GMET (bit 3) on.
