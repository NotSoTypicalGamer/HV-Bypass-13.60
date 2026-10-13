# ACPI_POINTERS.md — RSDP / XSDT / FACS / FADT physical addresses in PS5 13.60 kernel `.data`

**Date:** 2026-10-05 · **Input:** `scratch/ps5/kdata_1360.bin` (15,728,640 B = 0xF00000,
base VA `0xffffffffd0930000`, end `0xffffffffd1830000`) + `kernel/hv_dump/` (312 sparse 1 MiB
guest-PA chunks) + `freebsd-src` (releng/11.0). All offline.

## TL;DR (verdict)

**The RSDP physical address is NOT recoverable from `kdata_1360.bin`.** The FreeBSD global that
holds it — `acpi_root_phys` (`static u_long`, `sys/x86/acpica/OsdEnvironment.c:39`) — lives in the
acpi driver's **`.bss`**, and this dump contains **`.rodata` strings + main-kernel `.data` only**,
not the acpi driver's writable state. The same applies to ACPICA's table-pointer globals
(`AcpiGbl_FADT` copy, `AcpiGbl_RSDP`, `AcpiGbl_DSDT`, `AcpiGbl_RootTableList.Tables`), all of which
are `.bss`/malloc'd. No embedded ACPI table (RSDP/XSDT/FADT/IVRS/MCFG/FACS) exists anywhere in the
dump or in the 312 physical-memory chunks. The RSDP PA must be obtained **on-console** (§5), and the
cleanest path is the kernel's own sysctl `machdep.acpi_root` (which *is* `acpi_root_phys`).

---

## 1. The globals that hold ACPI physical addresses (source cross-ref)

| global | type / where | content | in this dump? |
|---|---|---|---|
| `acpi_root_phys` | `static u_long`, `OsdEnvironment.c:39` | **RSDP physical address** | **NO** (`.bss`) |
| `AcpiGbl_RSDP` | `ACPI_TABLE_RSDP *`, ACPICA `tbdata.c` | mapped (DMAP) VA of RSDP | NO (`.bss`) |
| `AcpiGbl_FADT` | `ACPI_TABLE_FADT` struct **copy**, ACPICA | FADT incl. `Facs`/`Dsdt`/`XFacs`@+0x84/`XDsdt`@+0x8C | NO (`.bss`) |
| `AcpiGbl_DSDT` | `ACPI_TABLE_HEADER *`, ACPICA | mapped DSDT VA | NO (`.bss`) |
| `AcpiGbl_RootTableList` | struct, ACPICA `tbdata.c` | `->Tables` = malloc'd array of `ACPI_TABLE_DESC {Address(PA), Pointer, Length, Signature}` | NO (malloc'd heap) |

`acpi_root_phys` is populated by `AcpiOsGetRootPointer()` (`OsdEnvironment.c:90-101`): first the
**`acpi.rsdp` tunable** (`TUNABLE_ULONG_FETCH("acpi.rsdp", …)`), then `resource_long_value("acpi",0,
"rsdp",…)`, then `AcpiFindRootPointer()` (memory scan). Its sysctl is `machdep.acpi_root`
(`SYSCTL_ULONG(_machdep, OID_AUTO, acpi_root, CTLFLAG_RD, &acpi_root_phys, 0, "The physical address
of the RSDP")`). `struct sysctl_oid.oid_arg1` @+0x20 points at `acpi_root_phys`; if that struct were
in the dump we could read the pointer and locate the variable.

### Sony delta (found in the dump)
Sony renamed the driver unit: strings **`nexus_acpi_root`** (VA `0xffffffffd0f5d35d`, off
`0x0062d35d`) and **`root/nexus_acpi`** (VA `0xffffffffd0f5c258`, off `0x005c6258`) are Sony-specific
(absent from releng/11.0). Sony's nexus/acpi path almost certainly reads the RSDP from the
hypervisor/bootloader (via the `acpi.rsdp` tunable or a BIOS-provided table) and stores it in its own
`.bss` — same non-captured situation. The message `"bios acpi entry is too many"` (off `0x005e5864`)
is Sony's custom ACPI table parser.

---

## 2. What `kdata_1360.bin` actually contains

Non-zero-byte density by 1 MiB region (VA `0xffffffffd0930000` + offset):

```
0x0000000 70.6%   0x100000 54.6%   0x200000  0.0%  <- 1 MiB zero hole
0x300000 58.3%   0x400000 88.1%   0x500000 91.2%
0x600000 95.2%   0x700000 80.0%   0x800000 84.6%
0x900000 99.6%   0xa00000 78.2%   0xb00000 68.4%
0xc00000 94.7%   0xd00000 72.5%   0xe00000 84.4%
```

The dense `0x5xxxxx–0x6xxxxx` band is `.rodata` string tables (ACPICA error strings, sysctl
names/descriptions, OEM-ID quirk strings). The dump is `.rodata` + `.data`; the acpi driver's
writable `.data`/`.bss` is absent.

### Signature "hits" are string constants, not tables

Every 4-byte ACPI signature in the dump is a **string literal**, never a table header (a real table
header needs a sane `Length` u32 at +4, `Revision` at +8, printable 6-byte OEMId at +10, 8-byte
OemTableId at +16 — a validated header scan finds **zero** such tables):

| string | off | VA | context (what it actually is) |
|---|---|---|---|
| `RSD PTR ` | `0x00618aed` | `0xffffffffd0f48aed` | `ACPI_SIG_RSDP` constant, followed by unrelated strings |
| `FACP` | `0x0066b147` | `0xffffffffd0f9b147` | string ("FACP\0aq_revcmp…") |
| `FACP  ` | `0x006d361d` | `0xffffffffd100361d` | ACPICA table-name ("FACP  ") |
| `FACS table` | `0x00607f1b` | `0xffffffffd0f37f1b` | ACPICA table-name string |
| `XSDT` | `0x001c73c0` … | `0xffffffffd0af73c0` … | quirk registry entry (below) |
| `RSDT`, `DSDT`, `SSDT`, `MCFG`, `APIC`×65, `HPET`×15, `DMAR`×3, `CRAT`×8 | — | — | all string constants / coincidences |

### The "FADT"/"XSDT" structure @ off `0x001c7360` is ACPICA's quirk table, not a pointer cache

```c
// acpi_quirk.c (releng/11.0): struct acpi_q_rule { char sig[4]; ... }
```
Entries `{ "FADT\0\0\0\0", <ptr to OEM-id string>, <ptr to OEM-table-id string>, 0 }` at 32-byte
stride: e.g. `0x001c7360 "FADT" -> "FUJ000"/"M9D"/"GBT"/"270-EX"`, `0x001c7390 "FADT" -> "FUJ  "/
"SONY "/"XSDT"/"invalid quirk header"`, `0x001c73c0 "XSDT" -> …"SPRINT  "`. These are the OEM-match
strings for `acpi_table_quirks()` (panic string `"invalid quirk header"` = `acpi_quirk.c:168`). They
carry **no physical addresses**.

### No physical addresses of any kind

- **DMAP pointers** (`0xfffff80000000000 … +16 GB`): exactly **1** apparent hit — PA `0x0000fffff700`
  (off `0x00ad2b30`) — which is a **false positive**: it is two adjacent 4-byte entries of an
  interrupt/vector table (`…00 f4 ff ff / 00 f5 ff ff / 00 f6 ff ff / 00 f7 ff ff…` = 0xFFFFF400…
  0xFFFFF800…), read as one u64. No real DMAP VA is stored.
- **Classic-range 16-byte-aligned u64** (`0x80000–0xFFFFF`): only small constants
  (`0x10000`, `0x80000`, `0xa0000`, `0xf4240`=1e6 …), none a plausible RSDP PA.
- **`acpi.rsdp=0x…` / `rsdp=0x…` / `nexus_acpi_root=0x…` environment entries**: **zero** (the
  `acpi.rsdp` string @ `0x006c84d5` is the bare tunable name `"acpi.rsdp\0#14"`, not an env value).
- **Physical dumps (`hv_dump/`, 312 chunks):** `RSD PTR `, `XSDT`, `IVRS`, `FACP`, `MCFG`, `FACS`
  → **zero hits**. (`DSDT`/`SSDT` hits are the same unaligned page-cache coincidences documented in
  `KERNEL_AMDVI.md` — the recurring offsets `0x…5f9c / 0x…ca3a / 0x…2f666` repeat across files at
  different guest PAs, i.e. the same kernel `.data` page captured repeatedly, not ACPI tables.)

---

## 3. Why the acpi driver's state is missing (proof)

Each acpi-driver string in `.rodata` should be referenced by a `.data`/`.bss` struct; **none** has a
back-pointer anywhere in the dump:

| string | purpose | hits | pointers into dump |
|---|---|---|---|
| `acpi_root` | sysctl `machdep.acpi_root` oid_name | 1 (`0x0065fbc4`) | **0** |
| `The physical address of the RSDP` | that sysctl's oid_descr | 1 (`0x005e3595`) | **0** |
| `ACPI global lock` | `mtx_init(&acpi_mutex, …)` name | 1 (`0x00698f72`) | **0** |
| `ACPI I/O ports` / `ACPI I/O memory addresses` | `acpi_rman_io/mem` descr | 1 / 1 | **0** |
| `ACPI root bus` | `ACPI_SERIAL_DECL(acpi,…)` | 1 (`0x0061ba2e`) | **0** |
| `acpi.rsdp` | tunable name | 1 (`0x006c84d5`) | **0** |

→ the `sysctl_oid` struct, `acpi_mutex`, the two `struct rman`s, and `acpi_root_phys` itself are all
outside the captured region. (By contrast, the quirk registry *does* carry string pointers, proving
the pointer scan works.)

---

## 4. Candidate RSDP physical addresses

No credible candidate emerges from the dump itself. Per ACPI spec + ACPICA `AcpiFindRootPointer()`
(`tbxfroot.c`), the RSDP is constrained to these classic x86 locations — these are the only offline
candidates:

- **`0x000E0000 – 0x000FFFFF`** on 16-byte boundaries (`ACPI_HI_RSDP_WINDOW_BASE`/`_SIZE` = 0xE0000/0x20000) — the primary ACPICA scan window.
- **EBDA window** (1 KiB, base read from BDA ptr @ `0x40E`; `ACPI_EBDA_WINDOW_SIZE` = 0x400) — typically `0x0009xxxx`.

(The single DMAP-derived value `0xFFFFF700` was ruled out as a vector-table false positive, §2.)

---

## 5. How to confirm on-console (authoritative, zero guesswork)

**Best — ask the kernel:** the sysctl `machdep.acpi_root` **is** `acpi_root_phys`:

```c
unsigned long rsdp_pa; size_t len = sizeof(rsdp_pa);
sysctlbyname("machdep.acpi_root", &rsdp_pa, &len, NULL, 0);   // -> RSDP physical address
```
`CTLFLAG_RD`, readable from any payload; no memory scanning, no panic risk. (Sony's renamed unit may
also expose `root/nexus_acpi` — try `sysctl -a | grep -i acpi` first.)

**Fallback — replicate ACPICA's scan through the DMAP** (only if the sysctl is absent/blocked):
`kernel_copyout(DMAP + pa, buf, 16)` for `pa` in `0xE0000..0xFFFFF` step 16 (then the EBDA window),
looking for `"RSD PTR "`. DMAP base = `0xfffff80000000000`. Check every `kernel_copyout` return (−1 =
skip; never sweep past ~16 GB).

**Then walk to IVRS** (the actual goal):
1. RSDP `+0x18` = `XsdtPhysicalAddress` (u64) → XSDT PA (or `+0x10` = `RsdtPhysicalAddress` u32).
2. Read XSDT via DMAP; each of the `(Length-36)/8` 64-bit entries = a table PA; find the entry whose
   `+0x00` signature is `"IVRS"`.
3. IVRS `+0x24` (past the 36-byte header + first IVHD header) holds IVHD subtables; the IOMMU MMIO
   base PA is `IVHD.BaseAddress` at IVHD `+0x08` (16-KiB-aligned) — see `MMIO_PHYSICAL.md` §1.1.
   (`0xFED80000` remains the unconfirmed standard-AMD candidate until this read.)

---

## 6. Change log
- 2026-10-05: created. Cross-referenced `acpi_root_phys` (`OsdEnvironment.c`), `AcpiGbl_FADT/RSDP/
  RootTableList` (ACPICA), `struct sysctl_oid` layout, and `acpi_quirk.c`; proved (validated-header
  scan + back-pointer analysis + DMAP/PA scans) that no RSDP/XSDT/FACS/FADT/IVRS physical address is
  stored in `kdata_1360.bin` (acpi `.bss` not captured) nor in the 312 physical chunks; identified
  the `0x001c7360` FADT/XSDT quirk registry and the Sony `nexus_acpi_root`/`root/nexus_acpi` strings;
  gave `sysctl machdep.acpi_root` + DMAP-scan + RSDP→XSDT→IVRS walk as the on-console path.
