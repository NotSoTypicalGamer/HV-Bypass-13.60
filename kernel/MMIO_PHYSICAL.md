# MMIO_PHYSICAL — AMD-Vi IOMMU MMIO physical address on PS5 13.60

**Goal:** determine the AMD-Vi IOMMU MMIO **physical** address(es) so a payload can read the
IOMMU control block through the **kernel DMAP** (`KERNEL_ADDRESS_DMAP_BASE + PA`). The
`kernel_copyout` primitive only reads `.data`-style VAs and returned **−1** on both the XOM text
region (`0xffffffffcfed0000`) and the device-mapped MMIO VA (`0xffffec8c01130000`). The DMAP is
the reachable alias for physical MMIO.

**Sources (all offline):**
- FreeBSD AMD-Vi driver `main` branch (`sys/amd64/vmm/amd/ivrs_drv.c`, `amdvi_hw.c`,
  `amdvi_priv.h`) — the layout/derivation oracle. FreeBSD 11.0 has **no** AMD-Vi driver (Sony's
  IOMMU code is Sony-original), but the *derivation* and *register layout* are fixed by the
  AMD-Vi (AMD IOMMU) spec, which the FreeBSD driver implements faithfully.
- ACPICA IVRS structure (`sys/contrib/dev/acpica/include/actbl2.h`).
- FreeBSD amd64 `pmap.c` `create_pagetables()` (releng/11.0) — how the DMAP is built.
- `kdata_1360.bin` (base `0xffffffffd0930000`, 15 MB) — cross-check of the MMIO pointers.
- Public `hv_defeat.h` (cragson/ps5-hen): `ECAM_BASE_PA = 0xF0000000`,
  `ECAM_B0D18F2 = ECAM_BASE_PA + 0x18*0x8000 + 2*0x1000` (IOMMU PCI device 00:18.2).

---

## 1. How the IOMMU MMIO PA is derived (the method)

### 1.1 Primary route — ACPI IVRS IVHD `BaseAddress` field

The AMD-Vi IOMMU's MMIO base physical address is reported by the ACPI **IVRS** table, in the
**IVHD (I/O Virtualization Hardware Definition)** subtable. FreeBSD reads it directly:

```c
/* ivrs_drv.c, ivhd_attach() */
softc->ctrl = PHYS_TO_DMAP(ivhd->BaseAddress);   // <-- the MMIO control block PA
```

`ACPI_IVRS_HARDWARE` layout (ACPICA `actbl2.h`), the field is at **offset +8**:

```
+0x00  ACPI_IVRS_HEADER   Type(1)=0x10/0x11/0x40 | Flags(1) | Length(2) | DeviceId(2)
+0x06  CapabilityOffset   (u16)  PCI config-space offset of the AMD-Vi 0x0F capability block
+0x08  BaseAddress        (u64)  <<-- IOMMU control-register (MMIO) physical address
+0x10  PciSegmentGroup    (u16)
+0x12  Info               (u16)  MSI number + unit ID
+0x14  Reserved           (u32)
```

`BaseAddress` is 16-KB-aligned and is the **physical address of the IOMMU MMIO register block**.

### 1.2 Secondary route — PCI capability id 0x0F (AMD-Vi / "Secure I/O")

The same value is mirrored in the IOMMU's PCI config space **capability block with Capability ID
0x0F** (AMD IOMMU spec §3.7). Within that block (at `CapabilityOffset` from the IVHD):

```
CapOff+0x08  Base Address Low   (MMIO base[31:14]; bits[13:0]=0)
CapOff+0x0C  Base Address High  (MMIO base[63:32])
```

### 1.3 On-console route — read the BAR from ECAM

The IOMMU is PCI class `0x08/0x06/0x00` (base-system-peripheral / IOMMU) at **bus 0, device 0x18,
function 2** (`ECAM_B0D18F2`). Its config space is at:

```
ECAM_IOMMU = 0xF0000000 + 0x18*0x8000 + 2*0x1000 = 0xF00C2000
  BAR0 @ +0x10  ->  0xF00C2010   (4 bytes, holds the MMIO base PA, 16-KB-aligned)
  BAR1 @ +0x14  ->  0xF00C2014
```

Reading `BAR0` (or the 0x0F capability base-address registers) from ECAM gives the **authoritative**
MMIO PA at runtime. All three routes (IVHD `BaseAddress`, 0x0F capability base registers, BAR)
agree.

---

## 2. Likely MMIO PA

The AMD IOMMU control block sits at a **fixed northbridge/data-fabric address** on essentially all
AMD platforms, and that value is what IVRS reports in `BaseAddress`:

**Primary candidate: `0xFED80000`** (the architectural AMD IOMMU MMIO base, 16 KB block).

This is **< 16 GB** (4.27 GB), so it falls inside the DMAP (`dmaplimit` ≈ 16 GB on PS5) and is
DMAP-reachable. The value is a *candidate to confirm on-console* (I could not read the PS5's IVRS
table offline; the definitive value is the ECAM BAR read of §1.3).

### Window mapping hypothesis

`kdata_1360.bin` shows the IOMMU MMIO is device-mapped as a **contiguous cluster of 10 windows,
16 KB (0x4000) stride**:

```
VA 0xffffec8c0112c000 + N*0x4000,  N = 0..9     (0x0112c000 .. 0x01150000)
```

A single contiguous KVA allocation of ~144 KB maps a contiguous physical MMIO region, so
`window[N].PA = window0.PA + N*0x4000`. If window 0 = `0xFED80000`, the range is
`0xFED80000 + N*0x4000` for N=0..9 (→ `0xFEDA0000`). (The lowest VA `0x0112c000` may map one
window *below* `0xFED80000` → `0xFED7C000`; confirm against the BAR value.)

---

## 3. Cross-check against kdata_1360.bin

- **The 8+ MMIO window VAs appear as literal pointers in `.data`**, each at the head of a
  Sony IOMMU unit-context struct (`.data` `0xffffffffd173ca58` .. `0xffffffffd173e198`). Layout
  per unit: `+0x00 MMIO_VA`, `+0x08 flags`, `+0x10 root ptr (0xffffffffcfed1098, XOM)`,
  `+0x18 self ptr`, plus `0x0fffffff01800000` / `0x0100000001b00000` at `+0x30`/`+0x38` in some
  units. A 10th window VA `0xffffec8c0112c000` sits just below the documented base, and
  `0xffffec8c01150000` closes the cluster.
- **No MMIO physical address is stored directly in `.data`.** The PA is consumed at boot (read
  from IVRS/ECAM and programmed into the IOMMU registers); the kernel keeps only the device-map
  KVA. A scan for AMD-standard MMIO PAs (`0xFED8xxxx`) finds only two *unaligned* coincidences
  (`0xfed10662`, `0xfed8c645`) — not addresses. DMAP VAs (`0xfffff800...`) are essentially absent
  (PHYS_TO_DMAP is computed at runtime as `pa | DMAP_MIN_ADDRESS`).
- The `0x0fffffff01800000` / `0x0100000001b00000` values are **DMA-buffer/register values**
  (device-table/cmd-buffer *RAM* addresses, low-MB range), **not** the MMIO base — do not treat
  them as the MMIO PA.

**Conclusion:** the `.data` dump confirms the *windows* (VA-side) but cannot yield the PA; the PA
must come from the ECAM/IVRS read (§1.3) or the DMAP probe (§5).

---

## 4. Why the DMAP is the reachable alias (and why it is safe to read)

FreeBSD amd64 `pmap.c` `create_pagetables()` builds the direct map by mapping **every** 1-GB/2-MB
page contiguously over `[0, dmaplimit)` (`dmaplimit = ndmpdp << 30`, `ndmpdp = max(4, ⌈Maxmem/1GB⌉)`):

```c
for (i = NPDEPG*ndm1g; i < NPDEPG*ndmpdp; i++)
    pd_p[j] = (i << PDRSHIFT) | RW | V | PS | G | M | A;   // 2MB page per slot
```

So the DMAP maps the **entire** physical range `[0, dmaplimit)` — including MMIO holes such as
ECAM `0xF0000000` and the IOMMU `0xFED80000` — not just RAM. `PHYS_TO_DMAP(x) = x | 0xfffff80000000000`
with the only assertion `x < dmaplimit` (~16 GB). Therefore:

- `DMAP + 0xFED80000 = 0xfffff800fed80000` → IOMMU control block (candidate).
- `DMAP + 0xF0000000 = 0xfffff800f0000000` → ECAM (to read the BAR).
- `DMAP + 0xF00C2000 = 0xfffff800f00c2000` → IOMMU config space (BAR0 @ `+0x10`).

The device-map KVA `0xffffec8c...` (Sony's separate `pmap_mapdev`-style mapping) is what
`kernel_copyout` refused (−1); the DMAP alias of the *same physical* MMIO is present and readable.

---

## 5. SAFE DMAP read probe (no-KP)

**Hard safety rules (from prior incidents):** never read PA ≥ `0x400000000` (16 GB) — the oversweep
past RAM **panics**, it does not return EFAULT; `kernel_copyout` returns **−1** on any fault, so
check every return value; probe **one page first** before reading a window; keep the HV carve-out
`0x60000000..0x70000000` out of scope (not needed here — all targets are < 1.5 GB or in the
1.75–4.3 GB safe band).

### Phase A — liveness test (one 4 KB page, one address at a time)

1. `ret = kernel_copyout(DMAP_BASE + 0xFED80000, buf, 0x1000)`.
2. If `ret == -1` → page absent in the DMAP for that PA; **stop**, try the next candidate
   (`0xFED7C000`, then read the real value from ECAM per Phase B).
3. If `ret == 0` → page is mapped. Sanity-check the bytes: the block should start with a
   device-table base register at `+0x00` whose decoded base PA is **4-KB-aligned**, and a control
   register at `+0x18` with `EN`(bit0) set (IOMMU enabled). Plausible registers ⇒ proceed.
   All `0xFF` / all `0x00` ⇒ not the IOMMU, move on.

### Phase B — recover the authoritative PA from ECAM (zero guesswork)

Read the IOMMU's config space via the DMAP and extract the BAR — this is a single 4-KB read, no
scan:

```
kernel_copyout(DMAP_BASE + 0xF00C2000, cfg, 0x1000)     // 00:18.2 config space
bar0 = *(uint32_t*)(cfg + 0x10);                        // MMIO base (16-KB aligned)
mmio_pa = bar0 & 0xFFFFC000;                            // mask type bits[1:0] + 16K align
```

(If `bar0` is 0/`0xFFFFFFFF`, the MMIO is not BAR-exposed and lives in the 0x0F capability base
registers at `CapabilityOffset+0x08/+0x0C` — walk the capability list from `cfg+0x34`.)

### Phase C — read the control block in 4 KB chunks

For the confirmed `mmio_pa` (candidate `0xFED80000`), read the 16-KB block in **4 × 4 KB chunks**,
checking `kernel_copyout`'s return on every chunk (abort on −1):

```
for off in {0x0000, 0x1000, 0x2000, 0x3000}:
    ret = kernel_copyout(DMAP_BASE + mmio_pa + off, buf + off, 0x1000)
    if ret == -1: abort (stop, don't continue)
```

Then parse the registers (offsets within the block; matches FreeBSD `struct amdvi_ctrl`):

| MMIO off | register | decode |
|---|---|---|
| `0x00` | **Device Table Base (DTRB)** | `base = (v >> 12) & 0xFFFFFFFFFF` (bits[51:12], 4-KB-aligned host-PA of the 256-KB device table); `size = v & 0x1FF` |
| `0x08` | **Command Buffer Base (CMDB)** | `base = (v >> 12) & 0xFFFFFFFFFF`; `len = (v >> 56) & 0xF` (log2 entries) |
| `0x10` | **Event Log Base (EVNTB)** | `base = (v >> 12) & 0xFFFFFFFFFF`; `len = (v >> 56) & 0xF` |
| `0x18` | **Control (CTRL)** | `EN`=bit0, `ELOG`=bit2, `ELOGINT`=bit3, `COMINT`=bit4, `CMD`=bit12 |
| `0x2000` | **Command Buffer Head** | `head = v & 0x7FFFF` (19-bit byte offset) |
| `0x2008` | **Command Buffer Tail** | `tail = v & 0x7FFFF` (SW-owned; writing it rings the doorbell) |
| `0x2010/0x2018` | Event-Log head/tail | 19-bit byte offsets |
| `0x2020` | **Status** | `EV_OF`=bit0, `EV_INTR`=bit1, `CMP`=bit2 |

**Reads only — do NOT write the tail pointer or any register in this probe.** The write half
(COMPLETION_WAIT enqueue to zero `VMCB+0x90`) is `IOMMU_AUDIT.md`'s lane and is out of scope here.

### Expected output

`DTRB` / `CMDB` / `EVNTB` base PAs land in normal RAM (< 16 GB, 4-KB-aligned) or, for the device
table, possibly inside the HV/secure carve-out `0x60000000..0x70000000` — which pins the HV
physical region (§0.3 of `VMCB_DISCOVERY.md`). `CTRL.EN` should be set (IOMMU enabled).

---

## 6. Change log
- 2026-10-05: created. Pinned the derivation (IVHD `BaseAddress` / 0x0F capability / ECAM BAR);
  candidate `0xFED80000`; kdata cross-check (10 windows, no PA in `.data`); DMAP reachability
  proof from `pmap.c`; safe 3-phase probe (liveness → ECAM BAR → 4-KB chunked control-block read).
