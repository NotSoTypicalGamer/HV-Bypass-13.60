# KERNEL_AMDVI.md — AMD-Vi IOMMU MMIO base & command-buffer PA recovery (offline disassembly)

**Date:** 2026-10-05
**Goal:** recover the AMD-Vi IOMMU MMIO **physical base** and the IOMMU **command-buffer
physical address** as the PS5 13.60 guest driver programs them, by disassembling the driver
code dumped at guest-PA ~0x3f800000.

**Verdict (TL;DR): neither PA is recoverable from this dump.**
- The **MMIO base PA** is *read at runtime* from the ACPI **IVRS** table (`ivhd->BaseAddress`,
  mapped with `PHYS_TO_DMAP`), or equivalently from the IOMMU PCI config-space **0x0F capability
  base registers / BAR0**. It is **not** a hard-coded literal in the driver, the **IVRS table is
  not present in the dump**, and the ECAM (0xF0000000) is MMIO (not RAM) so it is not captured
  either. Exhaustive `movabs r64,imm64` scan of all 187 files finds **zero** 4-KiB-aligned
  immediates in the MMIO/ECAM range — only two mask constants (`0xfffffff0`, `0xffffffff`).
- The **command-buffer PA** is computed at runtime by `vtophys(malloc'd buf) >> 12` and written
  solely to the MMIO `cmd.base` register (offset +0x08). It is a page-table-walk result, never a
  literal. Recovering it needs either an MMIO read of the CBRB register or a `pmap_kextract` of the
  buffer KVA — both outside what this memory dump can provide.

---

## 0. Corrections to the task premise (important)

Three statements in the task do not survive contact with the dump bytes:

1. **The contiguous dump does NOT contain the driver at offset `0x19800000`.**
   `hvdump_0x26000000_600MB.bin` is base `0x26000000`, so guest-PA `0x3f800000` = file offset
   `0x19800000`. That region is **all zeroes**. Non-zero spans of the contiguous dump are:
   `0x26000000–0x3aa00000`, `0x3ab00000–0x3ad00000`, `0x3ae00000–0x3f800000`,
   `0x3fe00000–0x40e00000`, `0x41200000–0x48000000`, `0x48100000–0x49a00000`,
   `0x49b00000–0x4c000000` — i.e. `0x3f800000–0x3fe00000` is a 6 MB **zero hole**.
2. **The driver code lives in the sparse chunk `hvcluster_3f800000.bin`** (guest-PA
   `0x3f800000–0x3f900000`), not in the contiguous dump. The same code image also appears
   (identical, byte-for-byte over ≥0x4000) in the contiguous dump at guest-PA `0x3c020000`
   (a −0x38b0000 shift for the `.text` pages) — two captures with the kernel text at different
   physical offsets.
3. **`"IVRSSupportModule"` is a false lead.** The string at guest-PA `0x3f879db5` is the tail of
   `"VshNMSystemShellUIVRSupportModule"` — a **PlayStation VR system-shell UI string** in a
   VSH heap page, not the AMD-Vi driver. There is no real ACPI `"IVRS"` table and no
   `"AMD-Vi"/"amdvi"/"ivhd"/"iommu"` driver string anywhere in the dump (all `"IVRS"` byte hits
   are the same VSH string; all `"DSDT"/"SSDT"` hits are unaligned page-cache coincidences).

---

## 1. Where the driver actually is, and what was disassembled

Sparse chunk `hvcluster_3f800000.bin` (guest-PA `0x3f800000`, 1 MiB) is a **mix** of pages:
kernel code pages (the IOMMU driver DMA code, libc/STL code), and userland/VSH page-cache pages
(`"kex local heap"`, `"mono local heap"`, `sqlite`, Discord/Miranda strings). The IOMMU
driver functions are the code that matches the task's "4 MiB mask" signature
`mov rcx, 0xffffffc00000` (= bits[39:22] set, i.e. 4 MiB granularity):

### 1.1 DMA-address validation — `0x3f8d27c0` (the "0x3f8d27e6" site)

```
0x3f8d27c0  push rbp; mov rbp,rsp; push r15/r14/r13/r12/rbx/rax
0x3f8d27ce  mov  r12, [rsi]                 ; r12 = caller's DMA address
0x3f8d27d1  mov  rax, r12
0x3f8d27d4  shr  rax, 0x30
0x3f8d27d8  cmp  eax, 0xfffd
0x3f8d27dd  jb   0x3f8d28ba                 ; (addr>>48) must be >= 0xfffd (kernel VA band)
0x3f8d27e3  mov  al, 0x30
0x3f8d27e5  movabs rcx, 0xffffffc00000      ; <-- 4 MiB mask
0x3f8d27ef  bzhi  rbx, r12, rax             ; rbx = r12 & ((1<<48)-1)   (PA part)
0x3f8d27f4  mov  rax, [rdi+0x18]            ; rax = unit-context ptr
0x3f8d27f8  and  rcx, r12
0x3f8d27fb  cmp  [rax+0x408], rcx           ; compare vs stored 4MiB-aligned DMA base
0x3f8d2802  je   0x3f8d280c
...
0x3f8d2893  mov  rax, [rdi+0x20]            ; fallback base pointer
```

### 1.2 Same validation, multi-window — `0x3f8d3b20` (the "0x3f8d3b46" site)

```
0x3f8d3b45  movabs rcx, 0xffffffc00000
0x3f8d3b54  mov  rax, [rdi+0x18]
0x3f8d3b58  and  rcx, r12
0x3f8d3b5b  cmp  [rax+0x408], rcx           ; window base #1
0x3f8d3b62  je   ...
0x3f8d3b64  cmp  [rax+0x1ef0], rcx          ; window base #2
0x3f8d3b6b  je   ...
0x3f8d3b70  cmp  [rax+0x1ee0], rcx          ; window base #3
```

### 1.3 Device-table-entry (DTE) construction — `0x3f8a1d00` (the "0x3f8a1db8" site)

```
0x3f8a1d4f  mov  [r13], 0x40000028          ; DTE word0 (V/TV/mode bits)
0x3f8a1d60  movabs rax, 0xe0000000e
0x3f8a1d78  mov  [r13+0x1c], rax            ; domain-id / IOTLB bits
0x3f8a1d7c  mov  [r13+0x24], 0xe            ; domain-id (high)
0x3f8a1db7  movabs r14, 0x1ffffffc00000     ; <-- 4 MiB-aligned PA mask, bit32 set
0x3f8a1dc1  bzhi  r15, rsi, rdi
0x3f8a1dd5  and   r8, 0xffffffffffc00000
0x3f8a1ddc  cmp   rcx, r8                   ; page-table root = [unit+0x6e8] vs DMA addr
```

**Interpretation.** These are the *runtime DMA map/unmap* paths of Sony's IOMMU driver (a port of
FreeBSD `amdvi`). `[rdi+0x18]` points to a **Sony IOMMU unit-context struct** (RAM, not the
standard `struct amdvi_ctrl` MMIO block) holding 4 MiB-aligned **DMA-window base PAs** at offsets
`+0x408`, `+0x440`, `+0x470` (a sub-buffer), `+0x1ee0`, `+0x1ef0`, and a page-table root at
`+0x6e8`. All of those are *runtime* values stored in RAM — none is the MMIO base PA, and none is
a compile-time constant.

---

## 2. FreeBSD amdvi.c cross-reference (how the PAs are really produced)

FreeBSD 11.0 has no AMD-Vi driver; Sony's is a port of the driver that landed later
(`sys/amd64/vmm/amd/{amdvi_hw.c,ivrs_drv.c,amdvi_priv.h}` in the `main` branch; the task's
`sys/dev/amd64/amdvi/` path is the historical pre-move location). The two functions that set the
two values the task asks for:

**MMIO base** — `ivrs_drv.c:ivhd_attach()`:
```c
softc->cap_off = ivhd->CapabilityOffset;      /* PCI 0x0F capability offset from IVHD */
softc->ctrl    = PHYS_TO_DMAP(ivhd->BaseAddress);   /* MMIO control block VA = DMAP + PA */
```
`ivhd->BaseAddress` is the u64 at **+0x08 of the `ACPI_IVRS_HARDWARE` sub-table** inside the ACPI
**IVRS** table; it is the IOMMU MMIO register-block PA (16-KiB-aligned). The same value is
mirrored in the IOMMU PCI config-space **capability id 0x0F** (`CapOff+0x08/+0x0C`) and in BAR0
(ECAM `0xF00C2000+0x10` for B0/D0x18/F2). **The PA is therefore read at boot from ACPI/PCI — it
is never embedded in the driver's code.**

**Command buffer** — `amdvi_hw.c:amdvi_init_cmd()`:
```c
ctrl->cmd.len   = 8;                              /* 256 x 16-byte entries = 4 KiB */
softc->cmd_max  = 1 << ctrl->cmd.len;
softc->cmd      = malloc(sizeof(struct amdvi_cmd) * softc->cmd_max, M_AMDVI, M_WAITOK | M_ZERO);
ctrl->cmd.base  = vtophys(softc->cmd) / PAGE_SIZE; /* <-- PA>>12, written ONLY to MMIO +0x08 */
ctrl->cmd_tail  = 0;                              /* MMIO +0x2008 */
ctrl->cmd_head  = 0;                              /* MMIO +0x2000 */
```
`vtophys()` = `pmap_kextract()` = a **kernel page-table walk**; its result exists only transiently
and is latched into the MMIO command-buffer-base register. The softc retains only the **VA**
(prior `.data` analysis pinned the cmd-buffer KVA at `0xffffffffd31e4000` and the event-log at
`0xffffffffd31e6000`).

---

## 3. Why neither PA is recoverable (evidence)

### 3.1 MMIO base PA — absent
- **No MMIO-range literal.** Exhaustive `movabs r64,imm64` scan (48 B8–BF + 8-byte imm) across all
  186 sparse chunks **and** the 608 MB contiguous dump, restricted to
  `[0xFE000000, 0xFFFFFFFF]`, yields **2** hits, both bit-masks: `0xfffffff0`, `0xffffffff`.
  There is **no** `0xFED80000`/`0xFED7C000`/`0xFED81000`, no ECAM `0xF0000000`, no BAR0
  `0xF00C2010` as a code immediate.
- **No IVRS reference in code.** `AcpiGetTable("IVRS", …)` would embed the 4-byte signature
  `49 56 52 53`; the only `"IVRS"` bytes in the dump are the VSH `"...UIVRSupportModule"` string.
- **No IVRS table in the dump.** No `RSDT`/`XSDT`/`MCFG`/`FACP`/`IVHD` ACPI signatures exist
  either (the `DSDT`/`SSDT` hits are unaligned page-cache coincidences). Without the table, the
  `BaseAddress` field cannot be read offline.
- **The init function is not captured.** Call-graph from the DMA code shows the driver spans
  `0x3f7d0000–0x3f9c0000+`. The parts outside `0x3f800000–0x3f900000` are: `hvcluster_3f600000.bin`
  and `hvcluster_3f700000.bin` are **all-zero** (failed reads), and there is no chunk for
  `0x3f900000–0x3f9c0000` (the `ivhd_attach`/`amdvi_setup_hw` code and the driver `.rodata`).
  The contiguous-dump `.text` copy at `0x3c020000` is byte-identical for the DMA code but its
  `.rodata`/init pages do not map at a fixed shift (the region is interleaved with VSH page-cache
  data), so the init code cannot be recovered there either.

### 3.2 Command-buffer PA — absent
- It is `vtophys(softc->cmd) >> 12` at init time (see §2) — a page-table-walk result, never a
  compile-time constant, and the softc does not retain the PA (only the KVA
  `0xffffffffd31e4000`).
- Recovery would require either (a) reading the MMIO CBRB register `+0x08` (needs the MMIO base PA,
  which §3.1 shows is unavailable), or (b) walking the kernel page tables for KVA
  `0xffffffffd31e4000` (the kernel page tables are not in this dump).

---

## 4. What WAS recovered (useful, but not the two PAs)

- Confirmation the driver is Sony's port of FreeBSD `amdvi`: the 4 MiB `0xffffffc00000` mask, the
  `0xfffd…` kernel-VA-band test, and the DTE word0 `0x40000028` construction all match `amdvi`
  semantics (see `amdvi_priv.h:struct amdvi_dte` / `AMDVI_CMP_WAIT_*`).
- Sony's **IOMMU unit-context struct** layout (RAM): 4 MiB-aligned DMA-window base PAs at
  `+0x408`, `+0x440`, `+0x1ee0`, `+0x1ef0`, a sub-buffer at `+0x470`, page-table root at `+0x6e8`;
  outer context at `[rdi+0x18]` (unit ptr), `[rdi+0x20]` (base ptr), `[rdi+0x28]` (offset dword),
  `[rdi+0x2c]` (flag byte), `[rdi+0x30]` (byte counter).
- Cross-file code-image identity: sparse `0x3f8d0000` ≡ contiguous `0x3c020000` (100% over 0x4000),
  proving the two dumps captured the same kernel text at different guest-PAs.

---

## 5. Next steps to actually obtain the two PAs (outside this dump)

1. **MMIO base PA** — on-console, read ECAM BAR0 via the DMAP:
   `kernel_copyout(DMAP_BASE + 0xF00C2000, cfg, 0x1000); mmio_pa = *(u32*)(cfg+0x10) & 0xFFFFC000;`
   (or walk the 0x0F capability at `cfg+0x34`). Candidate `0xFED80000` (standard AMD) remains
   **unconfirmed**.
2. **Command-buffer PA** — then read the CBRB register: `kernel_copyout(DMAP_BASE + mmio_pa + 0x08,
   8); cmd_buf_pa = (*(u64*)buf >> 12) << 12;` (or `pmap_kextract(0xffffffffd31e4000)`).

---

## 6. Artifacts & change log
- Analysis scripts: `hv_dump/amdvi_scan.py`, `hv_dump/dis_amdvi.py` (capstone 5.0.7).
- Reference source extracted to `kernel/amdvi_src/{amdvi_hw.c,amdvi_priv.h,amdviiommu.c,ivrs_drv.c}`
  from `freebsd-src` `main` (releng/11.0 has no AMD-Vi driver).
- 2026-10-05: created. Corrected the dump-location and `IVRSSupportModule` premises; disassembled
  the 4 MiB-mask DMA/DTE code; cross-referenced `ivhd_attach`/`amdvi_init_cmd`; proved (exhaustive
  movabs scan) that neither the MMIO base PA nor the command-buffer PA is a literal in the dump;
  documented the on-console ECAM-BAR → CBRB recovery path as the only way forward.
