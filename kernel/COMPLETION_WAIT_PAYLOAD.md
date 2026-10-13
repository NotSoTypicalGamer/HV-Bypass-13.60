# COMPLETION_WAIT_PAYLOAD — AMD-Vi COMPLETION_WAIT write primitive (probe82 / compwait.elf)

**Payload:** `scratch/ps5/probe82/compwait.elf` (C, ps5-payload-sdk v0.43, prospero-clang). **Status:** builds clean; NOT yet run on-console.
**Config:** `/data/compwait.txt` — three host-physical addresses (hex, whitespace-separated, optional `0x`):
`target_PA`, `cmd_buf_PA`, `mmio_base_PA`. **Log:** `/data/kex_compwait.txt` + stdout, O_SYNC.

This payload is the **write half** of the NPT-disable sequence: it uses the AMD-Vi IOMMU to
perform an *unchecked 8-byte physical store of `0`* to `VMCB+0x90`, clearing NP_ENABLE (bit 0) and
GMET (bit 3) in one shot (`VMCB_LAYOUT.md` §1–2). The IOMMU engine writes physical memory directly
and is **not** gated by the HV's NPT/SLAT write-protection — that is why it reaches the HV's
carve-out VMCB where a CPU-side `kernel_setlong` would panic (`COMPLETION_WAIT_PLAN.md`).

It is **read-only until a valid config is present**: with no (or an unparseable)
`/data/compwait.txt` it logs and exits without touching any MMIO or the command buffer. **No
address is hard-coded** — the three addresses are supplied at run time.

---

## 1. Exact command encoding (pinned against FreeBSD amdvi_hw.c / amdvi_priv.h)

The AMD-Vi **command entry** is 16 bytes = four little-endian dwords. FreeBSD defines it as:

```c
/* amdvi_priv.h */
struct amdvi_cmd {
	uint32_t 	word0;        /* bits [31:0]  -> dword0                       */
	uint32_t 	word1:28;     /* bits [59:32] -> dword1[27:0]                 */
	uint8_t		opcode:4;     /* bits [63:60] -> dword1[31:28] (high nibble)  */
	uint64_t 	addr;         /* bits [127:64]-> dword2 (low) + dword3 (high) */
} __attribute__((__packed__));   /* sizeof == 16 */
```

The driver builds a COMPLETION_WAIT exactly as (`amdvi_hw.c`, `amdvi_cmd_cmp()` — the routine the
queueing path uses; older/split FreeBSD revisions name the queue path `amdvi_queue_cmd`,
the field layout and opcode constants are identical):

```c
cmd->opcode = AMDVI_CMP_WAIT_OPCODE;            /* 0x1                            */
cmd->word0  = (pa & 0xFFFFFFF8) | AMDVI_CMP_WAIT_STORE;   /* S=1, addr[31:3]      */
cmd->word1  = (pa >> 32) & 0xFFFFF;             /* addr[51:32]                    */
cmd->addr   = data;                             /* 64-bit store value             */
```

Folded into the four dwords (the encoding `main.c` emits verbatim):

```
dword0 = (T & 0xFFFFFFF8) | 0x1                    // S=1 (bit0); StoreAddress[31:3]
dword1 = 0x10000000 | ((T >> 32) & 0xFFFFF)        // opcode 0x1 << 28 ; StoreAddress[51:32]
dword2 = 0x00000000                                // StoreData[31:0]  = 0
dword3 = 0x00000000                                // StoreData[63:32] = 0
```

where `T` = the target host-physical address (8-byte aligned). Byte order (little-endian):
`dword0[0..3] dword1[0..3] dword2[0..3] dword3[0..3]`.

### Field decode

| dword / bits | name | value here | meaning |
|---|---|---|---|
| dword0[0] | **S** (Store) | `1` | `AMDVI_CMP_WAIT_STORE` — store StoreData to StoreAddress |
| dword0[1] | **I** (Interrupt) | `0` | completion-wait interrupt |
| dword0[2] | **F** (Flush) | `0` | flush-queue barrier |
| dword0[31:3] | StoreAddress[31:3] | `T[31:3]` | 8-byte-aligned store target (low) |
| dword1[19:0] | StoreAddress[51:32] | `T[51:32]` | store target (high) |
| dword1[31:28] | **Opcode** | `0x1` | `AMDVI_CMP_WAIT_OPCODE` = COMPLETION_WAIT |
| dword2 | StoreData[31:0] | `0` | the 64-bit value written (low) |
| dword3 | StoreData[63:32] | `0` | the value written (high) |

Worked example — historical anchor `VMCB_PA = 0x6290B000` → `T = 0x6290B090`:

```
dword0 = 0x6290B091    dword1 = 0x10000000    dword2 = 0    dword3 = 0
bytes  = 91 B0 90 62 | 00 00 00 10 | 00 00 00 00 | 00 00 00 00
```

### Two facts that are easy to get wrong

1. **Opcode is the *high nibble of the second dword*** (bits[63:60]), *not* the low nibble of the
   first. `0x1` lands as `0x10000000` in dword1.
2. **Opcode `0x1` is COMPLETION_WAIT; `0x5` is INVALIDATE_INTERRUPT_TABLE and writes nothing.**
   (`amdvi_priv.h`: `AMDVI_CMP_WAIT_OPCODE 0x1`, `AMDVI_INVD_INTR_OPCODE 0x5`.) An earlier
   `A53MM_AUDIT.md` note quotes an opcode `0x05` for the COMPLETION_WAIT write — that is wrong;
   do not use it.

### Store semantics (why this works as a write primitive)

FreeBSD's own completion-wait consumer proves it: `amdvi_cmp_wait()` writes a sentinel
`VERIFY = 0xA5A5` to a memory location, enqueues a COMPLETION_WAIT whose StoreAddress is that
location and StoreData is `0xA5A5`, then **polls the location until it reads `0xA5A5` back**
(`amdvi_hw.c:434–460`). With `S=1` the command performs a full **arbitrary 64-bit physical store
of our chosen value** (here `0`) to StoreAddress — not a synthesized "completed" flag. The word
"completion" refers only to the synchronization behavior (the command retires only after all
prior commands complete); the store is an independent side effect we exploit.

---

## 2. Register offsets (struct amdvi_ctrl, CTASSERT-anchored; AMD IOMMU spec §2.5)

All offsets are relative to `mmio_base_PA` (the IOMMU control block; 16-KB stride between
windows, `AMDVI_MMIO_V1_SIZE = 0x4000`).

| offset | register | width | field of interest |
|---|---|---|---|
| `0x08` | Command Buffer Base (CMDB) | 64 | `base[51:12]`, `len[59:56]` = log2(entries) |
| `0x18` | Device Control | 64 | `EN` bit0, `COH` bit10, `CMD` bit12 |
| `0x2000` | Command Head | 19-bit byte offset | HW-owned (consumer) |
| `0x2008` | Command Tail (doorbell) | 19-bit byte offset | SW-owned (producer) |
| `0x2020` | Status | 64 | `CMP` bit2 = completion-wait completed |

Pinned by the `struct amdvi_ctrl` CTASSERTs in `amdvi_priv.h`:
`offsetof(pad1)==0x58`, `pad2==0x2028`, `pad3==0x2040`, i.e. head@0x2000, tail@0x2008,
status@0x2020 — all 8-byte fields after the 0x1FA8 pad.

- **Buffer length:** `blen = (1 << len) * 16`. FreeBSD uses `len = 8` → 256 entries → 4096 bytes.
- **Doorbell:** writing the new tail to `0x2008` **is** the doorbell. There is no separate
  doorbell register on AMD-Vi; the write tells the IOMMU to fetch/execute newly posted commands.
  Increment is a **byte** offset: `new_tail = (tail + 16) % blen` (FreeBSD `MOD_INC(a,s,m) =
  (a+s) % (m*s)` with `s = sizeof(struct amdvi_cmd) = 16`).
- **Access path:** touch MMIO through the **DMAP alias** `DMAP_BASE + pa`
  (`0xfffff80000000000 + pa`), *not* the device-map VA (which `kernel_copyout` returns −1 on).

---

## 3. The write sequence (what probe82 executes)

```
1. parse /data/compwait.txt -> target_PA, cmd_buf_PA, mmio_base_PA   (read-only gate)
2. read CTRL @0x18; require EN (bit0) && CMD (bit12); log COH (bit10)
3. read CMDB @0x08 -> cmdb_base, len, blen;  cross-check cmdb_base == cmd_buf_PA (else ABORT)
4. read head @0x2000, tail @0x2008 (mask 0x7FFFF)
   new_tail = (tail + 16) % blen;  ABORT if new_tail == head (queue full)
5. build entry { (T&0xFFFFFFF8)|1, 0x10000000|((T>>32)&0xFFFFF), 0, 0 }
6. kernel_copyin(entry, DMAP + cmd_buf_PA + tail, 16); read back and verify (else ABORT)
7. clear CMP: read status @0x2020, write back status | CMP (write-1-to-clear)
8. doorbell: kernel_setlong(DMAP + mmio_base_PA + 0x2008, new_tail)
9. poll status @0x2020 for CMP (bit2), up to 2000 × 1 ms
10. best-effort read-back of target_PA (logs "not guest-reachable" for HV carve-out)
```

Every step is logged O_SYNC; the three specifically instrumented steps are the **tail offset
computation**, the **doorbell write**, and the **status poll result**.

---

## 4. Build

```
wsl -e bash -lc 'cd /mnt/c/Users/USER/AppData/Local/kex/cache/scratch/ps5/probe82 && \
  PS5_PAYLOAD_SDK=/mnt/c/Users/USER/AppData/Local/kex/cache/scratch/ps5/sdk_v043/ps5-payload-sdk make'
```

Produces `compwait.elf` (~118 KB). `make` mirrors `probe72`/`probe76` exactly (same Makefile
shape). Deploy via elfldr (TCP 9021) on the etaHEN/Relapse payload chain.

---

## 5. Assumptions / runtime verification flags

1. **MMIO reachability** — `mmio_base_PA` must be readable through the DMAP alias (the probe
   self-checks at step 2/3 and aborts with a clear line if `kernel_copyout` fails).
2. **IOMMU armed** — `CTRL.EN` + `CTRL.CMD` set (self-checked). The HV enables the IOMMU (it is
   central to the isolation model), so both are expected set.
3. **cmd_buf_PA matches CMDB base** — if the parent repointed CMDB to a guest-writable buffer, the
   register base already equals `cmd_buf_PA`. A mismatch means the IOMMU fetches from the register
   base while we wrote the entry elsewhere → the probe **aborts** rather than mis-write.
4. **Coherency** — the on-die AMD-Vi is coherent (`COH` default 1). The probe logs `COH`; only if
   it were clear would a cache flush be needed before the doorbell.
5. **CMP semantics / the I flag** — the Status.CMP (bit 2) is the completion-wait-completed flag.
   Because the entry is enqueued with `I=0`, if a given IOMMU revision only sets CMP for interrupt
   completion-waits, the more robust verification is the **sentinel read-back** (`COMPLETION_WAIT_PLAN.md`
   §7): point StoreAddress at a harmless guest buffer with a non-zero StoreData and read it back,
   before ever targeting the VMCB. The probe logs CMP as the primary result and performs a
   best-effort target read-back as a secondary signal.
6. **Tail race** — the HV's own IOMMU driver is concurrently submitting commands to the same
   buffer; the tail/head read and the entry write are not atomic against it. This is inherent to
   the one-shot primitive and accepted by design (head/tail are logged for visibility).

---

## 6. Change log
- 2026-10-05: created. Encoding, register offsets, and doorbell increment pinned against FreeBSD
  `amdvi_hw.c` (`amdvi_cmd_cmp`, `amdvi_cmp_wait`, `amdvi_update_cmd_tail`, `MOD_INC`) and
  `amdvi_priv.h` (`struct amdvi_cmd`, `struct amdvi_ctrl` CTASSERTs, opcode/flag/status constants);
  store-semantics proven from the driver's `VERIFY = 0xA5A5` polling pattern. Built
  `probe82/compwait.elf` (prospero-clang, clean). Not yet run on-console.
