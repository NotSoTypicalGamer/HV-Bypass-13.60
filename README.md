# PS5 13.60 Hypervisor Bypass

A how-to for defeating the PS5 **13.60** hypervisor, from the primitives (kernel R/W,
GPU-DMA) to the working exploit. Assumes you know what a hypervisor and a syscall are,
but not the PS5 specifics — those are explained inline.

> **Status: CONFIRMED LIVE (2026-10-12).** Byepervisor-Reborn defeated the hypervisor on a
> real 13.60 console. Verified: kernel `.text` reads **plaintext** (xotext/XOM off), `.text`
> is **writable** (`0x41414141` written at `ktext+8` and persisted), and HV memory reads
> **plaintext** ("PS Hypervisor" strings dumped from the carve-out). The console survives in
> this state — next stage is the bring-your-own kernel patches (root, debug settings).

---

## Credits & attribution (who owns what idea)

- **GPU-DMA read/write primitive** — the `/dev/gc` DMA (`PACKET3_DMA_DATA`) + **bit-50**
  victim-leaf retarget that reaches system RAM and bypasses the CPU NPT — **NotSoTypicalGamer**
  (this project's owner). This is the Route B primitive *and* the §3 delivery mechanism.
- **S3-resume `startup_mp` AP-launch bug** (AP cores run in root-0 with an insecure NPT on
  resume) — discovered by **theflow0**.
- **`s3-resume-startup_mp-ap-launch` write-up / Route A recipe** — **Sonic-Iso**.
- **Byepervisor-Reborn** — the working 13.60 exploit that resolves ring-0 exec: the **khook**
  (DR7 hardware-breakpoint → #DB → IST-6 ROP) plus the **`break_hv`** AP payload that clears
  `NP_ENABLE` on all 16 VMCBs — **PS5Dev**.
- **`sysent` hook + `WRMSR(APICBASE)` → NULL-dispatch HV entry** (9.60 technique; source of
  the `sysent` stride-`0x30` correction that fixed our hijack) — **cedsaill3**.
- **Relapse kernel R/W** (`aio_multi_wait` race, syscall 663) — the **Relapse** team.
- **mast1c0re / Luac0re userland entrypoint** — **Gezine** (mast1c0re), Luac0re variant.
- **Single-step kernel text recovery** — **sleirsgoevy**.
- **Analysis, offsets, probes, and this write-up** — **NotSoTypicalGamer**.

---

## 0. The bypass, stated precisely

The hypervisor runs the GameOS kernel as a guest and translates every guest-"physical"
access through its own nested page tables (NPT). Defeating it is **one operation**:

> Write `0x8` to `NESTED_CTRL` (VMCB offset `+0x90`) on all 16 VMCBs.

`NESTED_CTRL` is normally `9` = `NP_ENABLE` (bit 0) | `GMET` (bit 3). Writing `0x8` clears
`NP_ENABLE` and keeps `GMET`. With `NP_ENABLE` off, the HV stops translating guest memory —
the guest is uncontained and can read/write the HV's own memory. That is the win.

Everything below is the path from "we can read/write the kernel" to "we can perform that
one write."

---

## 1. The two routes to that write

### Route A — the AP-launch (deterministic; now fully resolved)

Sonic-Iso's `s3-resume-startup_mp-ap-launch`, the reliable replacement for the stochastic
"lucky boot":

1. **Get ring-0 code execution** — *resolved*: **Byepervisor-Reborn's khook** (a DR7
   hardware execute-breakpoint on the `khv_startup_mp` call site that fires a #DB → IST-6
   ROP chain in ring 0). See §2.
2. Stage a position-independent AP payload at `0x3ffff000` (Byepervisor-Reborn's `break_hv`).
3. Fire **`HCALL 0x0f`** (`khv_startup_mp`): `RAX=0xf, RBX=15 (core), RCX=0x3ffff000
   (AP RIP), RDX=CR3`. The HV launches that AP **in root-0 (host) context**.
4. The AP never fetches GameOS kernel text, so it stays at root 0 with HV memory mapped —
   and reads/writes the VMCBs **in plaintext** (why root-0 matters: the guest can only
   ever see the encrypted-at-rest form).
5. The AP walks `pcpus[]` (HV-side) → `pcpu->vmcb`, and writes `NESTED_CTRL = 0x8` on each.

**Two ways to do step 5.** The original Route A *dropped* the `pcpus[]` dependency and made
the AP payload scan the carve-out (`0x60000000–0x70000000`) for the VMCB field signature
(`NESTED_CTRL==9 @ +0x90`, `Control2==1 @ +0xb8`, page-aligned nonzero `NESTED_CR3 @ +0xb0`).
Byepervisor-Reborn instead resolves the real `pcpus[]` at `HV + 0x82A60` and `pcpu->vmcb`
at `+0xa8` relative to the HV heap — more direct. Either works; the khook + `break_hv` path
is the shipped, verified one.

### Route B — direct GPU-DMA write (no exec; two open questions)

We already hold an arbitrary **system-RAM write** (the GPU-DMA write, §3). If we knew the
VMCB's guest-physical address we could retarget a PTE leaf at `VMCB+0x90` and write `0`
directly — no ring-0 exec, no hypercall. Two blockers:

1. **VMCB guest-PA** — not in the carve-out dump; believed to be in the 1.61–4 GB gap or
   the 32–40 GB region, reachable only on a "lucky boot" (root-0 NPT maps HV memory).
2. **The SME question** — if the VMCB is AES-XTS-encrypted at rest, a raw guest write lands
   plaintext over ciphertext → the HV decrypts garbage → `VMRUN` faults. The carve-out read
   showed a ~2 MB max-entropy block, so whether that block is the VMCB (encrypted) or HV
   code/key (and the VMCB is plaintext elsewhere) is **unresolved**. If the VMCB turns out
   plaintext, Route B collapses to "find the PA".

**Priority:** Route A is the plan (and is now implementable end-to-end); Route B is a cheap
parallel probe that could shortcut it.

---

## 2. Ring-0 code execution — the wall, and how it fell

The hypercall is a CPL-0 instruction (`vmmcall`), and 6.00+ firmware traps attempts to run
any code that wasn't part of the original kernel image (GMET / XOM). For months this was the
single blocking item. **It is now resolved** by **Byepervisor-Reborn's khook** (PS5Dev):

- Hooks the **#DB** IDT gate (vector 1) on core 0 with **IST 6**.
- Arms a **DR7 hardware execute-breakpoint** on the target address (`khv_startup_mp` call
  site, `ktext+0xC16EE0`) using a `resumectx` tail gadget.
- When the target executes, #DB fires → the IST-6 stack runs a **ring-0 ROP chain**
  (`pop rdx` / `pop rcx` / `mov [rcx],rdx` / `rep movsb` …) that rewrites the hypercall's
  `rsi` (AP vector) and `rdx` (CR3) before the hypercall proceeds.

This is a supervisor-state ROP, so it sidesteps SMEP (no user page), CFI (no indirect-call
target change), and XOM (the gadgets live in the already-mapped kernel text). The `#SX`
injection and GPU-DMA-into-`.text` plans below are now historical fallbacks.

### What we ruled out along the way (don't retry)

- **Syscall-table hijack** — panicked twice. Root cause found this session: the `sysent[]`
  `+8` field is **not** a uniform function pointer, *and* the stride is `0x30` (48 B), not
  the `0x18` we first assumed (cedsaill3's correction). Our first hijack wrote a string
  field in the wrong table, on top of SMEP/CFI blocking a userland target. See §5.
- **`.kelf`/kld module load** — 4.03/5.0 only; GMET blocks 6.x+.
- **Resume-`#GP` ROP** — needs to write the IDT `#GP` gate + TSS IST, SME-encrypted on
  13.60. Dead.
- **`wrmsr(MSR_APICBASE)` → `#SX`** — patched at 8.00. (Distinct from cedsaill3's 9.60
  `WRMSR(APICBASE)` → **NULL-dispatch** VMEXIT entry, which is a different bug.)

---

## 3. The primitives we already hold

Everything confirmed working on 13.60; Route A builds on this.

- **Userland exec** — Luac0re (Gezine's mast1c0re variant) via a *Star Wars Racer Revenge*
  (CUSA03474) PS2-emulator save-data bug → remote Lua loader on TCP 9026. `read64`/`write64`
  are userland-only.
- **Kernel read/write** — **Relapse** (the `aio_multi_wait` race, syscall 663) gives
  arbitrary kernel R/W + a `kcall`. **Correction:** that `kcall` (`worker_rop.fcall`) is a
  *ring-3* Web-Worker ROP pivot, not ring-0 exec — it can call kernel functions but cannot
  execute `vmmcall`. Offsets in `kernel/reference/relapse-wak1360/`.
- **GPU-DMA read** — *(NotSoTypicalGamer)* retarget a source PTE leaf (`/dev/gc` ioctl
  `0xC0108102`, `PACKET3_DMA_DATA` opcode `0x50`, **bit-50 set**) and DMA a physical address
  into a staging buffer. **Bypasses the CPU NPT entirely** — it dumped the XOM `.text` and
  read the HV carve-out (the only safe channel into `0x60000000`; a CPU read there panics).
- **GPU-DMA write** — *(NotSoTypicalGamer)* retarget a destination leaf to system RAM:
  `new = (old & ~phys_mask) | (target_phys & phys_mask) | (1ull<<50)`. Confirmed landing in
  kernel `.data`. This is the Route B primitive *and* the §2.1 delivery mechanism.

**Two traps worth memorizing (each cost us a day):**

1. **Bit 50 is the whole ballgame** — without it the `/dev/gc` vmid-6 path is VRAM-only and
   never reaches system RAM. The "vmid 6 = VRAM-only" conclusion was a red herring.
2. **The 80-bit mask truncation** — `0x0000FFFFFFFFFFE00000` as a 64-bit C constant clears
   `IS_PTE` (bit 54) → the 2 MB leaf becomes a table pointer → panic. Correct 2 MB mask is
   `0x0000FFFFFFE00000`. (And the GPU TLB caches `gva→phys`, so allocate a fresh 2 MB victim
   per chunk, not 256 retargets of one leaf.)

**Dumps:** `ktext_0.bin` (40 MB `.text`, plaintext XOM), `kdata_1360.bin` (15 MB `.data`,
`data_base = text + 0xCC0000`, KASLR-slid — always `payload_get_args()->kdata_base_addr`),
`hvdump_0x26000000_600MB.bin` (whole-band HV-alias dump).

---

## 4. The endgame recipe — full detail (Byepervisor-Reborn resolves it)

`HCALL 0x0f` = `khv_startup_mp`: `RAX=0xf`, `RBX=core (use 15)`, `RCX=AP RIP (0x3ffff000)`,
`RDX=CR3`. Guarded by `core < 16` + a one-shot bitmap.

VMCB (one page each, `sizeof=0x1000`, `0x2000` apart):

| field | offset | value |
|---|---|---|
| `NESTED_CTRL` | `+0x90` | `9` → write `0x8` (clear NP_ENABLE, keep GMET) |
| `NESTED_CR3` | `+0xb0` | active nested page-table root |
| `Control2` | `+0xb8` | `1` |
| `VMCB_CLEAN` | `+0xC0` | force reload on next `VMRUN` |

The shipped `break_hv` AP payload does exactly the final strike:

```text
heap = read(dmap + HV_HEAP_BASE)            # HV+0x83028
for core in 0..15:
    pcpu = read(dmap + PCPUS + core*8)      # HV+0x82A60
    if !pcpu: continue
    vmcb = read(dmap + (pcpu - heap) + 0xa8)
    if !vmcb: continue
    vpa  = vmcb - heap
    write(dmap + vpa + 0x90, read(dmap+vpa+0x90) & ~1)   # clear NP_ENABLE
    write32(dmap + vpa + 0xC0, 0)                        # force reload
```

Order of operations: **dry-run first** (validate the 16 signatures and write/read-back the
*inert* `+0x100` field, restore it) → **then strike** (`+0x90 = 0x8`, no restore). Validate
afterward: guest reads of HV-band addresses stop faulting; `VMRUN` continues (GMET still on).

The `khv_startup_mp` trigger fires on **S3 resume** — the payload hooks it, then instructs
"enter rest mode and resume" (needs USB-power-in-rest-mode = Always). On resume the AP runs
`break_hv` and the guest is left with xotext disabled and kernel `.text` writable.

---

## 5. What the `.text` / `sysent` analysis found (this session)

- **`.text` page map** (4 KB pages, `0x0–0xCC0000`): 78.7% plaintext, 17.9% zero, 3.5%
  ciphertext. The core handlers live in the zero/cipher pages.
- **`sysent[]` stride is `0x30` (48 B), not `0x18`** (cedsaill3's correction): `sy_narg`
  u32 @ `+0`, `sy_call` u64 @ `+8`. The real sysent is found at runtime via
  `proc->p_sysent->sv_table`, *not* a fixed kdata offset. Our earlier `+8` reading at stride
  `0x18` produced nonsense (entry 20 → UTF-16 `"ongPress"`, entry 663 → `"iority={2}"`),
  which is why the probe99 syscall-hijack dry-run panicked (it wrote a string field, not a
  handler, in the wrong table).

---

## 6. The dead ends (do not re-derive)

- **COMPLETION_WAIT (IOMMU)** — the guest drives the IOMMU via `hv_iommu_*` hypercalls, not
  raw MMIO; the `0x1130000` window is a RAM alias, not the AMD-Vi.
- **Hypercall-base leak** — `hv_iommu_*` returns only guest-visible state.
- **QA-flags route** — `qa_flags[1]` read `0x03` and setting the SL flag did not clear
  bit-58. Empirically dead.
- **hv_unmap_pt_tmr** — closed at 6.50.
- **NPT "==-guard"** — the bit-56–58 guard looks weak but is internal HV NPT-manager code,
  not guest-reachable.
- **Self-pager / hypercall jump table** — wrong target / ≤2.70 only.

---

## 7. Unknowns, and how each would be resolved

| unknown | decides | how to resolve |
|---|---|---|
| VMCB guest-PA | Route B | lucky boot + GPU-DMA read of the 1.61–4 GB gap |
| VMCB SME-encrypted at rest? | Route B viability | inspect the high-entropy carve-out block for VMCB structure |
| khook stability on 13.60 non-pro vs pro | Route A trigger | run `byepervisor_reborn.elf` on both SOC IDs |

The **lucky-boot trigger itself is unreleased** (Sonic-Iso's root-0-NPT mechanism, ≤14.00,
patched 14.10) — we don't know why the one confirmed readable boot happened, so it stays a
coin flip (~1/12) rather than a lever. The watcher `probe98/hvwatch.elf` catches it.

---

## 8. Reproduce the toolkit

1. **Entrypoint:** SWRR disc → Luac0re save-data → userland exec → Lua loader on 9026.
2. **Kernel R/W:** Relapse (`aio_multi_wait`), offsets from `kernel/reference/relapse-wak1360/13.60.js`.
3. **Ring-0 exec + HV defeat:** build and run **Byepervisor-Reborn** (`byepervisor_reborn.elf`)
   through elfldr; enter rest mode + resume. Offsets: `ACPI_SLEEP_MACHDEP_HOOK=0x3913B0`,
   `HV_MP_STARTUP_CALL=0xC16EE0`, `DATA_CAVE=0x2D39000`, `IDT_ARRAY=0x3BB4300`,
   `COMMON_TSS=0x3BB6FE0`, `HV_SYM_HEAP_BASE=0x83028`, `HV_SYM_PCPUS=0x82A60`; HV base PA
   `0x62800000` (non-pro) / `0x8E0800000` (pro). **Build pitfalls:** after a Windows clone,
   strip CRLF (`sed -i 's/\r$//'` on `*.sh`/`*.c`/`*.h`/`*.S`/`*.ld`/`Makefile` — else
   `build.sh`'s `set -e` dies with "Illegal option -"); build the `break_hv` flat blob
   manually (Ubuntu `xxd` rejects `-i -n name` together — use
   `xxd -i break_hv.bin | sed s/break_hv_bin/break_hv/g > break_hv.h`); then `make` with
   `PS5_PAYLOAD_SDK`. The payload polls forever after "enter sleep and resume" — the
   `Welcome to Hypervisor Bypass - NSTG` toast fires 3 s after resume, on success.
4. **GPU-DMA write:** `/dev/gc` ioctl `0xC0108102`, `PACKET3_DMA_DATA` `0x50`, walk the
   dev-vmid tree for the victim 2 MB leaf, retarget with bit-50, DMA, restore
   (`probe89/vmid7.elf`). *(NotSoTypicalGamer)*
5. **GPU-DMA read:** same, retarget the source leaf (bit-50) → dump `.text` / carve-out.
6. **Lucky-boot watcher:** `probe98/hvwatch.elf` after every JB.

Toolchain: LLVM 23 (`clang -target x86_64-sie-ps5`) + `ps5-payload-sdk` v0.43, libs
`-lkernel -lkernel_sys -lSceLibcInternal -lc`.

---

## Thanks

This research stands on the work of others who shared their findings:

- **theflow0** — for finding the S3-resume `startup_mp` AP-launch bug.
- **Sonic-Iso** — for the `s3-resume-startup_mp-ap-launch` write-up.
- **PS5Dev** — for Byepervisor-Reborn, the working 13.60 exploit.
- **cedsaill3** — for the sysent-hook technique and the `0x30` stride correction.
- **The Relapse team** — for the kernel R/W primitive.
- **Gezine** — for mast1c0re and the userland entrypoint.
- **sleirsgoevy** — for the single-step kernel recovery technique.

---

## Layout

- `kernel/` — findings, one `.md` per investigation (NPT/SME/IOMMU, GPU-DMA, sysent, VMCB).
- `kernel/reference/` — vendored public reference sources (cedsaill3, WAK1360-Relapse, cragson, ps5linux).
- `kernel/hv_dump/` — HV-dump analysis scripts.
- `probes/` — payload/build sources (GPU-DMA, HV scan, watcher, S3 AP-launch).
