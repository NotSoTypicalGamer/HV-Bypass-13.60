# HANDOFF.md — PS5 kernel KEX + hypervisor research (updated 2026-10-05)

Cross-agent handoff. Two parallel lanes, both on the user's own consoles only. Nothing
published; no exfil; checkpoint before destructive probes. Do NOT re-derive public info
(see PUBLIC_KEX.md, CVE_TRIAGE.md, HV_RESEARCH.md).

## Lane 1 — Kernel KEX that survives 14.00/14.10+ (critical path)
## Lane 2 — Hypervisor defeat on 13.60 (root-0 NPT maps HV memory, patched in 14.10)

## Consoles + access (verified)
- **7.61 (10.0.0.x)** — the DESTRUCTIVE workhorse. etaHEN 0x761. Has 13.60 `PS5UPDATE.PUP`
  staged at `/mnt/usb0/PS5/UPDATE/PS5UPDATE.PUP` (size-matched 1,247,471,104). User will
  update to 13.60 + re-JB with Relapse. FTP 2121 (anon), elfldr 9021, klog 3232.
- **11.60 Pro (10.0.0.x)** — READ-ONLY / non-destructive ONLY. A factory reset could lose
  its Blu-ray drive activation. **Currently kernel-panicked** (my fault — hvscan overswept;
  see below); cold-boot pending, no activation risk from a panic.
- **4.03 (10.0.0.x)** — deprioritized.
- Build/deploy: WSL + ps5-payload-sdk. Two SDKs: 4.03-era at
  `C:\Users\USER\ps5-hv-research\sdk\ps5-payload-sdk`, and **v0.43 (7.61–13.60 offsets) at
  `scratch/ps5/sdk_v043/ps5-payload-sdk`** — use v0.43 for 7.61/11.60/13.60 targets.
- **Capture card** = Guermok HDMI→USB, dshow `"Guermok USB3 Video "` (trailing space).
  Read the panic screen: `ffmpeg -f dshow -i video="Guermok USB3 Video " -frames:v 1 -y out.png`
  (close OBS first — device is exclusive). Panic text → framebuffer, NOT klog.

## Kernel facts (confirmed)
- FreeBSD **11.0-RELEASE** base. Stock syscalls 0–549; Sony adds 550–663+ (incl.
  `aio_multi_wait`=663, `sys_kqueueex`=539). **sysent = 24-byte stride** (record
  `{u32 sy_argsize, pad, sy_call*@8, sy_meta*@16}` — NOT 48; verified via 677 unique
  sy_meta pointers). sy_call canonical text pointers 0xffffffff80xxxxxx.
- **Syscall table stub-status is IDENTICAL across 7.61/11.60/13.60 (0 changes).** The
  earlier "74 changes" (SYSCALL_DIFF_761_1160.md) was a 48-byte-stride artifact — that doc
  is SUPERSEDED; see SYSENT_LAYOUT.md. Sony syscalls 550–676 are all live (~15 reserved stubs).
- Text XOM (hypervisor SLAT bit-58) — kernel_copyout on text returns −1; no clean bypass.
- Data KASLR-slid; always use `payload_get_args()->kdata_base_addr`, never SDK hardcode.
  Kernel .data dumps: `scratch/ps5/kdata_761.bin`, `kdata_1160.bin`, `kdata_1360.bin`.
- Offset table (7.61 / 11.60 / 13.60): KERNEL_DATA 0xC50000 / 0xD30000 / 0xCC0000;
  ALLPROC 0x34A9D50 / 0x35A5D70 / 0x3589E80; VMSPACE p_root=0x1d0, vm_pmap=0x2e8 (stable).

## CRITICAL pitfalls (cost me a console — read before any probe)
- **kernel_copyout / kernel_getlong on a bad or unmapped address = instant PANIC** (all ports
  down). The SDK constants are firmware-specific — use runtime kdata base, verify mapped first.
- **DMAP physical sweeps ALSO panic past the RAM** — the hvscan 32GB sweep killed the 11.60.
  It does NOT return EFAULT on overshoot.
- **Do physical scans in SMALL chunks + merge, not one big sweep** (scene-confirmed). Use
  `probe54/hvdump.elf` (reads `/data/hvdump.txt` `<base_hex> <size_hex>`), dump 256MB–1GB per
  pass, FTP each `.bin` off, concatenate locally. Smaller scans panic far less.
- Risky probes → 7.61 workhorse, NEVER the 11.60 Pro.

## HV lane (Lane 2) — toolchain ready, waiting on 13.60 console
- Lead (Sonic-Iso): root-0 NPT mapped the HV's own physical memory on ≤13.60; patched in 14.10.
  Public HV-defeat methods table in HV_RESEARCH.md (Byepervisor 1.00–4.51; hv_defeat_0304;
  hv_defeat_0506; TheFlow 3.00–6.02+7.61; **8.00–13.60 = unreleased NPT primitive**).
- Tools (all built with v0.43 SDK, scratch/ps5/):
  - `probe53/hvscan.elf` — SVM-instr (VMRUN/STGI/CLGI…) density scanner (needs chunking).
  - `probe54/hvdump.elf` — configurable physical dumper (base+size from `/data/hvdump.txt`).
  - `probe54/dump_chunks.py` — chunked dump-and-merge DRIVER: loops hvdump.elf one chunk at a
    time (default 512 MB), FTPs each `.bin` off, concatenates locally. Run:
    `python3 dump_chunks.py <host> <base_hex> <total_hex> [chunk_mb] [out.bin]`.
  - `probe55/nptwalk.elf` — NPT walker (given VMCB nCR3, logs HV/MMIO mappings >16GB).
  - `probe51` — kernel .data dumper (KERNEL_ADDRESS_DATA_BASE + kernel_copyout).
- Remaining tool: IOMMU write primitive — needs 13.60 kdata for the cmd-queue base/offsets.

## Kernel lane (Lane 1) — leads + tools
- **NEW FINDING (13.60, confirmed 2/2): kqueue filter -18 = deterministic panic.** `kevent(
  EV_ADD, filter=-18)` panics the kernel (unprivileged). Mechanism: `sysfilt_ops[~filt]`
  indexed without a bounds check (stock EVFILT_SYSCOUNT=12; PS5 extends it, but ~(-18)=17
  is still past the end) → garbage for_fop → f_attach call → fault. CWE-125 OOB read →
  uncontrolled indirect call. See KQUEUE_FILTER_PANIC.md. Probes: probe58/kqfilter.elf
  (enumerate all -1..-24), probe59/kqone.elf (single value), probe60/kqident.elf
  (NULL-ident vs pipe-ident discriminator — NOT yet run; needs a console + reset).
- **PRIMARY lead: kqueue/knote UAF** (pipe-close + EVFILT_USER spray). VALIDATED by BillZaiD
  `ps4-kernel-uaf-research-fw1352` (confirmed real on PS4 13.52). Tool: `probe47/kqclose.elf`.
  **ACTION before running: verify PS5 EVFILT_USER value** — PS4 uses **-7 (0xFFF9)**, NOT stock
  FreeBSD -4; if PS5 is also -7 the spray silently fails if coded with -4.
- aio_cancel UAF (`2dde3bed347a`) — tool `probe52`. pgrp UAF (`ef739c7373d8`). IP_OPTIONS
  getsockopt UAF (`e5e3e746fe4a`, reachable but not blindly-triggerable — 4 clean runs).
- `probe48/sysfuzz.elf` — syscall fuzzer (hung at sys 622; needs per-call timeout). 7 syscalls
  accept all 6 malformed-arg patterns: 585,596,599,606,609,617,620. See SYSCALL_FUZZ.md.
- `probe49/ioctlfuzz.elf` — char-device ioctl fuzzer. `probe50/umtxprobe.elf` — UMTX_OP_SHM
  probe (Sony stubbed op 25 at 12.40 — CVE-2024-43102 is PUBLIC, skip).
- `probe56/sockpressure.elf` — Unix-socket pressure primitive (AF_UNIX socketpair flood +
  SCM_RIGHTS fd-passing; reads `/data/spressure.txt` for thread count). Run ALONGSIDE a race
  to widen its window. Built v0.43 SDK.
- `probe57/kqpressure.elf` — the kqueue close-race + socket pressure COMBINED in one payload
  (reads `/data/kqpressure.txt` for pressure-thread count, default 2). The pressure widens the
  race window. Built v0.43 SDK.
- `probe58/kqfilter.elf` — kqueue filter-VALUE enumerator: EV_ADDs candidate values -1..-24 and
  logs which are recognized (EINVAL = unknown). RUN THIS FIRST on the next target to pin the
  real EVFILT_USER value (PS4=-7, FreeBSD-11=-11) before any spray. Built v0.43 SDK.
- `probe48/sysfuzz.elf` — REBUILT with a 2s SIGALRM per-call timeout (fixes the hang at sys 622;
  a blocking syscall now returns EINTR+TIMEOUT and the fuzzer continues through 676).

## New ideas / leads (from user's friends + research)
1. **Unix-socket pressure primitive** — a deterministic bug that drops the kernel into a
   SIGTRAP when pressure is applied to a Unix socket (friend's private find). Value is the
   PRESSURE, not the trap: it widens race windows. Public analog: **CVE-2026-58090 /
   FreeBSD-SA-26:57.unix** — UAF in the Unix SOCK_STREAM receive path (SCM_RIGHTS control
   messages not detached before an error path frees them → freed mbufs in the socket buffer →
   LPE; FreeBSD 15.0+, so the CLASS to audit in PS5's `uipc_usrreq.c`, not the exact bug).
   Build: socket-pair flood (AF_UNIX send/recv + SCM_RIGHTS) running alongside the kqueue/aio
   races to hold the kernel under load.
2. **Chunked dump-and-merge** (above) — unblocks the physical/HV scan without panics.
3. **Entrypoint = SWRR** (Star Wars Racer Revenge CUSA03474) via **Luac0re** (Gezine's
   mast1c0re variant) — PS2-emulator save-data bug, Hall of Fame menu → userland exec.
   Disc-only; PS5 ≥8.00 blocks non-AF_UNIX sockets (no network from the EP).
4. Public kernel exploits for reference (do NOT re-derive): Poopsploit/POOP (1.00–12.00);
   P2JB = `sys_kqueueex`(539) ucred ref-leak UAF (patched 13.00).
5. **UVFAT upcase-table OOB (live on 11.60, patched 13.60).** Sony `sce_exfatfs` driver
   `UVFAT_readupcasetable`/`copyupcasetable` reads an attacker-controlled on-disk exFAT
   upcase-table length, does `roundup(table_len, blsize)` with NO overflow guard → undersized
   malloc → OOB write. The fix string ("roundup overflow") is in 13.60 but ABSENT in 7.61/11.60.
   See UVFAT_AUDIT.md / UVFAT_EXPLOIT_PLAN.md. Target the 11.60 Pro (non-destructive-first —
   Blu-ray risk).
6. **aio_multi_wait (663) race = the Relapse UAF** (0x38 waiter node linked onto ≥2 requests,
   cleanup unlinks only the last and frees it; patched 14.00). 6 race surfaces + deterministic
   thr_suspend_ucontext freeze. See AIO_AUDIT.md. Probe: probe63/aiosrace.elf (built, not deployed).
7. **Second region (0xffffffffcfed0000) holds TMR/psp_mbox/a53mm/IOMMU state but is NOT readable
   via kernel_copyout (returns −1).** 6878 .data pointers into it (dense 128KB header). Access
   path unresolved (slid-vs-canonical alias / XOM). See SECOND_REGION_MAP.md / REGION_ACCESS.md.

## Blocked / waiting
1. 13.60 update + re-JB on 7.61 (user action) → unlocks the HV scan + 13.60 kdata dump.
2. 11.60 Pro cold-boot (user action) — same time as #1.
3. 13.60 raw kernel .data not downloadable — must dump on a 13.60 console (probe51).
4. Kernel text XOM — full disassembly needs single-stepping or decrypted kernel.
5. FreeBSD 11.0 VM testbed — image booted + sshd up, but SSH hostfwd banner exchange is
   broken (times out); needs a QEMU restart with a working file-transfer path before the
   kqueue trigger can be validated in-VM.

## Knowledge base (all in Caliper-C0re/kernel/)
FINDINGS.md · SILENT_FIXES.md · PUBLIC_KEX.md · SONY_SYSCALLS.md · HCI.md · XOM_BYPASS.md ·
ATTACK_SURFACE.md · DEAD_ENDS.md · INSPIRATION.md · VULN_HCI_DMA_READ.md (Marvell — moved to
#marvels thread) · RESEARCH_A53MM.md · RESEARCH_WLAN.md · RESEARCH_HCI_DMA.md ·
SYSCALL_FUZZ.md · SYSCALL_DIFF_761_1160.md · KERNEL_DIFF_761_1160.md · OFFSET_COMPARISON.md ·
CVE_TRIAGE.md · HV_RESEARCH.md · offsets_13.60.js.
Scratch: `C:\Users\USER\AppData\Local\kex\cache\scratch\ps5\` — probe44–probe60,
kdata_761.bin, kdata_1160.bin, kdata_1360.bin (13.60 .data, data_base 0xffffffffd0930000,
sysent @ +0x38), sram_dump.bin, kernel_data.bin, pup/PS5UPDATE.PUP (1,247,471,104),
vm/FreeBSD-11.0.qcow2 + vm/kqrace.c, sdk_v043/, ghidra/.


## NEW LEAD — UVFAT up-case-table roundup overflow (live 7.61/11.60, patched 13.60)
- Sony sce_exfatfs `UVFAT_readupcasetable` rounds attacker-controlled on-disk $UpCase
  DataLength (u64 @ entry offset 24) with `roundup(table_len, blsize)` and NO overflow guard.
  Guard string `"invalid UpCase table length: roundup overflow"` is in kdata_1360.bin only
  (absent 7.61/11.60) -> bug live on older fw, closed 13.60. See UVFAT_AUDIT.md.
- `table_len` in [2^64-blsize+1, 2^64-1] -> roundup2 -> alloc_len=0 -> malloc(0) ->
  UVFAT_copyupcasetable copies table_len bytes -> kmem OOB write/panic. Small-len OOB read:
  table_len=0 (hard), 64/127 (soft leftover in the 128-byte validation).
- Deliverables: `UVFAT_EXPLOIT_PLAN.md` (plan) + `uvfat_upcase_craft.py` (offline exFAT image
  builder, verified parse-back). Built probe images in `scratch/uvfat/`.
- NEXT: (1) SAFE probe on 11.60 Pro ONLY when it's back from its current panic — wrong-checksum
  image, expect `checksum != oldchecksum`/`first 128byte NG` in klog, no panic. (2) Overflow
  trigger on 7.61 workhorse. (3) Resolve copy-length bound (table_len vs FAT-chain) to decide
  DoS-only vs shapable overwrite.


## 2026-10-05 evening — ring-0 routes CLOSED, HV lane narrowed to the NPT alias

- **Ring-0 CODE execution is BLOCKED on 13.60.** The `.kelf`/kld route exists (`buzzer-re/ps5-kld-sdk` + `kldload`, TCP 9022, module at CPL0 via `kproc_create`; recipe in `KELF_BUILD.md`) but is **4.03/5.0 only — GMET blocks 6.x+**. The Guest-Mode Execute Trap (XOM enforcement) blocks allocating/running new kernel code on 6.00+, so `vmmcall` (CPL-0) is unreachable from the ring-3 payload. No `kernel_exec`/`vmmcall` primitive in ps5-payload-sdk v0.43.
- **QA-flags route = NO-GO** (patched on 8.00+; SL-debugger flag `qa_flags[1] bit 1` no longer honored). See `QA_FLAGS_ROUTE.md`.
- **Hypercall wrappers located** (`HV_WRAPPERS.md`): `hv_get_tmr_violation_error`(0xd), `hv_iommu_*`(0x6..0xb), `hv_startup_mp`(0xf), `hv_unmap_pt_tmr`/`hv_restore_pt_tmr`, `deci5s_sdbgp_vmmcall_handler` — but all in XOM text (only their `.data` string VAs are known), so addresses alone are useless without ring-0 exec.
- **CONCLUSION: the ONLY live HV primitive on 13.60 is the NPT alias (data read/write of HV memory through the guest page table) — the Sonic-Iso lead.** GMET does not block data reads/writes.
- **a53mm/a53mmsys/a53io/sbl_secreg/mbus are userland-OPENABLE** (a53mm itself EBUSY=held by kernel driver). ioctl codes UNKNOWN — brute-force (fixed type=61) found 0 live ioctls, all EINVAL/EOPNOTSUPP/ENODEV. TMR dump (`sceSblTmrDumpReg`) likely behind one of these; needs full type×nr×dir fuzz or cdevsw code xrefs (offline). See `probe64/a53query.elf`, `probe49/ioctlfuzz.elf`.
- **DMAP readable range is NOT 16 GB.** A 1.75–12 GB SVM-signature sweep (probe53/hvscan) PANICKED the 13.60 (2026-10-05), despite single 4 GB reads (0xF0000000/0xFED80000) returning ret=0. Guest readable DMAP ends somewhere below 12 GB. **`probe65/liveness.elf` (built, ready) maps the exact edge: 4 KB read at each 512 MB boundary 2–16 GB, logs the boundary BEFORE each read so the last logged line = the edge.** Run it FIRST after any cold-boot, then sweep only inside the confirmed-readable band.
- **Next step:** cold-boot 13.60 → re-JB → run liveness.elf → sweep the confirmed-readable band for dense SVM clusters (the NPT-aliased HV code). The HV host-PA is 0x62806F00/0x6282CBCB (3.00-4.xx); 8.00+ base unknown, hence the alias hunt.


## 2026-10-05 late — fault-page mechanism SOLVED; NPT is per-boot; dump-on-sight scanner ready

- **WHY some guest-PA reads panic:** the NPT entry has 3 states. (1) not-present → carve-out (1.5-1.75GB) → #NPF → HV injects normal #PF → kernel_copyout catches → returns -1. (2) present+xotext bit58 → kernel text → read traps → catchable → -1. (3) present but permission-stripped ("hidden") → the FAULT PAGES → read → #NPF → HV handler treats as fatal → hard panic. The fault band = the HV's protected DATA (VMCB / NPT structures / TMR). The dense SVM clusters = the HV's CODE (readable). Sources: psdevwiki Hypervisor page + AMD NPT semantics + kov.dev NPT deep dive + Byepervisor talk.
- **The NPT is REBUILT PER BOOT.** The HV's guest-visible layout (carve-out top, code-alias position, fault-page positions) moves every cold-boot — DMAP base observed 0xffffcd50../0xffffda2b../0xfffffc95.. across boots, and the same guest-PA reads -1 / data / panic on different boots. So fault-page bisection is futile (no fixed addresses to skip).
- **Right path confirmed:** code readable, data trapped = exactly the Sonic-Iso "root-0 NPT maps the hypervisor's own physical memory" picture. The read trap is why the exploit's WRITE half is the IOMMU COMPLETION_WAIT (writes VMCB+0x90 without reading the trapped page).
- **Strategy change:** stop logging offsets (reset re-rolls them). `probe67/hvscan3.elf` (built) DUMPS each dense 1MB cluster to /data/hvcluster_<off>.bin INLINE the moment it's found, so the HV code is saved before any later fault. On each fresh boot, run it from just above the carve-out (cfg start 0x7000000, end 0x100000000) — a "code-readable" boot (like boot A, clusters at 1.86-1.96GB) gets the HV code dumped before the fault at ~2GB. Then offline: disassemble the dumped code → extract IOMMU MMIO PA + VMCB PA → COMPLETION_WAIT write primitive.
- Dense clusters seen so far (boot A, now stale): 0x77800000 (22 hits), 0x77100000 (6), 0x79f00000/0x7bd00000/0x7d400000 (3 each).

## 2026-10-05 — HV dump analyzed offline; NPT-construction code is NOT in it (HV_NPT_CONSTRUCTION.md)

- Disassembled all 186 hvcluster_*.bin chunks (capstone). Result: the dump is SVM-signature-BIASED —
  it holds only the vmrun run-loop (6 mirrored chunks: 0x3fd00000/0x41000000/0x43d00000/0x45700000/
  0x46100000/0x46400000), the #VMEXIT dispatch (0x2ba00000/0x2d400000/0x2f500000/0x2eb00000/...),
  a VMCB/descriptor builder (0x41001590–0x41001757; movabs 0x8000000000000000 @0x41001665), a bignum
  lib, and 27 all-zero pages. The boot-time NPT constructor + bit-58 (NDA/xotext) decision are
  ABSENT: global scans found 0× `shr {12,21,30,39}`, 0× `and 0x1ff`, 0× `bts 58/63`, 0×
  `movabs 0x0400000000000000`, 0× `mov cr0/cr3/cr4`, 0× PTE-flag writes. readable-vs-trapped is a
  boot-time (not runtime) decision; no guest-writable input gates it (SL QA flag dead on 8.00+).
- NEXT: re-dump WITHOUT the SVM filter (probe54/hvdump.elf over the whole liveness-mapped band) to
  capture the low-density init/page-table code, or read the HV's own NPT pages via VMCB.nCR3.
  Full evidence + offsets in HV_NPT_CONSTRUCTION.md.

## 2026-10-05 (late) — GPU-DMA read/write probes written; blocked on 2 offsets; several lanes closed

- **GPU-DMA primitive (the deterministic path, works on ANY boot — bypasses the per-boot NPT roll):**
  the GPU translates memory via its OWN GPUVM page tables (kernel-managed, guest-controllable), not
  the CPU NPT. WRITE bypasses the fw-6.00 kernel-.data write protection (psdevwiki, "probably
  unpatchable", live 8.00-13.60); READ should likewise bypass the NPT xotext/NDA bit (PTE bit 58)
  to dump the XOM kernel .text/.bss (acpi_root_phys -> RSDP -> IVRS -> IOMMU MMIO base).
  - Payloads WRITTEN: probe73 (READ, gpuread.elf) + probe76 (WRITE verify, gpuwrite.elf), full PM4
    PACKET3_DMA_DATA opcode 0x50 encoding, /dev/gc ioctl 0xC0108102, GPU PDE bits (VALID=0, IS_PTE=54,
    TF=56, BLOCK_FRAG=59, ADDR_MASK=0xFFFFFFFFFFC0). Docs: GPU_DMA_READ.md / GPU_DMA_WRITE.md /
    GPU_DMA_WRITE_PROBE76.md.
  - BLOCKER: two per-fw offsets, both 0x0 and needed to run. ps5-hen (fw <=4.51) values for reference:
    VMSPACE_VM_VMID=0x1E4 (with VMSPACE_VM_PMAP=0x1D0), DATA_BASE_GVMSPACE=0x6202E70,
    gvmspace entry 0x100 bytes, page_dir_va@0x38, start_va@0x08, size@0x10. On 13.60 vmspace->vm_pmap
    is ~0x2E8 (FreeBSD 11.0 growth) so vm_vmid is likely ~0x2F0.
  - MY kdata_1360.bin scan (gvmspace candidates, huge start_va + 4KB-aligned page_dir_va):
    .data off 0x1d2b00 (start_va=0x164000000000, size=0x80000000, +0x38=0x80000000) and
    0x1d3000 (start_va=0x1e4000000000, size=0x40000000, +0x38=0x40000000). NOTE pd==size in both —
    suspicious; the page_dir_va field offset may have shifted on 13.60 (verify before trusting 0x38).
  - FIXED: probe76 used KERNEL_ADDRESS_DATA_BASE (hardcoded, mismatches most boots) — patched to
    payload_get_args()->kdata_base_addr (runtime). Always use the runtime kdata base.

- **IOMMU MMIO base PA still open.** The .data unit-context 'ctrl' VAs (0xffffec8c01130000 + 0x4000
  stride x8) are a DEVICE map, NOT the direct-map: on-console read of the derived PA 0x1130000 via
  DMAP returned all zeros (guest data, not MMIO registers) — negative, no panic. The MMIO base needs
  the device-map base (KASLR) or the RSDP->IVRS chain (via the .bss / GPU-DMA read).

- **kqueue filter=-18 = DoS only (KQUEUE_KEX.md).** sysfilt_ops[17] reads a fixed .data word
  (~28MB past data base, never user-influenced) -> deref/call -> deterministic panic. No leak, no
  controllable write/call. Closed.

- **FIRMWARE_DIFF.md done.** All three .data dumps present (7.61/11.60/13.60). 11.60 vs 13.60 sysent
  BYTE-IDENTICAL (909 entries, same stub map). 7.61 has 8 extra Sony syscall entries at idx 532-539
  (pointing into a 0xc0-strided metadata table), removed in 11.60; shifting 7.61 idx>=541 down by 8
  makes the maps identical. sysent stride 24 bytes.

- **hv_unmap_pt_tmr = dead on 13.60 (HV_UNMAP_PT_TMR.md).** Hypercall still present but the VMCB
  NESTED_CTRL heap-OOB was closed at 6.50 and the 8.00+ HV relocation removed the hvm_shm/vmcb0 anchors.

- **VMCB PA still unknown** — VCPU array is OUTSIDE the dumped range (0x7d00000-0x5ff00000 + 4-16GB);
  the "candidates" 0x204xxx000 were page-frame stacks (decrementing), not VMCBs. Needs the 1.61-4GB
  gap or 32-40GB region, ideally on a "lucky" (code-readable) boot (~1/12 roll). The 2-4GB gap
  boundaries read OK this boot but the 256MB sweep KP'd (trapped pages scattered inside chunks).

- **On-console KP rules added to the ps5-bug-hunting skill:** (1) low guest-PA 0x0-0x7d00000 has a
  trapped firmware page — DMAP scans must START at 0x7d00000, never 0; (2) PCI ECAM is bus-0-ONLY —
  reading bus 1+ faults/panics, and the IOMMU is not a PCI device on bus 0.

- **NEXT:** (a) wait for the GPUVM-offsets agent (deleg_13324824) + IOMMU-MMIO agent (deleg_d49b7ba5);
  (b) patch probe73/probe76 with the resolved offsets, rebuild, deploy on next 'send klog' — fire the
  WRITE test (probe76) first (lower risk), then the READ (probe73) to dump .text/.bss;
  (c) 14.00+ KEX lane = kqueue fd-knote race (PR 293382), agent deleg_8c9ec9b9 in flight.

## 2026-10-05 (night) — kqueue fd-knote race (PR 293382) = PRESENT on 13.60 → 14.00 KEX candidate

- **VULNERABLE.** FreeBSD 11.0 (PS5 base) lacks `fget_noref_unlocked()` (the fix commit 8f3227f5275
  is 2026-03-27, ~9.5 years after releng/11.0). `kqueue_register()` does `fget()` then `KQ_LOCK(kq)`
  with no post-lock re-check. No CVE = silent long-lived fix = ideal 14.00 KEX profile.
- **Race:** thread A `kevent(kq, EV_ADD, EVFILT_READ, fd)` vs thread B `close(fd)`. Window = between
  fget() (refcount bump) and KQ_LOCK(kq); kqueue_expand() (malloc+bcopy, KQEXTENT=256) widens it.
  close()'s knote_fdclose(fd) finds nothing (knote not yet in list) → fdrop leaves f_count 2→1 →
  thread A links a knote whose kn_fp = a file no longer at fd → dangling knote → UAF of struct file.
- **Primitive ladder:** fd-slot reuse + second close → f_detach + fdrop(fp_old) → double-free/UAF of
  struct file; reclaim via KNOTE zone (128B) with EVFILT_USER knotes. Fake knote controls kn_fp
  (+0x60, free sink), kn_fop (+0x68, indirect-call sink), kn_hook (+0x70). → arbitrary free →
  refcount corruption → kernel R/W.
- **probe77 built** (non-destructive win/loss demo, PIPE_EOF side-channel, thr_suspend/thr_resume).
  Deterministic landing needs the kernel toolbox (watchpoint on fget's fd_ofiles load) — NOT in probe77.
- **PITFALL:** PS5 EVFILT_USER = -11 (NOT PS4's -7); a -7 spray silently registers TIMER knotes and
  no-ops the reclaim. kevent(363) is stock; kqueue creation is sys_kqueueex(539), registration unaffected.
- **Speculative/unverified:** Stage 2-3 escalation (fd reuse + KNOTE reclaim) not yet run live; must
  be demonstrated on the 7.61 workhorse first. Sandbox reachability not established. Doc:
  KQUEUE_FD_KNODE_RACE.md. This is a CANDIDATE, not a completed exploit.

## 2026-10-05 (night) — SlopVisor mechanism + DETERMINISTIC TRIGGER candidates + scanner false-positive

- **ROOT0_NPT_TRIGGER.md (KEY):** the 'root-0 NPT maps HV memory' bug = NPT PML4 **entry 0** identity-maps
  low guest RAM (0-512GB) including the HV carve-out (~0.6-0.7GB) unless explicitly carved. The
  readable-vs-trapped split = the AMD NPT **NDA bit (58)**: present+no-bit58 = readable (lucky),
  present+bit58 = trapped (#NPF panic), not-present = carve-out (-1). The 14.10 fix = entry 0 now carves
  the HV region. The SlopVisor trigger is UNRELEASED (no writeup; psdevwiki §13.1 is a stub; only the
  Sonic-Iso tweet).
- **DETERMINISTIC TRIGGER CANDIDATES (the 'way around the coin flip'), in order:**
  1. [TOP] **Rest-mode suspend -> resume -> rescan.** Byepervisor bug #2 = on resume the HV re-runs NPT
     construction while some boot inputs are NOT reinitialized. If 8.00+ has the same asymmetry for the
     own-pages carve-out, EVERY resume leaves the HV pages readable. Probe: cold-boot -> re-JB -> liveness
     -> rest mode -> resume -> re-establish kernel R/W -> hvscan (dump-on-sight). Repeat 3-5 resumes.
  2. [TOP] **First-boot-after-update** = the ONE confirmed readable boot. Reinstall the SAME 13.60 PUP
     (staged at /mnt/usb0/PS5/UPDATE/PS5UPDATE.PUP, 1,247,471,104 bytes) via recovery, then scan; also
     Safe-Mode 'Rebuild Database'. Log the boot MODE with every scan.
  3. [Deterministic, no coin flip] Read IOMMU MMIO DTRB(+0x00)/CBRB(+0x08) -> HV host-PA base. CAVEAT:
     the window read all-zero on a JB'd boot (guest iommudrv uses hv_iommu_* hypercalls, not raw MMIO) —
     must verify liveness first (write-back sentinel). probe84/mmioverify.elf being built for this.
- **CRITICAL — the SVM-density scanner FALSE-POSITIVED:** the >=3 0F 01 D8..DF/MB heuristic caught a
  repeated 16-bit data table (...d2 00 d4 00 d8 00...), so the 'lucky' detection we've been rolling on is
  partly NOISE. The 186-chunk 'HV dump' was guest RAM. FIX (probe83/hvscan4.elf being built): require
  >=2 SVM ops at valid instruction boundaries within <=64B, reject the 2-byte-stride table pattern.
- **VMCB PA: still negative** — VCPU_ARRAY_4_16GB.md found NO VCPU/VMCB-pointer array in the 4-16GB
  dumps either. So the VCPU array is in the un-dumped 1.61-4GB gap (needs a real lucky boot + a reliable
  scanner) or the 32-40GB host-PA region.
- **Overnight agents (8 running):** GPUVM offsets, VMCB 4-16GB (done, negative), root-0 NPT trigger
  (done, this doc), COMPLETION_WAIT payload (probe82), kernel .text map, gvmspace drift, hvscan4
  (probe83), mmioverify (probe84).
- **Morning plan:** fire mmioverify (probe84) first (deterministic MMIO liveness) -> if live, read
  DTRB/CBRB to pin the HV base; else try rest-mode-resume then hvscan4 (fixed scanner) to catch a real
  lucky boot; then GPU-DMA read/write once the offsets land.

## 2026-10-05 (late night) — GPU-DMA offsets RESOLVED + all probes built/staged

- **OFFSET_VMSPACE_VM_VMID = 0x1FC** (confirmed — live vmspace dump shows u32 value 2 @ 0x1FC; the
  <=4.51 0x1E4 + 0x18 shift, NOT +0x8). The earlier 0x1EC was wrong (reads 0xFFFFFFFF).
- **OFFSET_DATA_GVMSPACE = 0x2EEA570** (measured via IDT anchor: idt=0x2EF4300, gap 0x9D90, verified
  across 11.60/12.70/13.60). The gvmspace array is 16 x 0x100 bytes; page_dir_va@0x38 = 0xFFFFFF80A0C98000.
- **probe73/gpuread.elf + probe76/gpuwrite.elf BUILT** with the correct offsets (and the probe76
  data-base bug fixed to payload_get_args()->kdata_base_addr).
- **MORNING CHECKLIST (first 'sk'):**
  1. mmioverify.elf (probe84) — MMIO write-back sentinel -> is the window live?
  2. If live -> read DTRB(+0x00)/CBRB(+0x08) @ DMAP+0x1130000 -> pin HV host-PA base (no coin flip).
  3. If dead -> rest-mode resume -> hvscan4.elf (probe83, fixed scanner) -> catch a real lucky boot,
     dump 0x60000000-0x90000000 for the VCPU array -> VMCB PA.
  4. gpuwrite.elf (probe76) — WRITE test first (lower risk), then gpuread.elf (probe73) -> kernel .text/.bss
     -> acpi_root_phys -> RSDP -> IVRS -> IOMMU MMIO base PA.
  5. compwait.elf (probe82) — once VMCB PA + cmd-buf PA + MMIO base are known, clear VMCB+0x90 bit 0.

## 2026-10-05 (night) — COMPLETION_WAIT DEAD + GPU-DMA walk in progress

- **COMPLETION_WAIT (IOMMU) is DEAD** — mmioverify (probe84) proved the MMIO window at guest-PA
  0x1130000 is a writable RAM alias, NOT the real AMD-Vi: DTRB/CBRB/evlog/ctrl/cmd-head/tail all read
  0, evt_tail/status read random RAM, and a sentinel write to cmd_tail PERSISTED on read-back (a real
  cmd_tail wouldn't hold a written value). The guest's iommudrv drives the IOMMU via hv_iommu_* hypercalls,
  never the raw MMIO. So the doorbell write would just scribble a RAM page — no command fetch. IOMMU write
  primitive abandoned.
- **GPU-DMA write (probe76) — walk fails.** vmid=2 (VMSPACE_VM_VMID=0x1FC CORRECT) + page_dir_va
  (0xffffff8097aa0000) resolve fine, but the PDB2 walk hits a not-VALID PDPT entry for BOTH the CPU VA
  (victim_va=0x200200000) and the phys_out (victim_off=0x2027a00000). So the onion/main-direct-memory
  buffer is NOT mapped in the per-VMID gvmspace (garlic) page tables at either address. The open question:
  is onion even in the gvmspace, or must we allocate GARLIC memory (a different syscall)? Agent
  deleg_52370a43 (GPU_DMA_MEMORY_MODEL.md) is resolving the onion-vs-garlic model + the correct GPU VA.
- **hvscan4 (probe83) is scanning 0x10000000-0x400000000** on the live (unlucky) boot looking for dense
  SVM code at a DIFFERENT guest-PA than the 7 known cluster addresses (the 'root-0 NPT maps HV memory'
  alias may land the HV code at a randomized PA each lucky boot). No hits yet at 0x500MB.
- **Still the strongest levers:** (1) fix the GPU-DMA walk (the write primitive, needed to clear VMCB+0x90
  once the VMCB guest-PA is known); (2) rest-mode-resume / fresh-update boot as the deterministic
  readable trigger; (3) VCPU-array dump -> VMCB PA on a lucky boot.

## 2026-10-05 (late night) — GPU-DMA walk root cause + deterministic fix

- **ROOT CAUSE (GPU_DMA_MEMORY_MODEL.md):** on 13.60 the onion/main-direct-memory buffer is mapped in
  the per-VMID gvmspace at a HUGE 48-bit GPU VA (the direct-memory region table at .data+0x1D2B00 shows
  start_va=0x164000000000, 256GB stride), NOT at the CPU userland VA (0x200200000) and NOT at the
  phys_out bus address (0x2027a00000). The old ps5-hen formula 'GPU VA = victim_va - gvmspace.start_va'
  broke because 13.60's gvmspace.start_va = 0x0 (so it returned the raw CPU VA). ≤7.61 had
  start_va = the direct-memory VA base, which is why the old formula worked there.
- **FIX (patched + built into probe76/gpuwrite.elf):** stop guessing the GPU VA. (1) compute each
  buffer's PHYSICAL via cpu_va_to_pa (4-level x86-64 walk from pmap->pm_cr3; vmspace->vm_pmap inline @
  0x2E8, pm_cr3 @ +0x28); (2) scan the GPU page tables (gpu_scan_leaf_by_pa) for the leaf PTE whose
  ADDR_MASK == that physical, and reconstruct the GPU VA from the 4 index levels; (3) drive the
  PACKET3_DMA_DATA with the recovered GPU VAs. Self-validates (leaf PA == victim PA) and bails cleanly
  if onion is absent from the gvmspace (fallback: allocate GARLIC via sceKernelAllocateDirectMemory).
- probe76/gpuwrite.elf is REBUILT with this fix (console was down from the hvscan4 panic, so it is
  staged for the AM deploy). probe73/gpuread.elf still needs the SAME fix applied (secondary).
- **AM sequence (after the user's reset + 'sk'):** (1) fire mmioverify already done -> IOMMU dead, skip;
  (2) fire gpuwrite.elf (the fixed walk) to verify the GPU-DMA write primitive; (3) if the walk recovers
  the GPU VA, the write primitive is LIVE -> the remaining blocker is only the VMCB guest-PA (rest-mode
  resume / lucky boot); (4) rest-mode resume = enter rest mode, wake, re-establish kernel R/W, rescan
  with hvscan4 for the dense SVM at ANY address (the HV alias is randomized per boot).

## 2026-10-06 (early AM) — hypercall-leak lane CLOSED (negative)

- IOMMU_HYPERCALL_LEAK.md: the hv_iommu_* hypercalls (0x6-0xc) are a PARA-VIRTUALIZED guest-buffer
  interface — the guest allocates its own cmd-buffer/device-table/event-log and registers them via
  SET_GUEST_BUFFERS; every return is guest-visible state (status, head/tail indices, guest-PA DTE
  roots). NONE returns the HV's DTRB/CBRB/EVNTB (the values that live in the carve-out). No deterministic
  HV-base leak. Also: the wrapper "VAs" in HV_WRAPPERS.md are .rodata FORMAT-STRING addresses, not call
  targets — the actual hv_* wrapper functions are in XOM .text and unrecoverable offline.
- One residual (low-prob) probe worth a single cheap test IF a ring-0 vmmcall cave is available: sweep
  vmmcall(0xc READ_DEVICE_TABLE, dev_id 0x0..0xFFFF) and look for a DTE pt_base (q1/q2 low 52 bits,
  4K-aligned) landing in 0x60000000..0x70000000 (carve-out) = the HV's own shadow DTE / TMR device id.
  Closes the shadow-DTE hypothesis; not a plan.
- Remaining deterministic lane unchanged: GPU-DMA write (fixed, staged) + VMCB guest-PA via
  rest-mode-resume / lucky boot.

## 2026-10-06 (AM) — GPU-DMA: DMA copy PASS, retarget KP

- GPU_DMA_PHYS_FIX.md: walk fixed. Garlic physical comes from the LEAF PTE (bits 13-47), NOT
  cpu_va_to_pa (which returns fake 0x47bc00000 > 16GiB for the bus-translated direct-memory VA).
  GPU tree is 5 levels for 8KB leaves. Victim garlic: gpu_va=0xc80000000 phys=0x34c00000 pte_pa=0x13432800.
- KEY: the GPU has MULTIPLE VMIDs (0..6). The victim is mapped in BOTH vmid[2] (garlic VA 0xc80000000)
  AND vmid[6] (the CPU/direct-memory VA 0x200400000 -> phys 0x47bc004c0). Driving the DMA with the
  CPU VA works (vmid[6] maps it). This resolves the onion-vs-garlic / VA confusion: both are valid.
- T0 (baseline PACKET3_DMA_DATA copy staging->dst, no retarget): PASS, sentinel 0xDEADBEEFCAFEBABE
  landed at dst. The DMA copy mechanism is CONFIRMED on 13.60.
- T1 (mprotect drop PROT_GPU_WRITE -> kernel_setlong retarget the victim leaf -> re-enable -> DMA):
  KERNEL PANIC (all ports down). Suspect the retarget PTE value or the mprotect on the direct-memory
  mapping (ps5-linux-loader uses the SAME mprotect sequence, so likely the new_pte/retarget PA).
- NEXT (after reset + re-JB + sk): rebuild the write test WITHOUT the mprotect (or with the ps5-linux-loader
  exact prot_ro/prot_rw sequence), retarget the victim leaf to the STAGING physical (safe), DMA
  victim->cmd, read cmd back for the sentinel. Log every kernel_setlong + the new_pte value before the
  submit. If the retarget PA is the issue, sanity-check the target physical is readable first.

## 2026-10-06 (AM) — GPU-DMA ARBITRARY WRITE CONFIRMED on 13.60 (major milestone)

- GPU_DMA_WRITE_TEST.md: RETARGET PASS. The GPU-DMA arbitrary write primitive WORKS on 13.60:
  sentinel 0xDEADBEEFCAFEBABE landed through a retargeted victim PTE into the staging page, read+write
  directions, no panic. This is the kernel-memory WRITE primitive (GPU bypasses CPU NPT write-protect).
- Root cause of the earlier KP: 80-bit mask literal 0x0000FFFFFFFFFFE00000 truncated to 64 bits by the
  compiler -> cleared IS_PTE bit54 -> GPU treated the 2MB leaf as a table pointer at garbage -> fault.
  Correct 2MB mask = 0x0000FFFFFFE00000 (bits 21-47); 8KB mask = 0x0000FFFFFFFFE000.
- Working sequence (13.60): /dev/gc opens vmid 6 (the 'dev' vmid) where garlic direct-memory buffers map
  at their CPU VAs (not the vmid-2 garlic VA 0xc80000000). Allocate 3x2MB garlic (sceKernelAllocateDirectMemory
  type 0xb + sceKernelMapDirectMemory), walk the dev-vmid tree for the victim 2MB leaf (IS_PTE bit54),
  retarget: new = old & ~0x0000FFFFFFE00000 | target_phys & mask (preserve ALL flag bits incl bit50+IS_PTE),
  kernel_setlong(dmap+pte_pa,new), PACKET3_DMA_DATA (opcode 0x50, ioctl 0xC0108102) src->dst, usleep 500ms,
  restore old. NO mprotect needed.
- PASS values: victim leaf gva=0x200c00000 phys=0x47bc00000 pte_pa=0x13e69030 raw=0x004000047bc004f7;
  retarget->staging 0x004000047be004f7 (phys 0x47be00000).
- NEXT: (1) write to kernel .data (needs kASLR base + a safe padding/bss field offset — the write
  primitive is proven, so pick a target PA and DMA-write it); (2) THE remaining HV-defeat blocker is now
  ONLY the VMCB guest-PA (rest-mode resume / lucky boot). Once we have the VMCB PA, retarget->VMCB+0x90
  bit0=0 disables NPT = HV defeat.

## 2026-10-06 (late AM) — .data write FAIL: /dev/gc is VRAM-only on 13.60

- GPU_DMA_KDATA_WRITE.md: the /dev/gc (vmid 6) DMA primitive is VRAM-ONLY — garlic->garlic retarget
  (T2) PASSES but VRAM->system-RAM (kernel .data) does NOT land (read-back stays 0, no panic). Root cause:
  on 13.60 the direct-memory buffer has TWO mappings: vmid 6 (the /dev/gc 'dev' vmid) maps it at the CPU VA
  -> VRAM phys 0x47bc00000 (>16GiB, garlic), while vmid 2 (the process vmid) maps it at the garlic GPU VA
  0xc80000000 -> SYSTEM-RAM phys 0x33400000 (onion). /dev/gc -> vmid 6 -> VRAM only.
- To reach system RAM (kernel .data / VMCB): MAIN/onion direct memory (sceKernelAllocateMainDirectMemory
  mem_type=1) + process vmid 2 + GNM submission (sceGnmSubmitCommandBuffers), NOT /dev/gc. This is the
  etaHEN/flatz path. Hurdles: GNM driver-init fails in elfldr ('Failed to get trap handler code',
  sceGnmSubmitDone=0x80D4FFFF) + onion leaves lazily populated (~280KB of 2MB). Victim-only GNM variant
  kwrite3.c in probe78/ written, not deployed. Agent deleg_2c4f7313 is resolving the GNM path now.
- NET: GPU-DMA write primitive is VRAM-only so far; system-RAM write (needed for VMCB+0x90) still open.
  The VMCB guest-PA (rest-mode resume) is USELESS without a system-RAM write first — so GNM/system-RAM is
  the critical path, rest-mode resume is secondary.


## 2026-10-06 (late) — GNM/vmid-2 system-RAM path: GNM cannot init in elfldr (BLOCKER, documented)

- GPU_DMA_SYSRAM_WRITE.md written (sysram_write_pass = false). Deployed kwrite3.c (victim-only GNM):
  vmid-2 onion leaves ALL populated (phys0..3 = 0x33400000/0x33402000/0x33404000/0x33406000, so NO
  lazy-population issue for the first 4 leaves), vmid=2 confirmed, retarget PTE write lands. But
  sceGnmSubmitCommandBuffers returns 0 as a SILENT NO-OP: even the within-victim T2 copy fails (got=0).
- Root cause (RE'd libSceGnmDriverForNeoMode.sprx in-memory image, pulled to scratch/ps5/gnm_neo4.bin):
  "Failed to get trap hanlder code" (Sony typo) is printed by the module CONSTRUCTOR, before main().
  Gnm::Initialize() fails at KMD-gated steps -> sets state 0x8eee00ff ("not initialized"):
    - first init step @0x38b5 (KMD client registration, must return 1) -> "Gnm Initialize() error"
    - "Get CU Mask" (@0x3b69, a KMD syscall/IPC) -> "Get CU Mask Fails"
    - "Initialize Embedded Shader" -> "Initialize Embedded Shader Fails"
  Once state=0x8eee00ff: RegisterOwner*/CreateWorkloadStream return 0x8eee00ff, SubmitDone returns
  0x80d110ff, SubmitCommandBuffers silently no-ops. RegisterOwner* is also hard-stubbed (mov eax,0x8eee00ff; ret).
  Trap handler = CWSR microcode (SceGnmTrapCode/SceGnmTrapData/SceGnmCwsr resources, 22MB CWSR @ garlic
  0xc80008000, trap code @ 0xf00000000), allocated by Initialize() via an imported KMD allocator.
- Why references work: flatz BD-JB (sun.awt.GnmUtils.copyPlanesBackgroundToPrimary) + znullptr gpu.lua
  (sceGnmSubmitCommandBuffers) both run in GNM-ALREADY-INITIALIZED processes (BD-J JVM / game / etaHEN),
  so no explicit init needed. elfldr spawns a bare process -> Gnm::Initialize() can't complete.
- NET: GPU-DMA system-RAM write needs a GNM-initialized process context. elfldr payload CANNOT do it
  without reimplementing the KMD client-registration + Get-CU-Mask + CWSR resource-allocation stack.
  Paths forward: (1) run the DMA from a GNM-initialized process (inject into etaHEN/game/BD-J), or
  (2) RE the KMD syscalls (a53mm /dev/a53mm owns GPU MMU) and replicate the registration. The VMCB
  guest-PA write (HV defeat) remains blocked on a system-RAM write primitive.

## 2026-10-06 (noon) — GNM can't init in elfldr: system-RAM write blocked; 2 paths

- GNM_INIT_SEQUENCE.md / FLATZ_GNM_COPY.md / GPUVM_POPULATION.md + GPU_DMA_SYSRAM_WRITE.md (console):
  DEFINITIVE — GNM cannot initialize in the bare elfldr payload process. The 'trap handler code' is the
  AMD GPU trap handler (TBA/TMA), kernel-privileged on RDNA2 (PS5 Oberon); only the KMD can install it.
  Gnm::Initialize() fails at KMD-gated steps (GPU-client registration, Get-CU-Mask, CWSR microcode alloc at
  fixed garlic VAs 0xc80008000), setting the driver-wide error state 0x8eee00ff; RegisterOwner* is stubbed
  to 'mov eax,0x8eee00ff; ret'. After that sceGnmSubmitCommandBuffers is a SILENT NO-OP (returns 0, never
  queues) and sceGnmSubmitDone=0x80d110ff. So the onion/vmid-2 GNM write is UNREACHABLE from elfldr.
- flatz path (extracted, probe79/flatcopy.elf BUILT): onion sceKernelAllocateMainDirectMemory(mem_type=1,
  2MB,2MB) + MapDirectMemory prot 0x33 MAP_NO_COALESCE + process vmid + PACKET3_DMA_DATA (0xC0055002 /
  0xA3006000, src/dst = garlic-window VAs 0xc80000000..) + sceGnmSubmitCommandBuffers/SceGnmSubmitDone.
  The ONLY diff from the working /dev/gc packet is WHO submits and WHICH vmid translates. Runs in game/BD-J.
- Population is fault-driven (lazy 8KB leaves) on 13.60; eager population rides the same broken GNM CS-validate.
- 2 PATHS: (1) game/app entrypoint (PS4-game save-data / BD-J / Y2JB / PS2-emu) where GNM is pre-initialized —
  probe79 is ready to deploy there; (2) /dev/gc vmid regression — on <=12.40 /dev/gc bound the PROCESS vmid 2
  (system RAM reachable), on 13.60 it opens vmid 6 (VRAM-only). Agent deleg_ac15ca1d is reversing the gc driver
  to see if /dev/gc can be made to bind vmid 2 from elfldr (no game needed). If yes -> the existing /dev/gc
  primitive reaches system RAM and the VMCB write is back on.


## 2026-10-06 — WRMSR(APICBASE) resume-#GP probe offsets RESOLVED (13.60, live console)

- Replicating ps5-linux-loader's 6.00-7.61 hv_defeat_0607 delivery (resume #GP -> ring-0 ROP -> wrmsr(MSR_APICBASE)) on 13.60. Live read-only VA dumps via kernel_copyout; no panics.
- Runtime kdata = 0xffffffffcae90000 (brief's 0xffffffffcbc2d000 is STALE; ktext=0xffffffffca1d0000, dmap=0xffffaded00000000 confirmed via FACS ptr 0xffffaded7fd6e000).
- RESOLVED (kdata-relative, verified live): AcpiGbl_FACS = kdata+0x2D09490 (holds dmap+0x7fd6e000, FACS_PA=0x7fd6e000); IDT = kdata+0x2EF4300 (IDT_GP=vec13 handler 0xffffffffca43a358, ist 0); COMMON_TSS = kdata+0x2EF6FE0 = IDT+0x2CE0, TSS stride 0x68 (NOT 0x100), tss_ist6@+0x4C / tss_ist7@+0x54. ACPICA is statically linked into core kernel .bss (FADT copy @ kdata+0x2D09320, DSDT @ +0x2D09460).
- Gadgets NOT recoverable: .text XOM (kernel_copyout AND MemDBG rwpipe both -1); DMAP low 0-0x7d00000 is a panic edge. Needs single-stepping (sleirsgoevy) or a 13.60 text dump. 7.61 link-time gadget offsets recorded as unverified reference.
- Full detail + values: WRMSR_PROBE_OFFSETS.md. Payload: scratch/ps5/wrmsr_dump/ (wrmsr_dump.elf = configurable VA dumper, /data/rdcfg.txt "<base> <size>").

## 2026-10-06 — wrmsr(APICBASE) lane CLOSED (patched 8.00); PS2EMU entry DEAD on 13.60; GNM context = Y2JB + /dev/gc re-bind

- **wrmsr(APICBASE) HV-exec lane CLOSED.** WRMSR_APICBASE_MECHANISM.md: primitive = wrmsr(0x1B, X|0x800|0x100) → HV stores X in vc+0xe8, reflects X into host APIC_BASE MSR, BSP bit → injects #SX (vec 30). psdevwiki §12.1: "Patched ... since PS5 FW 8.00". + 8.00+ HV moved off 0x628xxxxx (get_hv_stack dead) + .text gadgets XOM AND recompiled per fw (OFFSETS_1360_PREDICTION.md: .text slid ~2.75MB, GAD_* not portable). Offsets still resolved for the record (AcpiGbl_FACS=kdata+0x2D09490, IDT=kdata+0x2EF4300, COMMON_TSS=kdata+0x2EF6FE0). Lane CLOSED.
- **PS2EMU (Luac0re/mast1c0re) entrypoint DEAD on 13.60** — user confirmed the Hall-of-Fame save-data does NOT trigger (mast1c0re PS2-emu save bug patched on 13.60). Not a Lua-loader issue.
- **Luac0re LOADER is firmware-independent** (LUACORE_1360_PORT.md): read64/write64 ROP gadgets are EBOOT-relative (SWRR disc binary, never rebuilt), libc/fios offsets + syscall numbers stable 9.xx→13.20. Only TODO = sceKernelDlsym delta -0x450. The "1360 not implemented" = Luac0re's OWN kernel jailbreak (p2jb cr_ref, ≤12.40), which we don't need (Relapse is the KEX).
- **flatz GPU-DMA 13.60 Lua port done** (FLATZ_GPU1360_LUA.md + gpu1360.lua): rebinds flatz gpu.lua to Luac0re API + 13.60 layout (5-level 8KB leaves, onion GPU VA 0xc80000000, vmid 2, masks). Correction: DMA_DATA header = 0x8C00C000 (NOT 0xA3006000). One hard seam: Luac0re read64/write64 are USERLAND-only — the GPU walk/PTE-retarget needs the Relapse kernel R/W wired in (func_wrap kernel_copyout stub, or JB-daemon socket).
- **CURRENT LANES (agents in flight):** (1) /dev/gc vmid re-bind (DEVGC_VMID_REBIND.md) — why vmid 6 (VRAM-only) and whether it can bind vmid 2 / inject system pages (GPUVM can mix VRAM+system pages, so VRAM-only is driver behavior); (2) Y2JB (Y2JB_GPU_DMA_1360.md) — the YouTube V8 GNM context + its shipped p2jb GPU-DMA .data write.

## 2026-10-06 (evening) — Luac0re remote_lua_loader (9026) RUNS on 13.60; /data/ sandboxed; KP fragility

- The mast1c0re save-data DID eventually trigger + the Luac0re 2.4b remote_lua_loader now LISTENS on 9026 (shahrilnet protocol). Protocol: connect -> send Lua (<=500KB) -> close/FIN -> run_lua_buffer executes. NO response channel (verify via file write or on-screen notification; the capture card dshow was busy, so on-screen only via user's screenshots).
- /data/ is NOT writable from the PS2-emulator sandbox: io.open("/data/...") -> nil -> file_write (misc.lua:25) -> "attempt to index a nil value (local 'fd')". Game-writable paths = /savedata0/ (Luac0re's own files live at /savedata0/lua/) + /common_temp/. FTP /data/ == /user/data/ (etaHEN's); FTP /user/savedata/ + /user/common/ exist.
- KP fragility: the Luac0re process (PS2 emu + JIT) kernel-panicked ~minutes after a BENIGN Lua error on 13.60 (not obviously the error's fault). PS2EMU route has a ticking clock — do the GPU-DMA work fast (alloc+walk+submit+verify within minutes).
- Luac0re dlsym (func.lua): SCE_KERNEL_DLSYM = read64(LIBC_OFFSETS.sceKernelGetModuleInfoFromAddr) - 0x450 (fw>=10); sceKernelLoadStartModule = func_wrap(dlsym(LIBKERNEL_HANDLE=0x2001, "sceKernelLoadStartModule")); module handle = sceKernelLoadStartModule("libX.sprx",0,0,0,0,0); dlsym(handle, sym) -> read64(addr_out).
- NEXT: re-launch SWRR+Luac0re -> send a /savedata0/-writing probe -> dlsym sceGnmSubmitCommandBuffers/SceGnmSubmitDone to confirm GNM is initialized in the PS2-emu process -> then the GPU-DMA (still needs the Relapse kernel R/W seam: Luac0re read64/write64 are USERLAND-only).

## 2026-10-06 (late evening) — SYSTEM-RAM WRITE ACHIEVED: /dev/gc + bit-50 fix (GNM detour was a red herring)

- **KDATA-WRITE-PASS on 13.60.** DEVGC_VMID_REBIND.md: the /dev/gc DMA reaches system RAM — the earlier "vmid 6 VRAM-only" conclusion was WRONG. The real blocker was ONE flag: retarget the victim leaf with **bit 50 ("system coherent") SET**. `new = (old & ~phys_mask) | (target_phys & phys_mask) | (1ull<<50)`.
- Working probe: probe89/vmid7.elf. victim garlic gva=0x200600000 phys=0x47bc004c0 raw=0x004000047bc004f7; retarget -> target_pa=0x8b79ad0 (kdata+0x299AD0, zeroed field) with bit50 -> sentinel 0xdeadbeefcafebabe landed (verified BOTH kernel_copyout AND dmap read-back), then restored to 0. NO GNM context needed — the /dev/gc dev vmid (5 or 6, dynamic per boot) natively mixes VRAM + system-RAM leaves.
- So the entire GNM/PS2EMU/Y2JB detour was unnecessary for the WRITE: /dev/gc + bit50 = system-RAM write from the bare elfldr. Y2JB_GPU_DMA_1360.md independently confirms p2jb's gpu.js uses the SAME /dev/gc ioctl 0xC0108102 (not GNM).
- **REMAINING BLOCKER for HV defeat = ONLY the VMCB guest-PA** (retarget -> VMCB+0x90 bit0=0 -> NPT off). Still the lucky/readable boot (rest-resume ruled out). Next: (a) lucky boot + HV scan for the VMCB, or (b) the GPU-DMA READ (probe73/gpuread) — if the GPU READ bypasses the NPT it can dump the HV carve-out + find the VMCB deterministically (no coin flip).

## 2026-10-06 (late evening) — GPU-DMA READ works (bypasses NPT); VMCB NOT in carve-out (protected region high-entropy)

- GPU_DMA_READ_CARVEOUT.md: the GPU-DMA READ (bit-50 src-leaf retarget) BYPASSES the CPU NPT — CONFIRMED (read_bypasses_npt=true). Retarget src leaf -> PA + bit50, DMA copy src->staging, verify vs kernel_copyout (T-A MATCH on kernel .data).
- HV carve-out 0x60000000-0x72000000 (288MB) dumped via GPU-DMA READ. NO plaintext VMCB: the trapped region (CPU panics at 0x60600000) reads as ~2MB max-entropy (7.96 bit/byte). Agent's "encrypted at rest" hypothesis is UNCONFIRMED — the AMD VMCB is read by the CPU (VMRUN) so it should be plaintext; the high-entropy block is more likely the HV's code/key, and the VMCB is elsewhere (VCPU_ARRAY_4_16GB.md says the VCPU/VMCB array is in the un-dumped 1.61-4GB gap or 32-40GB).
- PITFALL: the GPU TLB caches victim.gva->phys — reuse of one retargeted leaf 256x yields only 2 distinct chunks. Allocate ONE FRESH 2MB garlic victim per chunk (garlic pool ~54MB -> 48MB segments).
- Console KP'd (the agent's boundary.elf CPU-read oversweep — CPU kernel_copyout of the carve-out is the panic trigger; GPU-DMA READ is the ONLY safe channel). Recoverable.
- NEXT (after sk): sweep the OTHER VMCB-candidate regions (the 1.61-4GB gap) via the GPU-DMA READ (safe), NOT CPU reads. Once the VMCB guest-PA is known, probe89/vmid7.elf (the WRITE) retargets -> VMCB+0x90 bit50 + stores 0 to clear NP_ENABLE.

## 11.60 Pro 'lucky boot' check — BLOCKED (2026-10-07)
- 11.60 Pro (10.0.0.x) confirmed: fw=0x11600005, build W:\Build\J03675035. elfldr 9021 + FTP 2121 + klog 3232 all live.
- klog reveals active GPU vmids: vmid 6 (dev, the /dev/gc vmid) + vmid 4 (Agc/Gnm Compositor). Dev vmid = 6, SAME as 13.60.
- gvmspace offset is DIFFERENT on 11.60: 13.60's DATA_BASE_GVMSPACE=0x2EEA570 (kdata-relative) is all-zero on 11.60. a53mm rebuilt (J03675007 11.60 -> J03950001 13.60) moved it + likely changed the gvmspace struct layout (page_dir_va field, entry size).
- Two runtime BSS scans (page-dir 0xffffff80 pattern, then broadened high-VA) found only false positives. gvmspace layout lives in XOM .text -> not recoverable offline; kdata_1160.bin has no gvmspace (it's in BSS).
- re-anchor 'gvmspace = idt - 0x9D90' needs ring-0 sidt, but the elfldr payload runs in RING 3 (sidt #GPs, verified on-console). kernel_getlong/kernel_setlong work (syscall R/W).
- Non-destructive GPU-DMA read on 11.60 blocked until gvmspace offset is found (needs ring-0 primitive or a53mm .text RE).
- NOTE: klogsrv-ps5.elf (slopkit payload) works on 11.60 unchanged (deploys via elfldr, streams on 3232) — the kernel msgbuf offset is firmware-agnostic.

## 2026-10-07 (late) — resume-#GP ROP port to 13.60 (in progress)

- Cloned ps5-linux-loader; full <=7.61 offset table in hand (source/offsets.c). The <=7.61 HV-defeat mechanism = RESUME-PATH #GP: corrupt ACPIGBL_FACS (write FACS-8) -> on resume AcpiSetFirmwareWakingVector corrupts its own ptr -> #GP -> kernel ROP chain (rewritten #GP IDT gate + TSS IST6/7) -> hypercall / VMCB write. NOT a "lucky boot".
- KEY ENabler: the GPU-DMA READ (bit-50 src-leaf retarget) already BYPASSES the CPU NPT (read_bypasses_npt=true). Kernel .text is XOM via NPT bit-58, so the GPU read can dump .text directly -> recover 13.60 FUN_*/GAD_* offsets (no guessing the a53mm recompile delta).
- Staged + built: probe94/textdump.elf (.text dump, VA->PA via cpu_va_to_pa from kernel CR3, NO bit-47 since .text is plaintext like .data; config /data/gpread90_cfg.txt = byte offset into .text) and probe95/kdata24.elf (24MB .data re-dump from RUNTIME kdata_base; IDT/TSS/ACPIGBL_FACS sit ~15-16MB into .data, past the old 15MB kdata_1360.bin).
- 13.60 .data offsets (<=7.61, relative to text 0xffffffff80210000): IDT 0x1ABFDF0, COMMON_TSS 0x1AC0AD0, ACPIGBL_FACS 0x1AB7C50, STOPPED_CPUS 0x730FDE0. 13.60 values differ (recompile) -> recover from the dumps.
- Next (on 'sk'): deploy kdata24 + textdump, FTP-pull, then ROPgadget + structure search -> build non-destructive resume-#GP probe (corrupt FACS + rewrite #GP gate to safe handler -> suspend -> resume -> confirm #GP fires).

## 2026-10-07 (late) — resume-#GP port: .text PLAINTEXT, but IDT/TSS SME-ENCRYPTED (BLOCKER)

- Dumped the kernel .text via GPU-DMA (bit-50, no bit-47): PA 0x11000000-0x13800000 is PLAINTEXT x86 code (1903 prologues). The .text is XOM but NOT encrypted. Gadget/function addrs recoverable offline from ktext_0.bin (40MB).
- .text VA->PA walk FAILS via kernel pm_cr3 (the .text is NOT in the KASLR-slid pmap). Recovered the PA empirically: .text code at ~0x11200000 (physbase ~0x11100000); .data (kdata_base) at PA 0x150a0000.
- Physical layout: .text 0x110-0x136 (plaintext) | 12MB CIPHERTEXT 0x138-0x144 | uniform gap 0x144-0x14a | .data 0x150a0000+ (plaintext syscall table).
- IDT/TSS/FACS: ZERO gate descriptors (any selector) in any plaintext dump. The <=7.61 layout puts them at text+~28MB == the 0x13800000 ciphertext region -> they are SME-ENCRYPTED on 13.60.
- BLOCKER: resume-#GP ROP needs to WRITE the IDT #GP gate + TSS IST. Those are encrypted: raw GPU-DMA write -> kernel decrypts to garbage; bit-47 (C-bit/encrypted) access is REJECTED by the IOMMU (distinct=1). On <=7.61 the IDT was plaintext; 13.60 encrypts the static .bss.
- Status: gadgets recoverable (have ktext_0.bin) but #GP write primitive blocked by SME on the IDT/TSS. Next: (a) verify IDT not simply >24MB into .data (dump more), or (b) find a write path that goes through the kernel's own encrypted-write (not the GPU raw write).
- Dumps (local): kdata24.bin (24MB .data), ktext_0.bin (40MB .text 0x11000000), ktext_2800000.bin (18MB 0x13800000).

## 2026-10-07 — >24MB .data check: IDT/TSS confirmed SME-encrypted (resume-#GP ROP DEAD)

- Dumped 0x16ea0000-0x1aea0000 (40MB past the 24MB .data): mix of ciphertext (0x16ea-0x174a, 0x178a-0x184a) + uniform gaps. ZERO gate descriptors / TSS / FACS.
- VERDICT: IDT/TSS/FACS are SME-encrypted on 13.60 (not in any plaintext region). The resume-#GP ROP is BLOCKED: its #GP setup writes the IDT #GP gate + TSS IST, which are encrypted -> raw GPU-DMA write decrypts to garbage; bit-47 (C-bit) access is IOMMU-rejected (distinct=1).
- What survived: .text is PLAINTEXT (XOM only) -> ROP gadgets/functions ARE recoverable from ktext_0.bin (40MB). Only the trigger-write primitive is missing.
- <=7.61 wrote a PLAINTEXT IDT; 13.60 SME-encrypts the static .bss. This is a NEW 13.60 protection, a hard wall for the resume-#GP technique.

## 2026-10-07 — function-pointer->ROP->hypercall: hypercall mechanism UNPINNED (blocker)

- Confirmed ROP chain shape from ps5-linux-loader hv_defeat_0506.c: pop rdi->tmr_id, pop rsi->0x1000, pop rdx->0, FUN_HV_UNMAP_PT_TMR(tmr_id,0x1000,0). Needs GAD_POP_RDI/RSI/RDX_RET + FUN_HV_UNMAP_PT_TMR addr (all in .text).
- BLOCKER: ktext_0.bin (40MB, PA 0x11000000) has ZERO vmmcall (0F 01 D9). The 64 WRMSR (0F 30) + 1957 '0F 01 00' sites are NON-ALIGNED -> data coincidences, not real instructions. The one known vmmcall site (deci5s/sdbgp VMMCALL handler, canonical 0xffffffff8046ed70) is ZEROS at expected PA 0x1145ed70.
- => Either the hypercall is NOT vmmcall (psdevwiki only says 'hypercalls and MMIO', never names the instruction; <=7.61 hv_defeat_0607.c triggers HV via wrmsr(MSR_APICBASE)), OR the .text VA->PA anchor is wrong (code at PA 0x11200000 may not be canonical 0xffffffff80210000).
- psdevwiki Hypervisor page reconfirmed: hypercall table 0x0-0x10; TMR (MAP/UNMAP/RESTORE_PT_TMR) are >=0x11 undocumented; NPT 'xotext' bit = bit 58; HV's own page tables map .text WITHOUT xotext (needs to read .text in intercept handlers); NPT stored in HV-only data segment (guest can't edit).
- NEXT: pin .text VA->PA via syscall table anchor (sy_call pointer VA -> its function body in ktext_0.bin). Resolves whether the dump is the real kernel .text.

## 2026-10-07 — "new NPT leak" hunt: FOUND the HV NPT-manager code in the hvdump

- Key asset: C:\Users\USER\Caliper-C0re\kernel\hv_dump\hvdump_0x26000000_600MB.bin (608MB, base guest-PA 0x26000000) = a WHOLE-BAND dump (not SVM-density-filtered) that CONTAINS the HV's own code. This is the dump the skill said to make (dump whole readable band WITHOUT SVM filter) and it already exists locally.
- Confirmed HV code (not guest kernel): in HV-alias range (guest-PA 0x2b-0x46 GB), uses Sony custom errno 0x8a6cxxxx, int 0x41 panic paths, 0x3f00 PTE-type tags.
- Bit-58 (xotext/NDA) handling: 6 movabs 0x0400000000000000 sites (NOT bts). Three clusters: 0x15aaef32/0x15aaf012 (PTE guards), 0x15ca671c, 0x0d24c90b/0x1e4cc90b (dup), 0x244898a0.
- NPT PTE-edit function family at guest-PA 0x3baae580-0x3baae770 (tagged 0x3f00, bzhi/and/or phys-addr+flags rewrites). 13-entry dispatch at 0x3baae0c0 (cmp ebx,0xc; jmp [rcx+rax*4]).
- CANDIDATE BUG: protection gate = and [rdi+4],0x700000000000000 (bits58-60); cmp ==0x400000000000000 (bit58); je skip. This is ==bit58 (bits59-60 must be clear), NOT &bit58. A PTE with bit58 + bit59/60 set bypasses the guard -> rewritten. Exploitability depends on what bits 59/60 are (NPT PTE bits 52-62 are reserved/avail in AMD; Sony repurposes 58 for xotext).
- NEXT: map what bits 59/60 do in the NPT PTE (from these functions + the pte-set path), determine if the guest can ever cause bit59/60 to be set, and whether a bypass is reachable. Also look for the NPT CONSTRUCTOR (the code that SETS bit58 / builds the carve-out) - it may be elsewhere in the 608MB (search for or-with-bit58 patterns + the carve-out bounds 0x60000000/0x70000000).

## 2026-10-07 (cont) — NPT PTE protection flags + candidate bug details

- NPT PTE Sony-custom flags confirmed live in HV code: bit57 (3 movabs), bit58=xotext/NDA, bit59 (5), bit60 (5), bit61 (11), bit62 (9), bit63=NX. The two guard functions use TWO protection conditions:
  1) (PTE & 0x700000000000000) == 0x400000000000000  (bit58 set, bits59-60 clear)
  2) (PTE >> 61) == 5  (bits61-63 == 0b101 = the no-access/NDA band flag)
  Skip the PTE rewrite if EITHER holds.
- CANDIDATE BUG (still unproven-exploitable): condition 1 is '==' not '&' - a page with bit58 + bit59/60 set bypasses the xotext guard. Exploitability hinges on what bits 59/60 mean + whether the guest can ever cause them to be set. bits 59/60 are NOT the SME C-bit (C-bit=stage-1 bit47, masked during NPT translation).
- 0x605f0000 (readable-window boundary) appears 11x but only in DATA tables (0x140000-stride address lists), NOT in carve-out code. The NPT CONSTRUCTOR (which sets bit58 / builds the 0x60000000-0x605effff carve-out) is still NOT located in the dump.
- The PTE-edit family at 0x3baae580-0x3baae770 operates on a STRUCTURE at [rdi+0x20..0x34] (not a single 8-byte PTE), tagged 0x3f00 - may be a VMCB/mem-descriptor field, not the NPT PTE. Needs more RE to classify.
- STATUS: HV NPT-manager code located + protection flags decoded; a candidate ==-vs-& guard bug identified but exploitability unproven; constructor/carve-out logic not yet found. Deep RE ongoing.

## 2026-10-07 (later) — PUP decryption done + §(d) QA-flag test EMPIRICALLY CLOSED

- **PUP decrypted on-box.** Rebuilt `zecoxao/ps5-pup-decrypt-elf` against `sdk_v043` + LLVM 23 (prebuilt has stale 13.60 offsets; `make` absent so compile with `clang -target x86_64-sie-ps5` directly + `SCE_PROSPERO_SDK_DIR` + `win/prospero-lld.exe` on PATH). Output: `PS5UPDATE1.PUP.dec` (1,247,469,973 B) pulled locally → 33 PUP segments → nested BLS containers → components.
- **Component classification (13.60):** `C0000001` (476 KB, magic 0xd48ff9aa) + `C0040001/2` (113/121 KB, magic 0xef6bab47) = raw-encrypted, NOT SELFs → the separately-loaded components (HV candidates), per-console encrypted. `C3000005–C3000014` (15×~1.4 MB) = Prospero SELFs (magic 0x7747331D), system components. `C003`/`C005` = deeper BLS layers. Confirms the HV plaintext (and thus the NPT constructor) is NOT statically recoverable from the PUP — per-console encryption, not a tooling gap.
- **§(d) QA-flag test RUN (was the one thing never executed):** `qa_flags[1]` read **0x03 on a JB'd boot** (Relapse already sets SL 0x02 + UL 0x01). Set flag, `enter_rest_mode()` (direct-link `sceKernelOpenEventFlag/NotifySystemSuspendStart/SetEventFlag(0x400)`, NOT dlsym — dlsym returns NULL on 13.60), resume, re-JB. **hvdump rescan of `0x605f0000–0x60800000`: 528/528 pages readable, distinct_bytes=256/256, x86_prologues=0, vmcb_candidates=0 — still ciphertext.** The SL flag does NOT clear bit-58 on 13.60. §(d) is EMPIRICALLY DEAD, closing the QA_FLAGS_ROUTE.md "never run" caveat.
- **Dead ends re-confirmed (do not re-recommend):** self-pager (1.00–13.40 max, /system usermode SELFs only, not the separately-loaded HV/kernel); shared hypercall jump table (≤2.70 only, HYPERCALL_PROBE.md §2.2); QA-flag route (now empirically dead). The one open thread remains the hvdump NPT-manager reachability question (can any guest-controlled path set bit59/60 alongside bit58 to slip the ==-guard).

## 2026-10-07 (final) — ==-guard decode CORRECTED + reachability CLOSED

- **CORRECTION:** the guard mask `0x700000000000000` = `0x7<<56` = bits **56–58**, NOT bits 58–60 (earlier notes were wrong). Guard = `(PTE & bits56-58) == bit58`, i.e. bit58 set + bits 56/57 clear.
- Two `0x4900`-tagged flag-setter functions: `fnA @ 0x3baaef10` (skip if bits56-58==bit58) and `fnB @ 0x3baaf004` (skip if bits56-58==bit58 OR bits61-63==5). Both write the PTE flags field from `rsi` (arg) and SKIP the write when the page is protected. The `0x3f00`-tagged setters @ `0x3baae580–0x3baae760` are UNGUARDED (tag-check only) but a DIFFERENT structure type.
- **REACHABILITY CLOSED:** zero direct `call rel32` sites to the dispatch `0x3baae0c0` or either guard fn across the whole 608 MB → they are vtable/indirect-called INTERNAL HV NPT-manager methods, NOT guest-callable hypercalls. The guest's only HV interface is the hypercall table (0x0–0x10 + TMR), separate functions. The ==-weakness cannot be used to unprotect kernel `.text` (those pages are locked protected by the boot-time constructor, and the guard skips writes to them).
- **NET:** every public + discovered attack surface on 13.60 is now closed: constructor (per-console encrypted + init-once), jump table (≤2.70), QA flag (empirically dead), self-pager (wrong target), hypercall-base leak (nonexistent), ==-guard (not guest-reachable). The only remaining lever is the unreleased Sonic-Iso root-0-NPT mechanism (≤14.00, patched 14.10) — the thing that produced the one lucky boot — whose trigger is not reproducible without it.

## 2026-10-07 (watcher) — lucky-boot watcher built + tested (probe98/hvwatch.elf)

- Adapted `hvscan4` → dumps to `/mnt/usb0/hvwatch/` (`cluster_<off>.bin` per hit + `RESULT.txt` = `dumps=N` + LUCKY/NOT-LUCKY). Hardcoded range `0x7d00000–0x5ff00000` (below the `0x60000000` NDA/panic band), config-file mechanism removed. Build: `clang -target x86_64-sie-ps5` + `SCE_PROSPERO_SDK_DIR` + `-lkernel -lkernel_sys -lSceLibcInternal -lc`.
- First run (normal boot): **NOT-LUCKY, dumps=0** — expected. Scan takes **~8 min** (~2.8 MB/s `kernel_copyout` over 1.4 GB); the elfldr socket resets before completion, so the deploy is **send-and-forget** — poll `/mnt/usb0/hvwatch/RESULT.txt` + `/data/kex_hvscan4.txt` via FTP afterward. The payload keeps running after the socket closes (verified: log progressed to `scanned 0x500 MB` then RESULT appeared).
- Use case: after every JB, send `hvwatch.elf` + check the USB; a LUCKY result = HV code readable → pull the clusters for RE.
- **Auto-deploy daemon `probe98/hvwatch_daemon.py`** (background+persist): polls the LAN for elfldr 9021, skips `10.0.0.x`, fw-queries (`fwquery.elf`) to confirm 13.60, then deploys `klogsrv.elf` (captures `/dev/klog` on 3232 to `klog_<ts>.log`) + `hvwatch.elf`, and logs the LUCKY/NOT-LUCKY verdict + klog path to `hvwatch_log.txt`. `klogsrv` built from source against `sdk_v043` (the upstream prebuilt is SYSV-OSABI and never binds; disable the `notify_user` notification — it can hang). Restart via `python3 hvwatch_daemon.py`.
