# HV-RE — PS5 13.60 hypervisor defeat

Private research on defeating the PS5 hypervisor on firmware **13.60** — getting past root-0
nested paging (NPT) to read the hypervisor's own memory, then clearing `NP_ENABLE` on all 16
VMCBs to uncontain the guest. Nothing published; console-local probes only.

Sibling repos: **KEX-RE** (14.00+ kernel exploit hunt) · **Marvell-RE** (88W8897 WiFi/BT).

## What we're up against

The 13.60 hypervisor protects its own memory three ways:

- **NPT (nested paging)** — the HV translates guest memory through root-0 page tables.
  Clearing `NP_ENABLE` (write `0x8` to `VMCB+0x90` — bit 0 off = NPT disabled, bit 3 on =
  GMET) is the ≤7.61 endgame recipe: the HV stops translating and the guest is uncontained.
- **SME** — the VMCB (and HV memory generally) is AES-XTS-encrypted at rest. A raw store
  decrypts to garbage → VMRUN faults. The C-bit (bit 47) is HV-owned and provably clear, so
  it is **not** the answer.
- **IOMMU no-access band** (`0x60000000–0x605effff`) — the VMCB lives here. CPU read panics,
  GPU-DMA read returns nothing, GPU-DMA write is dropped.

## The two attack paths

### A. Deterministic: S3-resume AP-launch (primary)

Sonic-Iso's `s3-resume-startup_mp-ap-launch` write-up (`kernel/s3-resume-startup_mp-ap-launch.md`)
shows a **deterministic** root-0 VMCB write — no lucky boot:

- Relapse (`aio_multi_wait`, syscall 663) gives kernel R/W + kcall/ROP.
- Stage a root-0 AP payload at `0x3ffff000`, then `HCALL 0x0f` (`khv_startup_mp`,
  `core=15, RIP=0x3ffff000, CR3=0x68000`). The HV launches that AP *in root-0 context*.
- The AP payload walks the inner-HV `pcpus[]` (`m_vmcb @ +0xa8`, `core_id @ +0x138`) using
  `hv_heap_offset` (13.60: `0x2a028`), computes each `VMCB phys = pcpu[core].m_vmcb −
  hv_heap_offset`, and strikes `NESTED_CTRL @ VMCB+0x90 = 0x8` on all 16 VMCBs — clearing
  `NP_ENABLE` while keeping `GMET`.
- Resume trigger: `acpi_sleep_machdep` via the Relapse kcall (a direct call, no IDT/TSS).
  The `#GP`-via-ACPI-FACS route (ROP off `IDT_GP`/`COMMON_TSS.tss_ist6`) is **dead on 13.60** —
  the IDT/TSS are HV-encrypted and unreadable from the guest (see Offset-hunt status).

Port plan + payload skeleton: `kernel/S3_AP_LAUNCH_PORT.md`, `probes/probe99/`
(`ap_launch.S`, `trigger.c`). Public ≤6.02 reference implementation in
`kernel/reference/` (`hv_defeat_0506.c`, `ps5linux_offsets.c`, `cragson_offsets.h`).

### B. Stochastic: the lucky boot (secondary, still armed)

The **root-0-NPT "lucky boot"** — a per-boot state where root-0 NPT maps the HV's physical
memory as plaintext-readable. Stochastic, so it runs as a passive watcher, not a one-shot.

- `probes/probe98/hvwatch_daemon.py` — auto-detects a 13.60 boot, streams the klog, deploys
  the scan payload.
- `probes/probe98/hvwatch_fast.elf` — 2 MB-chunk SVM-opcode sweep of `0x7d00000–0x5ff00000`
  (4 KB fallback), declaring **LUCKY / NOT-LUCKY** with early exit.
- On a verified LUCKY, `probes/probe98/hvfulldump.elf` dumps every readable non-zero page.

## Offset-hunt status (13.60)

Disassembled the dumped kernel text (capstone) — see `kernel/13.60_OFFSET_HUNT.md`.

- **Confirmed**: text base `0xffffffff80200000`, **`.data` = text + `0xCC0000`** (from
  WAK1360-Relapse `OFFSET_KERNEL_DATA`; the earlier `0x82000000` conclusion was wrong).
- **`.text` page map** (ktext_0.bin, 4 KB pages, `0x0–0xCC0000`): **78.7% plaintext code,
  17.9% zero pages, 3.5% AES-XTS ciphertext pages.** The zero+cipher pages cluster where the
  core handlers live (see the sysent note).
- **`sysent[]` `+8` field is NOT a uniform function pointer** (corrects `GHIDRA_MAP.md`).
  Disassembling the `+8` targets: entries 0–5 point into cipher/zero pages, entry 20 → UTF-16
  `"ongPress"`, entry 663 → `"iority={2}"`, but entry 97 (socket) → valid x86. So `+8` is a mix
  of code / string / zero, and "`sy_call` → `0x80xxxxxx` for all 677" is wrong — the table (or
  the `0x38` base) must be re-verified before any syscall-hijack.
- **ROP gadgets resolved** (usable): `mov [rdi],rsi; pop rbp; ret` (3 sites, primary
  `0xffffffff81b260c4`), `pop rdi/rsi/rdx/rcx/rax/rsp; ret`, `iretq`, and `add rsp,0x20; pop
  rbp; ret` (the `0x28` variant doesn't exist). `wrmsr;ret` and `vmmcall` are **absent** from
  the clean text.
- **Blocked**: `acpi_sleep_machdep` and the hypercall wrapper are in **XOM-scrambled text**.
  `IDT`/`COMMON_TSS`/`ACPIGBL_FACS` sit in a **4 MB AES-XTS ciphertext block** (kdata+0x1000000)
  that is unreadable via GPU-DMA *or* `kernel_copyout` — the HV decrypts on its own interrupt
  path. So the `#GP` trigger is dead; the direct-kcall trigger is the path.
- `pcpus[]` base is the **hypervisor's** (SME carve-out `0x60000000–0x70000000`), not a kernel
  symbol — it needs an HV dump, not a kernel-text dump.

## Next step

Re-dump the **scrambled text region** containing the acpi.c sleep path (from the console,
`kernel/13.60_REDUMP_PLAN.md`) to resolve `acpi_sleep_machdep`'s VA — now the single blocking
offset. The trigger is a direct Relapse kcall of `acpi_sleep_machdep` (no IDT/TSS); the kernel
R/W + kcall + ROP gadgets are all in hand (WAK1360-Relapse + the offset hunt). `pcpus[]`
still needs an HV dump (lucky boot).

## Confirmed findings (see `kernel/` for the full write-ups)

- **Root-0 NPT guard** — bits 56–58 of the NPT entry; zero callers in the guest-visible
  paths → the guard is closed off (`ROOT0_NPT_WINDOW.md`, `ROOT0_NPT_FLAG.md`).
- **False LUCKY** — an SVM-opcode density heuristic tripped on guest-RAM pointer tables
  (~180 distinct bytes, no prologues/errno). The filter now requires a real x86 prologue
  (`41 57 41 56 41 55 41 54 53`) or the Sony errno `0x8a6c`, plus <220 distinct bytes.
- **Resume does not re-trigger lucky state** — suspend→resume was tested as a flyer; it does
  not reproduce the lucky read.
- **NDA band is not reachable via GPU-DMA on a normal boot** — the bit-50 src-leaf retarget
  self-test passes, but `0x60000000` reads land all fill-byte (distinct=1/256).
- **≤7.61 hypercalls / wrmsr-#SX, A53/EL3, GPU-DMA write, IOMMU-MMIO `COMPLETION_WAIT`** —
  all empirically dead on 13.60.
- **probe99 ring-0 dry-run — two failure modes, and the field wasn't even a handler.** The
  syscall-20 hijack wrote to a `+8` field that disassembles to a UTF-16 string (`"ongPress"`),
  not a function — so it hit a non-handler field, on top of SMEP/CFI blocking a userland target.
  Ring-0 exec is still the wall; Relapse's `kcall` is ring-3 ROP, not ring-0. Surviving plan:
  GPU-DMA overwrite a plaintext `.text` function *body* (supervisor page → SMEP-neutral, unchanged
  call target → CFI-neutral), then trigger it.

## Layout

- `kernel/` — findings, one `.md` per investigation, plus `HANDOFF.md` (rolling state),
  `13.60_OFFSET_HUNT.md`, `13.60_REDUMP_PLAN.md`, `S3_AP_LAUNCH_PORT.md`, and the copied
  `s3-resume-startup_mp-ap-launch.md` + `reference/` (public sources).
- `kernel/hv_dump/` — the lucky-boot HV dump (312 clusters + the 637 MB full-band dump) and
  the analysis scripts. LFS-tracked binaries.
- `kernel/amdvi_src/`, `kernel/gpudma_src/` — reference sources (AMD-Vi, GPU DMA, Luac0re).
- `probes/` — payload/build sources: `probe83` (SVM scanner), `probe90` (GPU-DMA read/write +
  text dump), `probe93` (carve-out/A53), `probe97` (QA-flag rest-mode), `probe98` (the
  watcher), `probe99` (S3 AP-launch skeleton).

## Toolchain

Payloads build with LLVM 23 (`clang -target x86_64-sie-ps5`) against the
`ps5-payload-sdk` (sdk_v043), libs `-lkernel -lkernel_sys -lSceLibcInternal -lc`,
`SCE_PROSPERO_SDK_DIR` set, `win/prospero-lld.exe` on PATH. Console: elfldr 9021, FTP 2121
(anon), klog 3232. Entrypoint: Star Wars Racer Revenge (CUSA03474) via Luac0re.
