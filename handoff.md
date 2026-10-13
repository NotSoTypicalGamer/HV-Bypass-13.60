# HV-RE — fresh-agent handoff

Goal: **defeat the PS5 13.60 hypervisor** — get past root-0 nested paging (NPT) to read the
hypervisor's own memory, then clear `NP_ENABLE` on all 16 VMCBs to uncontain the guest.
Deterministically if possible (the current best plan); the stochastic "lucky boot" is a
secondary fallback. Nothing is published; this repo is private.

## The target

The 13.60 hypervisor runs the game (FreeBSD 11.0 guest) under a root-0 hypervisor (SVM).
It defends its memory three ways:

1. **NPT (nested paging)** — root-0 page tables translate guest memory. The known ≤7.61
   endgame is writing `NESTED_CTRL @ VMCB+0x90 = 0x8` (bit 0 off = NPT disabled, bit 3 on =
   GMET) on all VMCBs; the HV then stops translating and the guest is uncontained.
2. **AES-XTS encryption at rest** — the VMCB, the HV's own data, and the kernel's *sensitive*
   structures (IDT, COMMON_TSS, ACPIGBL_FACS) are encrypted. The C-bit (bit 47) is
   HV-owned and provably clear, so this is NOT standard AMD SME — it's a Sony-custom HV
   encrypt-on-write path.
3. **IOMMU no-access band** (`0x60000000–0x605effff`) — the VMCB lives here. CPU read panics,
   GPU-DMA read returns fill bytes, GPU-DMA write is dropped.

## The two attack paths

### A. Deterministic — S3-resume AP-launch (primary)

From Sonic-Iso's `kernel/s3-resume-startup_mp-ap-launch.md`: Relapse gives kernel R/W +
kcall; stage a root-0 AP payload at `0x3ffff000`; the S3 resume path issues `HCALL 0x0f`
(`khv_startup_mp`, `core=15, RIP=0x3ffff000, CR3=0x68000`), which makes the HV launch that AP
**in root-0 context**. The AP walks the inner-HV `pcpus[]` (`m_vmcb @ +0xa8`, `core_id @
+0x138`, `hv_heap_offset` 13.60 = `0x2a028`), computes `VMCB phys = pcpu[core].m_vmcb −
hv_heap_offset`, and strikes `NESTED_CTRL = 0x8` on all 16 VMCBs. `kernel/S3_AP_LAUNCH_PORT.md`
is the 13.60 port plan; `probes/probe99/` has the payload skeleton.

### B. Stochastic — the lucky boot (secondary)

A per-boot state where root-0 NPT maps the HV's physical memory as plaintext-readable. Runs
as a passive watcher (`probes/probe98/hvwatch_daemon.py` + `hvwatch_fast.elf` / `hvfulldump.elf`).
On a verified LUCKY boot it dumps every readable non-zero page. Suspend→resume does NOT
re-trigger it. This produced the existing HV dump (see below).

## Hard-won ground truth (don't re-derive these)

- **Kernel R/W + kcall + ROP: SOLVED.** WAK1360-Relapse (arg0WAK) is a complete 13.60 port
  of the `aio_multi_wait` (syscall 663) UAF → arbitrary kernel R/W + a ROP kcall
  (`worker_rop.fcall(rip, rdi, rsi, rdx, rcx, r8, r9)`). Exact 13.60 offsets in
  `kernel/reference/relapse-wak1360/13.60.js` (aio struct sizes, `SECURITY_FLAGS 0x01A5C064`,
  `QA_FLAGS +0x24`, `UTOKEN +0x8C`, `ALLPROC 0x03589E80`, KASLR defeat `rtmsg2`, gadget map,
  full `syscall_map`).
- **Text base** `0xffffffff80200000`. **`.data` = text + `0xCC0000`** (not `0x82000000`).
- **ROP gadgets resolved** (kernel text): `mov [rdi],rsi; pop rbp; ret` (3 sites, primary
  `0xffffffff81b260c4`), `pop rdi/rsi/rdx/rcx/rax/rsp; ret`, `iretq`, `add rsp,0x20; pop rbp;
  ret` (the `0x28` variant doesn't exist). `wrmsr;ret` and `vmmcall` are **absent** from the
  clean text.
- **The IDT / COMMON_TSS / ACPIGBL_FACS are HV-encrypted.** They sit in a 4 MB AES-XTS
  ciphertext block (kdata+0x1000000..0x1400000). Neither GPU-DMA nor `kernel_copyout` (CPU)
  decrypts them — the HV decrypts on its own interrupt-delivery path. Therefore the
  `#GP`-via-FACS trigger (ROP off `IDT_GP`/`COMMON_TSS.tss_ist6`) is **dead on 13.60**.
- **`pcpus[]` base is the hypervisor's**, in the SME carve-out (`0x60000000–0x70000000`) —
  not a kernel symbol. It needs an HV dump (lucky boot), not a kernel-text dump.
- **Dead empirically on 13.60**: ≤7.61 hypercalls / wrmsr-#SX, A53/EL3, GPU-DMA write,
  IOMMU-MMIO `COMPLETION_WAIT`, the NDA band via GPU-DMA on a normal boot.

## The open items (blocking the deterministic chain)

1. **`acpi_sleep_machdep` VA** — the resume trigger. The acpi.c sleep-path code is in an
   **XOM-scrambled region** of the kernel text (the text dump has a ~2.8 MB scrambled header
   + scattered scrambled chunks). This is the single most-needed offset; the trigger is a
   direct Relapse kcall of `acpi_sleep_machdep` (no IDT/TSS needed).
2. **The hypercall wrapper** (`vmmcall` path) — also in a scrambled region; `vmmcall`
   (`0f 01 d9`) has 0 hits in the clean text. Needed only if the AP-launch must be driven
   directly rather than via the resume path.
3. **`pcpus[]` base** — needs an HV dump (lucky boot), or a fresh idea.

## Where the data lives

- Local: `C:\Users\rocks\AppData\Local\kex\cache\scratch\` — `KEX-RE\dumps\`
  (`ktext_0.bin` 40 MB, `ktext_2800000.bin` 18 MB, `ktext_5ea0000.bin` 40 MB [data],
  `kdata_1360.bin` 15 MB, `kdata_761/1160.bin`, `kernel_data.bin` 48 MB), plus
  `ktext_3a00000.bin`, `ktext_bss*.bin`, `bssscan.bin` (16 MB `.bss` band).
- Repos: **HV-RE** (this one, hypervisor-only), **KEX-RE** (kernel-exploit hunt), **Marvell-RE**
  (88W8897 WiFi/BT). HV dump (312 `hvcluster_*.bin` + 637 MB full-band) is LFS-tracked in
  `HV-RE/kernel/hv_dump/`.
- Key docs: `README.md`, `kernel/S3_AP_LAUNCH_PORT.md`, `kernel/s3-resume-startup_mp-ap-launch.md`,
  `kernel/13.60_OFFSET_HUNT.md`, `kernel/13.60_REDUMP_PLAN.md`, `kernel/HANDOFF.md` (rolling
  state), `kernel/reference/` (public ≤6.02 `hv_defeat_0506.c`, `ps5linux_offsets.c`,
  `cragson_offsets.h`, WAK1360-Relapse).

## Fresh-eyes questions (suggested attack surface)

- Is there a **cleaner resume trigger** than `acpi_sleep_machdep` — a syscall or ioctl that
  drives the S3 path directly, callable via the Relapse kcall without resolving the scrambled
  text?
- Can the **encrypted IDT/TSS block** be read by any guest-visible path (the AES-XTS key is
  HV-held, but is there a decrypt-on-read gadget or an aliased plaintext mapping)?
- Is the **hypercall** reachable without the scrambled wrapper (e.g. a `vmmcall` in a clean
  region we haven't scanned, or an indirect hypercall via a known HV entry)?
- Is the **lucky boot** actually more tractable than the deterministic chain — can the
  root-0-NPT window be *induced* rather than waited for?
- Can `pcpus[]`/VMCB physical addresses be derived from the existing HV dump (the 312
  clusters + full-band capture) rather than requiring a new lucky boot?

## Console / toolchain

- 13.60 console: elfldr 9021, FTP 2121 (anon), klog 3232, at `10.0.0.x`. Entrypoint: Star
  Wars Racer Revenge (CUSA03474) via Luac0re. The 11.60 Pro (`10.0.0.x`) is **strictly
  off-limits** (factory-reset risk to its Blu-ray activation).
- Payloads build with the ps5-payload-sdk (`sdk_v043`, `prospero-clang -target x86_64-sie-ps5`),
  **via WSL** (`wsl.exe -e bash -c '...'` — the git-bash lacks `rev`, which the SDK wrapper
  needs). Deploy = send the `.elf` over raw TCP to 9021 (`socket.sendall`), not HTTP POST.
- Constraint: avoid kernel panics on the live console where possible; prefer reading local
  dumps over re-dumping; use the 13.60 (not the Pro) for risky tests.

## Gotchas already paid for

- The kernel-text dump is XOM-scrambled in places; full linear disassembly OOM'd capstone on
  the 40 MB file — chunk it and skip the scrambled regions.
- `.data` is KASLR-slid per boot; the runtime base is `payload_get_args()->kdata_base_addr`
  (e.g. `0xffffffff88dc0000`), never a hardcode.
- GPU-DMA text reads need the bit-50 src-leaf retarget; self-test (T-A READ-KNOWN) must pass
  before trusting any read.
- No personal info in the repos.
