# ROOT-0 NPT WINDOW — LIVE-CONFIRMED on 13.60 (2026-10-06)

## Corrected framing (supersedes the 32–40 GB guess)

The root-0 NPT (Sonic-Iso / "Slopervisor") maps the HV's carve-out **readable** at a
**guest-PA window**, live-confirmed on two consecutive boots:

- **Window: `0x605f0000 – 0x607fffff` (2.1 MB)** — `kernel_copyout` returns `ret=0`
  (present + readable, bit 58 / NDA clear).
- `0x60000000 – 0x605effff` = not-present (`ret=-1`).
- `0x60800000+` = NDA (bit 58 set) → **hard panic** on read.
- Same start address (`0x605f0000`) on both boots → **deterministic**, not a coin flip.

## The data is uniform ciphertext

`probe93/hvdump.elf` (dumps the window, 528/528 pages, writes `/data/kex_hv.bin`):

```
distinct_bytes=256/256  zeros=0.60%  ff=0.38%
x86_prologues=0
vmcb_candidates=0
```

All 256 byte values present, ~0.39 % each → **uniform random**. No x86 code, no VMCB
predicate hit. The HV's carve-out is **SME-encrypted at rest**; the aliased NPT entry has
the **C-bit (bit 47) CLEAR**, so the guest reads the raw ciphertext, not the decrypted VMCB.

## Model

- Root-0 NPT present+readable (bit 58 clear) = the bug — the map exists ≤14.00.
- The 14.10 fix removed the map ("root-0 NPT no longer maps the HV's own physical memory").
- The **plaintext** VMCB read Sonic-Iso needs = the C-bit (bit 47) SET on that entry, so the
  CPU decrypts with the SME key. Two boots observed C-bit clear → ciphertext.

## Confirmed primitives (live)

- **READ = ciphertext** (uniform random, 3/3 boots). The HV's data is SME-encrypted; the
  aliased NPT entry has the C-bit (bit 47) CLEAR, so my read is raw DRAM = the HV's ciphertext.
- **WRITE = plaintext, WRITABLE.** `kernel_setlong(0x605f0000, 0x1122334455667788)` returned
  rc=0 and read back verbatim → the NPT entry's W bit (bit 1) is SET. My writes land raw
  (C-bit clear) and read back plaintext. A blind volatile store (instead of kernel_setlong)
  silently killed the payload (fault, console survived) — use `kernel_setlong` for writes.
- The write does NOT crash the console → the window is likely HV FREE/unused memory (not
  code/VMCB), or the HV simply hasn't re-read the address. Unresolved.
- SME asymmetry: HV writes/reads its memory with C-bit SET (encrypt/decrypt), I access with
  C-bit CLEAR (raw). So my plaintext write is DECRYPTED=garbage to the HV — a clean
  VMCB+0x90 store is NOT possible through this channel unless the VMCB itself is plaintext
  (host PTE C-bit clear) or the SME is breakable (see open item 3).

## Open items (in priority order)

1. **C-bit is DETERMINISTIC-CLEAR on 13.60** — 3/3 cold boots (distinct DMAP bases) read the
   window as uniform ciphertext (256/256 bytes, 0 prologues, 0 VMCB). Not a coin flip; do NOT
   grind re-rolls for a plaintext boot.
2. **Is the window WRITABLE (NPT bit 1)?** A write primitive would act on the VMCB without
   decrypting. Untested — a blind write may panic if the window is HV code (asymmetric SME
   write = HV reads garbage). Test carefully with a log-before write.
3. **SME/onion scheme** — is the ciphertext AES-SME (hard wall) or the PS5 onion XOR/linear
   scheme (known-plaintext / address-tweak breakable)? Determines whether a clean
   VMCB+0x90 write is even possible through the alias.
4. Where the VMCB sits: host-PA `0x8xxxxxxxx` (32–35 GB) aliased into this window, or
   NDA-locked elsewhere.

## VMCB location — CORRECTED (from GPU_DMA_READ_CARVEOUT.md)

The VMCB/NPT/TMR region is **`0x60600000–0x607FFFFF` (1.62 GB)** — the exact band the CPU
hard-panics on, and where the GPU-DMA read returned 2 MB of max-entropy (≈7.96) = AES
ciphertext at rest. This is **BELOW the ~2 GB IOMMU gate**, so the GPU-DMA write (bit-50,
vmid 7) CAN reach the VMCB. The earlier "host-PA 0x8xxxxxxxx (32–35 GB, from vm_page.phys)"
was a misread — discard it. (Old ≤7.61 anchors 0x62xxxxxx are ABOVE this band; on 13.60 the
HV region is at 0x60600000+.)

## Definitive verdict (4 research agents + live bit-47 test, 2026-10-06)

- **SME is AES-128-XTS**, key in the AMD-SP, never exposed to x86 — a hard wall (tekingame +
  AMD whitepaper).
- **The C-bit (bit 47) is NOT guest-controllable.** It lives only in the NPT entry (CPU) and
  the AMD-Vi IOMMU leaf (DMA), both HV-owned. The guest's stage-1 C-bit is masked out during
  translation (AMD APM §15.34.6). Live test: setting bit 47 in the GPUVM PTE retarget makes
  the GPU-DMA read land NOTHING (`distinct=1/256`, `changed=0` — bit 47 is a bus-address bit
  the IOMMU rejects, not the C-bit).
- **Therefore:** the guest reads the HV memory only as ciphertext and writes only raw (which
  the HV decrypts to garbage). A plaintext VMCB read and a clean `VMCB+0x90` write are both
  unachievable through the CPU NPT or the GPU-DMA path.
- **VMCB offset not recoverable offline** — the whole 2 MB band is max-entropy ciphertext
  (re-verified entropy 7.987), no plaintext VMCB / per-core array in the dumps.
- **Sonic-Iso mechanism remains unreleased** and is not reconstructable from the architecture
  alone — whatever defeats the AES-128 SME is not the C-bit.

## VMCB location — live diff result (2026-10-06)

Temporal diff of the readable window (`0x60600000–0x607fffff`, 200ms apart, probe93/diff.elf):
**0/512 pages changed** — the window is completely static. So the readable window is the HV's
FREE/static memory (or static NPT), NOT the VMCB. The VMCB is the region that PANICS on CPU
read = NDA-locked, which on the current boot is `0x60800000+` (the doc's `0x60600000` was a
different boot — the NDA boundary re-rolls per boot). The VMCB is therefore both AES-encrypted
AND NDA-locked; finding it needs a GPU-DMA read of `0x60800000+` diffed over time, and the
follow-up (raw garbage write to `+0x90`) is a 50/50 with reserved-bit fault risk.

## Garbage-write viability — NESTED_CTRL field (from HV_UNMAP_PT_TMR.md)

`VMCB+0x90` = **NESTED_CTRL** (nested-paging control dword): **bit 0 = NP_ENABLE**, **bit 3 =
GMET_ENABLE** (`0x8`), the rest **RESERVED**. The ≤7.61 defeat wrote `0x8` via the
`hv_unmap_pt_tmr` OOB + DMAP — both dead on 8.00+ (OOB closed at 6.50, HV moved). A raw
garbage write (AES-decrypt of my raw store) would set the reserved bits → VMRUN faults → KP.
So the garbage write is NOT viable: every write path is either raw-garbage (reserved-bit
fault), unconfirmed (GPU-DMA→system-RAM = FAIL), or dead (IOMMU COMPLETION_WAIT = RAM alias).
**The write half is fully blocked on 13.60.**

## A53 (PSP) firmware source — a53-RE repo (seregonwar/a53-RE)

Full DWARF-backed source recovery of `a53.elf` (the AMD PSP / ARM Cortex-A53 co-processor).
Confirmed from source:

- **The PS5 crypto is AES-XTS.** `zcnPutCommandAesXts(len, paSrc, paDst, PASID, ZcnAesXtsMode,
  ZcnAesType, ZcnAesXtsSize, kmbKeyID, lsbContextID, order)` + `zcnDriverSetIdmaAesTweakIndices`
  (tweak = block index). The key is a **`kmbKeyID` — a KMB (key-management) slot ID, never in the
  code**. This is the *flash/SSD* path (the A53's ZCN engine), but it's the same AES-XTS+tweak
  scheme as the DRAM SME.
- The A53 is the **root of trust**: boots the x86 (boot-config over DVM mailbox from `0x54000000`,
  x86 CP params at `0xd0000000`), sets up the DRAM/IOMMU, and speaks to the x86 over the
  deci/C2P/DVM channels (`deci_target_mp4.c`, `deci5s_mp4.c`, `c2pmsg.c`).
- The **DRAM (SME) encryption setup and key are NOT in this EL3 loader** — they live in the A53
  ROM / x86 firmware, not the recovered source. So the repo confirms the hard wall (AES-XTS +
  hidden KMB key) but does not break it.

## GPU-DMA system-RAM access — allocation-size fix (2026-10-07)

The "2MB-leaf = VRAM-only" wall is NOT a coin flip: **allocation size controls the leaf format.**
`probe90/leafsize.elf`: 64KB/256KB/1MB garlic buffers → **8KB leaves** (`raw=0x…0277`, bit50 can
route to system RAM); 2MB buffer → 2MB leaf (`0x4f7`, VRAM-only). So allocate **64KB garlic
buffers** to get system-RAM-capable leaves. `probe90/diff2.elf` (64KB buffers, 8KB leaf + bit50)
read `0x605f0000` → `distinct=256/256` (ciphertext = the HV memory, matching the CPU read) — the
GPU-DMA READ works. `0x60800000+` reads all-one-byte (the HV's zero/BSS region). The VMCB is in
the 2MB band `0x60600000–0x607fffff` (encrypted, static — temporal diff won't flag it if the HV
doesn't rewrite dynamic fields); find it by sweeping that band.

## Carve-out layout (GPU-DMA sweep, 2026-10-07)

Full map via 8KB-leaf + bit50 reads:
- `0x60000000–0x605effff` → **all `0xFF`** (IOMMU no-access) + CPU NDA panic. HV code + **VMCB**
  live here; unreachable by read from CPU or GPU.
- `0x605f0000–0x607fffff` → sparse encrypted pages (the **NPT** page tables) + zeros. The
  "root-0 NPT window". NOT the VMCB.
- `0x60800000+` → zeros (BSS/free).
So the VMCB is in the *no-access* region, not the readable window. Open question: does the
GPU-DMA **write** (clean, bit50) still land in that region even though the read returns 0xFF?

**RESOLVED (2026-10-07):** `sweep.elf` write test — sentinel to `0x60000000` via 8KB-leaf+bit50
→ `ioctl=0`, `STILL-ALIVE` (no panic). The write is **dropped** by the IOMMU's no-access
mapping, same as the read returns `0xFF`. The VMCB is therefore unreachable via the GPU-DMA
(the AMD-Vi I/O page table protects the HV code/VMCB region from *both* directions, on top of
SME + the CPU NDA). The writable region is only the NPT window `0x605f0000–0x607fffff` and the
guest's own DRAM.

## Files

- `probe93/carveout.c` / `.elf` — 4 KB scan of `0x60000000–0x72000000`, logs readable pages.
- `probe93/hvdump.c` / `.elf` — dumps + characterizes the 2.1 MB window (histogram, x86
  prologue count, VMCB scan), writes `/data/kex_hv.bin`.
- `probe93/iommu.c` / `.elf` — IOMMU MMIO DTRB/CBRB read (returns zero: hypercall-driven, dead).
