# HV IOMMU + Hypercall Recovery — Findings (PS5 13.60 guest-PA dump)

## Executive summary

**The AMD SVM secure-monitor (hypervisor) code is NOT present in this dump in a
disassemblable form.** Offline x86-64 disassembly cannot recover either requested
artifact from the provided clusters:

| Artifact | Result |
|---|---|
| AMD-Vi (IOMMU) MMIO physical base | **NOT RECOVERED** — no 0xFEDxxxxx / 0xFExxxxxx / ECAM 0xF0000000 base literal exists anywhere in the 186 chunks |
| Hypercall dispatch table (0x0–0x11) | **NOT RECOVERED** — no vmmcall handler / hypercall jump table exists in the clear |

The "mixed-op" clusters identified as HV dispatch code are **data**, and the
SVM opcodes used to flag them are **false positives**.

---

## What the dump actually is

The 186 × 1 MiB chunks are a **sparse sample of guest physical memory** (~13 %
of the 0x07d00000–0x5ff00000 span). Content classes (by byte-frequency /
entropy classification):

- **Clear x86-64 code** (guest OS, not HV): `0x42400000` (highest REX.W density
  3.3 %, 1435 `55 48 89 e5` prologues), `0x37f00000`, `0x15f00000`, `0x3fd00000`,
  `0x46100000`, `0x46400000`, `0x3f800000`, `0x41000000`, `0x43d00000`, etc.
- **Guest-OS data**: SVG images, UI strings (`"title-container"`), PS5 system
  strings (`"psfx_open_error_"`, `"psfx_slider_level"`, `"Decide_01_mk_vol"`,
  `"VAGp"`), 0x77 `wwwwwwww` fill.
- **Page tables / bitmaps**: repeating 8-byte records `0x0c` / `0x0c…ff` (the
  `0x0c00000000000000` and `0xffffffffff00000c` patterns at cluster heads), plus
  single-bit-dominant bitmap regions (top bytes 0x00, 0x80, 0x01, 0x02, 0x04,
  0x08, 0x10, 0x20, 0x40).
- **High-entropy (encrypted/compressed)**: `0x2b800000`, `0x29e00000`,
  `0x27600000`, `0x25500000`, `0x25700000`, `0x16500000`, `0x13f00000`,
  `0x26e00000`, `0x25c00000`, `0x2d800000`, `0x2b700000`, `0x2b900000`,
  `0x2bc00000`, `0x29f00000`, `0x2da00000`, `0x2c800000` (entropy ≈ 8.0).
- **Empty**: ~30 clusters are 100 % zero (`0x2e500000`, `0x34900000`,
  `0x3af00000`, `0x40300000`, `0x42800000`, `0x43a…43e`, `0x4c600000`,
  `0x4cc00000`, `0x4d500000`, `0x4da00000`, `0x4eb00000`, `0x50d00000`,
  `0x55f00000`, `0x57600000`, `0x5a400000`, `0x5ff00000`, …).

## Why the "mixed-op" clusters are not HV code

The clusters `0x2ba00000`, `0x2d400000`, `0x2f500000`, `0x2eb00000`,
`0x2d200000` were flagged because they contain byte sequences `0f 01 d8..df`
(VMRUN/VMMCALL/VMLOAD/VMSAVE/STGI/CLGI/SKINIT/INVLPGA). Evidence these are
**false positives inside data**, not instructions:

1. **No clean instruction context.** Every SVM-op occurrence sits inside
   repeating/non-code data. Example, `0x2d400000` around the "STGI" at
   `0x2d4583ce` — the surrounding bytes are a repeating 16-byte record
   (`dc 70 10 ff 00 1f e1 11 0f 1f 01 10 f1 10 0f 01 …`), not valid x86.
2. **Byte-frequency signature is data, not code.** The `0x2d400000` code region
   is 23 % `0x00` and 2.6 % `0x0c`, with REX.W (`0x48`) at ~0.0 %; real x86-64
   code has `0x48` at ~10–15 % and dense `55 48 89 e5` prologues (this region
   has **zero** prologues).
3. **Cluster heads are page-table records** (`0x0c00000000000000`), followed by
   PS5 system-software strings (`psfx_open_error_`, …) — i.e. data pages.
4. **Replication, not code layout.** The same SVM-op offsets reappear shifted by
   a constant across clusters (e.g. 0x2eb vs 0x2f5 differ by 0x40000; 0x29e vs
   0x2b8 differ by 0x20000) — the signature of aliased/duplicated data, not a
   contiguous code image.
5. **Transform check (negative).** XOR (all 256 keys), bit-reverse, nibble-swap,
   byte-rotate, 8×8 bit-transpose and 6-bit repacking of the "code" region all
   fail to produce an x86 signature (no prologues, REX.W stays < ~1.5 %). The
   data is not lightly-obfuscated code.

## Guest OS identification

- `FreeBSD` version string present in `0x7d00000`, `0xdc00000`, `0xe800000`,
  `0x1bc00000`, `0x1bd00000`, `0x1f200000` → the guest is the FreeBSD-derived
  Orbis OS.
- `Orbis` string in `0x42400000`.
- **The FreeBSD AMD-Vi (IOMMU) driver is present in the clear at `0x3f800000`**
  (the `"IVRSSupportModule"` string at `0x3f879db5`, plus driver code at
  `0x3f8d27e6` / `0x3f8d3b46` / `0x3f8a1db8`). This is *guest* driver code, not
  the HV.
- That driver performs DMA-address validation using
  `mov rcx, 0xffffffc00000` (`0x3f8d27e6`) and
  `mov r14, 0x000001ffffffc00000` (`0x3f8a1db8`), i.e. a **4 MiB-alignment mask**
  — the low 32 bits `0xffc00000` appear in the dump and were initially mistaken
  for an IOMMU base. They are **masks, not the MMIO base**. The driver also
  tests `shr rax, 0x30; cmp eax, 0xfffd` (top-16-bit range check for reserved
  MMIO/DMA addresses).

## Evidence for the negative results

- **No `0xFEDxxxxx`/`0xFECxxxxx`/`0xF0000000` base as an immediate or aligned
  pointer** anywhere in the 186 chunks (aligned 4/8-byte scan). The only
  0xF0000000 hits are a repeating table field in `0x13300000` (DMA-region
  descriptors), not a base.
- **No ACPI IVRS table** in the dump (only the `"IVRSSupportModule"` module-name
  string) → the IOMMU base cannot be read back from firmware tables either.
- **No real SVM instruction** anywhere (every `0f 01 d8..df` is a false positive
  in data); hence no VMRUN loop, no vmmcall handler, no `cmp rax, 0x11` +
  indexed `jmp [table + rax*8]` hypercall dispatch.

## Conclusion / recommendation for the parent

The hypervisor code is either (a) inside the **high-entropy (encrypted/
compressed) clusters** listed above — which require the boot-time decryption key
or decompressor to recover — or (b) in a 1 MiB guest-PA region that was **not
captured** by this sparse dump. To proceed, the dump must be re-taken as a
contiguous range (or the HV's resident physical range located first), or the
encrypted clusters must be decrypted with the console's key. The SVM-opcode
heuristic used to select the "mixed-op" clusters is not reliable on this data —
it matched structured data, not code.

## Artifacts

- Working scripts (capstone disassembly, cluster classification, SVM-opcode
  scan, MMIO literal scan, transform tests) left under
  `C:\Users\USER\AppData\Local\kex\cache\scratch\` (`dump_code.py`,
  `classify.py`, `scan_svm_ops.py`, `scan_mmio2.py`, `scan_mov_raw.py`,
  `transform_test.py`, `transpose_test.py`).
