# VCPU Array / VMCB-Pointer Search — 4–16 GB Guest-Physical Dumps

**Date:** 2026-10-05
**Target:** Hypervisor VCPU array — 16 (or 8) consecutive 8-byte host-PA pointers to VMCBs
(4KB-aligned, constant incrementing stride ~0x2000–0x3000), plus any dense cluster of
0x2xxxxxxxx / 0x8xxxxxxxx 4KB-aligned values.
**Inputs (all offline):** `hvcluster_<hex>.bin` with base ≥ `0x100000000` (4 GB) in
`C:\Users\USER\Caliper-C0re\kernel\hv_dump\` — **126 files**, 1 MiB each, guest-PA bases
`0x10ba00000` … `0x3fc000000` (≈126 MiB total, 16,515,072 qwords).

## Conclusion

**Nothing found. The entire 4–16 GB region is uniformly random (encrypted) data — there is
no plaintext VCPU/VMCB-pointer array recoverable from these dumps.**

Every one of the 126 chunks is statistically indistinguishable from a uniform byte stream.
No candidate arrays exist because no plaintext pointers exist in this range at all.

## Evidence

### 1. The region is encrypted / random — not plaintext memory
Global byte statistics over all 126 MiB:

| Metric | Measured | Uniform-random expectation |
|---|---|---|
| Zero bytes | 0.391 % | 0.391 % (1/256) |
| Byte entropy | **8.0000 bits/byte** | 8.0000 |
| u64 high-nibble distribution | 6.25 % × all 16 nibbles | 6.25 % |
| 4KB-aligned nonzero u64 | 3,974 / 16,515,072 = 0.0241 % | 0.0244 % (1/4096) |

Per-file check: **0 of 126 files** deviated (none had >5 % zeros or entropy <7.0). The
encryption is uniform across the whole range, not sparse/partial.

### 2. No constant-stride VMCB-pointer arrays
NumPy exhaustive scan (8- and 16-entry windows, all 4KB-aligned + nonzero + in host-PA range
0x10000000–0x4000000000, constant *positive* stride 0x1000–0x10000):

**0 candidate arrays.** (Compare: the same scan on the 0x07d00000–0x60000000 dumps found
page-frame stacks and page-size tables; here there is nothing because the data is a keystream.)

### 3. No plausible host-PA values
Of the 3,974 4KB-aligned nonzero qwords (exactly the count random data predicts):
- **0** match the old VMCB anchors (0x6290B000, 0x6290E000, 0x62A05000).
- **0** fall in 0x60000000–0x70000000, 0x200000000–0x300000000, 0x800000000–0x900000000,
  or 0x10000000–0x400000000.

## Interpretation

The 4–16 GB guest-physical window is **encrypted**. This is consistent with the 8.00+ HV
relocation: the hypervisor's own memory in this range is either (a) encrypted in DRAM and only
decrypted on access under the HV's key, or (b) the dump tool captured this range through a path
that returns ciphertext. Either way, a plaintext VCPU array cannot be recovered from these
chunks — the VCPU array is not here in recoverable form, so this range is **ruled out** as a
plaintext source of VMCB host-PAs.

**What to do instead:**
1. Re-dump the same range through a path that returns **decrypted** memory (if the encryption is
   a dump-artifact rather than true at-rest DRAM encryption).
2. If the HV genuinely encrypts at rest, the VCPU array must be located via the **lower** ranges
   already partially dumped (0x07d00000–0x60000000) or by dumping the still-uncovered
   0x60000000–0x10ba00000 window (the 1.5–4.2 GB band, which includes the old 0x62xxxxxx VMCB
   region) to see whether *that* band is plaintext.

## Method / artifacts
- `scan_vcpu_4_16gb.py` — constant-stride 8/16-window VMCB-array scan (NumPy). → 0 hits.
- `entropy_4_16gb.py` — global byte entropy + u64 high-nibble distribution. → 8.0000 bits/byte.
- `outlier_4_16gb.py` — per-file entropy/zero outliers + aligned-value host-PA band search. → 0.
- `vcpu_4_16gb_conststride.json` — (empty) candidate list.
- No network access used; entirely offline.
