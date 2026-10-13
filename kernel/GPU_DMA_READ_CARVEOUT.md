# GPU-DMA READ of the HV carve-out — 13.60 (result)

**Date:** 2026-10-06 · **Console:** 10.0.0.x (13.60, fw `0x13600007`), now KERNEL-PANICKED (KP, see §6)
**Payload:** `scratch/ps5/probe90/gpread90.elf` (main2.c/main3.c) — fresh-victim GPU-DMA READ
**Result:** ✅ **READ bypasses the CPU NPT** (confirmed) · ❌ **VMCB guest-PA not recovered** (HV data is encrypted at rest)

---

## 1. Bottom line

1. **The GPU-DMA READ primitive works and BYPASSES the CPU NPT.** Retargeting a garlic
   victim leaf to a physical address with **bit 50 ("system coherent") set** and issuing
   `PACKET3_DMA_DATA` (opcode 0x50, header `0xC0055002`, dma-header `0x8C00C000`) with
   `src=victim.gva+off`, `dst=staging.gva` copies arbitrary physical memory into a
   CPU-readable staging buffer. Verified byte-for-byte against `kernel_copyout` of kernel
   `.data` (T-A MATCH), then used to read the carve-out where `kernel_copyout` returns −1.
2. **The GPU read of the carve-out returned real data** (no panic, no −1/trap): a 288 MB
   dump of `0x60000000–0x72000000` with 31+ distinct 1 MB chunks of kernel-pointer tables,
   ASCII log/string data, and high-entropy (encrypted) blobs.
3. **No plaintext AMD VMCB was found** anywhere in the dump. The trapped/protected region
   (CPU `kernel_copyout` **panics** there) starts at **0x60600000** and contains a ~2 MB
   **uniformly high-entropy (≈7.96 bit/byte) block** — the HV's own data is **encrypted at
   rest**, so a standard VMCB control-area/save-area signature scan returns nothing.

---

## 2. What the READ primitive is (confirmed live)

| step | value (this boot) |
|---|---|
| kdata_base | `0xffffffffc88e0000` |
| DMAP base | `0xffffacd800000000` |
| dev vmid | 6 |
| victim garlic leaf | `gva=0x200800000 phys=0x47bc004c0 pte_pa=0xde79020 raw=0x004000047bc004f7 is_2m=1` |
| retarget recipe | `new = (old & ~0x0000FFFFFFE00000) | (base & 0x0000FFFFFFE00000) | (1ull<<50)` |
| packet | type3 hdr `0xC0055002`, dma hdr `0x8C00C000`, src/dst = GPU VAs, len ≤ 0x1FFFFF |
| submit | `ioctl(/dev/gc, 0xC0108102, {0, 1, &desc})`, `usleep(300ms)` |

**T-A READ-KNOWN** (retarget victim → `kdata` PA `0x8800000` + bit50, DMA 4 KB → staging):
`ioctl=0 match=1` — staging bytes identical to `kernel_copyout(kdata)`. **This proves the
READ direction + bit50 against a known system-RAM page.**

---

## 3. GPU TLB staleness (the v1 bug that cost a dump)

The first sweep re-targeted the **same** victim leaf 256× and produced only **two** distinct
1 MB chunks (the 2nd+ retargets were ignored — the GPU TLB caches `victim.gva → first phys`).
Fixed by allocating **one fresh 2 MB garlic victim per carve-out chunk** (each leaf
retargeted exactly once). Garlic pool caps at ~54 MB (~27 × 2 MB buffers), so the 288 MB
dump was taken in six 48 MB segments via `/data/gpread90_cfg.txt` (base-offset config, no
recompile).

Dump files (local): `scratch/ps5/carveout_60000000.bin`, `..._63000000.bin`,
`..._66000000.bin`, `..._69000000.bin`, `..._6c000000.bin`, `..._6f000000.bin`
(48 MB each; last one overshoots to 0x72000000).

---

## 4. Carve-out content (0x60000000–0x72000000, offline analysis)

| PA range | content |
|---|---|
| 0x60000000–0x60600000 | CPU `-1` (NPT carve-out). GPU read: 0xFF fill + a 24-byte-stride function-pointer table at 0x60100000 (`{u64 8, 0xffffffff81xxxxxx, 0xffffffff80xxxxxx}` — guest-kernel link-time text pointers, NOT the guest sysent, verified vs `kdata_1360.bin`) |
| **0x60600000–0x607FFFFF** | **CPU PANICS here.** GPU read: **2 MB of entropy ≈7.96 (encrypted)** — the HV's protected data (VMCB / NPT / TMR region), ciphertext at rest |
| 0x60800000–0x60bFFFFF | all-zero (empty) |
| 0x60c00000–0x60e6FFFFF | low-entropy (≈2–3) structured data — length-prefixed ASCII log/string records |
| 0x62200000, 0x64900000, 0x66400000, 0x6a000000, … | scattered 1 MB high-entropy (encrypted) blobs |
| rest | 0xFF fill and zeros |

---

## 5. VMCB search — negative

Searched all 288 MB for the AMD VMCB (control area `nested_ctl@0x90` bit0 = NP_ENABLE,
`nCR3@0xB0` 4 KB-aligned, `ASID@0x58`, `iopm@0x40`/`msrpm@0x48`; save area `CS@0x410`,
`CR0@0x558`, `EFER@0x4D0`). **Result: zero clean candidates** (43 loose hits, all with
garbage `nCR3`). The HV's VMCB/NPT/TMR data is **encrypted at rest** (the trapped region is
max-entropy ciphertext), so a plaintext signature match is impossible without first
recovering the HV's encryption scheme.

**Best lead for the VMCB guest-PA:** the trapped/protected region begins at **0x60600000**
(the CPU `kernel_copyout` panic point) — per the research model this is where the VMCB /
NPT structures / TMR live. It is the only region the CPU hard-panics on, and it reads as
encrypted ciphertext through the GPU.

---

## 6. Console status — KP (my error, documented)

The `boundary.elf` probe swept `kernel_copyout` over `0x60000000..0x72000000` at 1 MB
steps to map the carve-out. It logged `-1` for `0x60000000–0x605FFFFF`, then **hard-panicked
at 0x60600000** (the trapped page) — this is exactly the panic the research warns about
("present-but-permission-stripped → HARD PANIC"), and CPU reads of the carve-out are NOT a
safe channel. 2121/9021/3232 all down. **The GPU-DMA READ is the only safe channel for the
carve-out.** Recoverable by user cold-boot + re-JB (`sk`).

---

## 7. Conclusion

- **`read_bypasses_npt = true`** — proven: GPU-DMA READ returned real physical content from
  the region where `kernel_copyout` returns −1 (0x60000000) and where it hard-panics
  (0x60600000), with no trap and no panic.
- **`vmcb_pa_found = false`** — the carve-out dump contains no plaintext VMCB; the HV's
  protected memory is encrypted at rest (max-entropy at the trapped region 0x60600000+).
- Next steps (after `sk`): (a) do **not** CPU-sweep the carve-out again; (b) either recover
  the HV's in-memory encryption to decrypt the 0x60600000 blob, or locate a plaintext VMCB
  elsewhere (e.g. above 0x72000000 via more GPU-DMA segments); (c) once the VMCB guest-PA is
  known, the existing GPU-DMA **write** primitive (`probe89/vmid7.elf`, KDATA-WRITE-PASS)
  retargets → `VMCB+0x90` with bit50 and stores 0 to clear NP_ENABLE.
