# ACPI IVRS / AMD-Vi IOMMU MMIO Search — Findings

**Date:** 2026-10-05 · **Firmware:** PS5 13.60 · **Scope:** offline scan of guest-physical memory dumps
**Result:** **ACPI tables (RSDP/XSDT/IVRS chain) are NOT present in the captured guest-PA range. The AMD-Vi IOMMU MMIO base PA could NOT be recovered from these dumps.**

---

## 1. Inputs scanned

Directory: `C:\Users\USER\Caliper-C0re\kernel\hv_dump\`

- `hvdump_0x26000000_600MB.bin` — contiguous 608 MiB, guest-PA base `0x26000000` (covers `0x26000000`–`0x4C000000`).
- 186 sparse 1 MiB `hvcluster_<hex>.bin` chunks below 4 GiB (`0x07d00000` … `0x5ff00000`).
- 126 sparse 1 MiB chunks in the 4–16 GiB range (`hvcluster_10ba00000.bin` … `hvcluster_3fc000000.bin`, i.e. `0x10ba00000`–`0x3fc000000` ≈ 4.27–15.94 GiB).
- `kernel_text_0xffffffff80200000.bin` — 0 bytes (empty).

Total: **313 non-empty files, ~965 MiB (0x39800000 bytes)** of guest physical memory. All 126 high chunks verified non-trivial (≈99.6 % non-zero bytes each), so the high region was genuinely scanned, not just zero-filled.

## 2. Method

1. Byte-exact signature scan over every file for `RSD PTR `, `XSDT`, `RSDT`, `IVRS`, `IVHD`, `FACP`, `DSDT`, plus `SSDT`, `MADT`, `APIC`, `FACS`, `MCFG`, `BGRT`, `HPET`, `WAET`, `CRAT`, `CDIT`, `SRAT`, `SLIT`, `DMAR`, `HEST`, `BERT`, `ERST`, `FPDT`, `GTDT`, `NFIT`, `WSMT`, `SPMI`, `DBG2`, `UEFI`, `BOOT`, `SLIC`, `MSDM`.
2. Checksum-validated ACPI header parse: for every known-signature hit, checked `sig[4] + length(u32 LE) + revision[1] + checksum(sum==0)`.
3. Broad "table-like structure" scan (signature absent): regex over every file for any 4-char printable signature with `length ∈ [36, 0x100000]`, `revision ≤ 30`, in-bounds, then checksum over the declared length.
4. SMBIOS / UEFI firmware blob probe (`_SM_`, `_SM3_`, `_DMI_`, `UEFI PLATFORM`, `AMDI`, `AMD `, `AMDIOMMU`, `SEATTLE`, `Oberon`).

## 3. Results

| Signature | Hits | Verdict |
|---|---|---|
| `RSD PTR ` (RSDP) | **0** | absent |
| `XSDT` / `RSDT` | **0** | absent |
| `FACP` / `FACS` / `MADT` / `APIC` | **0** | absent |
| `IVHD` | **0** | absent |
| `MCFG` / `HPET` / `BGRT` / `SRAT` / `CRAT` / `DMAR` … | **0** | absent |
| `IVRS` | 17 | **all false positives** — substring of the string `"VshNMSystemShellUIVRSupportModule"` (and `"onVRModeChangedVshNMSystemShellUIVRSupportModuleH"`). No real IVRS table header. |
| `DSDT` / `SSDT` | 158 / 148 | fragments embedded in high-entropy (obfuscated/encrypted-looking) data; **not** valid table headers. |
| `_SM_` / `_SM3_` / `UEFI PLATFORM` / `AMDI` / `AMDIOMMU` | **0** | no firmware/SMBIOS blob captured |

- **Checksum-validated ACPI header scan (known signatures): 0 valid tables.**
- **Broad table-like-structure scan:** 53 structures with a coincidental zero-checksum, but all carry garbage signatures (`UUUU`, `DETE`, `IH8Y`, `HHHH`, `NULL`, `ENT_`, `URLA`, `GREE`, …) — none are ACPI tables. 194 922 further candidates with non-zero checksum, all random/false.
- The `DSDT`/`SSDT` bytes sit inside high-entropy regions whose surrounding bytes are non-ASCII (e.g. `cd dc fc 0b d9 70 ed ff f0 10 20 11 33 41 33 34 44 53 44 54 2a 00 …`). Identical 64-byte sequences recur at multiple guest-PAs (e.g. `0x15685f9c` and `0x2d493c8c`), consistent with the FreeBSD/Orbis kernel ACPI driver (`hwacpi` string is present) holding AML in an obfuscated/encrypted form — but **no table header survives**.

## 4. Conclusion

The ACPI table chain — RSDP → XSDT/RSDT → IVRS → IVHD (`BaseAddress` u64 at IVHD+0x08 per AMD IOMMU spec; task's +0x28 offset corresponds to the IVHD type-10h `DeviceId/CapOffset/BaseAddr` region and was checked too) — is **not recoverable from the captured guest-PA range**:

- No RSDP, no XSDT/RSDT, no FACP/FACS/MADT, no IVRS/IVHD anywhere in ~965 MiB of guest physical memory spanning `0x07d00000`–`0x3fc000000`.
- On PS5 the ACPI tables and the AMD-Vi IOMMU are owned by the **hypervisor**, not the guest; the tables live in hypervisor/firmware-reserved memory at high physical addresses that are not part of the guest's physical address space (and the guest's own AML copies appear obfuscated/encrypted).

**AMD-Vi IOMMU MMIO base PA: NOT RECOVERED from these dumps.** To obtain it, capture the hypervisor/firmware memory (or read the IVRS directly from the hypervisor's ACPI region), not guest-PA.

## 5. Artifacts

- `ivrs_scan.py` — signature scan across all dumps.
- `ivrs_parse.py` — context dumps + checksum-validated known-signature parse.
- `ivrs_broad2.py` — broad "table-like structure" (signature-agnostic, checksum-validated) scan.
- `ACPI_IVRS_SEARCH.md` — this document.
