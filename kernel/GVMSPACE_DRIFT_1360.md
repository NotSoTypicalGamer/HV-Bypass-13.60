# GVMSPACE drift — 7.61 / 11.60 / 13.60, and the corrected 13.60 offset

**Result:** `OFFSET_DATA_GVMSPACE` (13.60) = **`0x2EEA570`** — *measured*, not estimated.
Drift from 12.00/12.70 (`0x2E7E570`) = **`+0x6C000`** (442,368 B).
The prior estimate (`0x2E80000–0x2EC0000`, best `0x2EC29F0`) was **~0x2A570 too low**.

---

## 1. TL;DR

| Symbol | 12.70 | 13.60 | drift | basis |
|---|---|---|---|---|
| `OFFSET_DATA_GVMSPACE` | `0x2E7E570` | **`0x2EEA570`** | `+0x6C000` | **measured in the live 16 MB dump** |
| `kernel_pmap_store` | `0x2E1CFB8` | `0x2E88F70` (derived) | `+0x6C000` | `gvmspace − 0x61600` (stable gap) |
| `idt` | `0x2E88300` | `0x2EF4300` | `+0x6C000` | **measured (256-entry IDT signature)** |
| `allproc` | `0x2885E00` | `0x28C9E80` | `+0x44080` | Relapse 13.60 `0x03589E80` − `KERNEL_DATA 0xCC0000` |
| `rootvnode` | `0x30D7510` | `0x314B510` | `+0x74000` | Relapse 13.60 `0x03E0B510` − `0xCC0000` |

All offsets are **`kdata_base`-relative** (the `.data`-segment base that `payload_get_args()->kdata_base_addr`
returns, and the base the 15 MB dumps start at). This is the *same* convention as YarP2JB's
`DATA_BASE_GVMSPACE` and ps5-payload-dev-SDK `ALLPROC`/`KERNEL_PMAP_STORE`.

---

## 2. How the offset was measured (not guessed)

The three 15 MB dumps (`kdata_761.bin` / `kdata_1160.bin` / `kdata_1360.bin`, each `0xF00000` bytes) do
**not** contain `gvmspace` — it sits at ~48–49 MB into `.data` (see §4). But the live 16 MB dump
`gvmspace_1360_dump.bin` (`.data` offsets `0x2E00000–0x2F00000`) **does** contain the array. It was found
by anchoring on a structure that *is* in the dump:

1. **The IDT is found at `.data` `0x2EF4300`** (file offset `0xF4300`) — 256 consecutive 16-byte gate
   descriptors with the exact IDT format (`dwords 0x2000`, `ist<8`, type `0x8E/0xEE`,
   upper 8 bytes `0xFFFFFFFF00000000`). A 256-entry exact match is effectively impossible to hit by
   accident; it is a true positive.
2. **`gvmspace` sits a stable `0x9D90` below the IDT.** Verified across firmware where both are known:
   - 11.60: `idt 0x2E70300 − gvmspace 0x2E66570 = 0x9D90`
   - 12.70: `idt 0x2E88300 − gvmspace 0x2E7E570 = 0x9D90`
   - 13.60: `idt 0x2EF4300 − gvmspace 0x2EEA570 = 0x9D90` ✓
   (7.61 used `0x9D60`; the +0x30 difference is the pre-6.00→7.00 structural shift and does not apply to 11.60+.)
3. Therefore **`gvmspace = 0x2EF4300 − 0x9D90 = 0x2EEA570`**, verified in-place against the array's own
   signature (next section).

### In-place verification of the array at `0x2EEA570`

| field | offset | observed | meaning |
|---|---|---|---|
| vmid/state | `+0x00` | `0x0, 0x20, 0x2, 0x3, 0x4, 0x5, 0x20…` | `0x0`=VMID0 active, `0x20`=free slot, `n`=VMID n active |
| `start_va` | `+0x08` | `0x0` (all) | GPU VA space starts at 0 — **not** a "huge GPU VA" |
| `size` | `+0x10` | `0xFC00000000` (VMID0), `0x1000000000000` (VMID 2–5) | GPU VA-space size (VMID0 ~1 TB, apps 2⁴⁸) |
| active | `+0x18` | `0x1` | active flag |
| GPU PDB2 phys | `+0x28` / `+0x30` | `0x17E98000` (+`0x4000`/entry) | GPU page-directory physical (16 KB stride) |
| `page_dir_va` | `+0x38` | `0xFFFFFF80A0C98000` (+`0x4000`/entry) | **kernel VA of the PDB2** — the discriminator |

16 entries × `0x100` stride (VMID 0–15; `vm_vmid` indexes 1..0x10, VMID 0 = the system GPU VM). At the
dump instant VMIDs 0,2,3,4,5 were live, the rest free — a menu-state console, exactly as expected.
`page_dir_va@0x38` is a **`0xffffff80…` page-aligned kernel VA, distinct per entry, 16 KB stride** — this
is the field the GPU-DMA primitive reads, and it matches the documented signature
(`0xffffff80…/0xfffffffe…`, 0x1000-aligned, distinct per VMID).

---

## 3. The drift model (anchors, 7.61 → 11.60 → 13.60)

Anchor offsets in the `kdata_base` convention (7.61/11.60 from YarP2JB + kstuff `prosper0gdb/offsets/`;
12.70 from kstuff; 13.60 from Relapse + this measurement):

| anchor (conv. A) | 7.61 | 11.60 | 12.70 | 13.60 |
|---|---|---|---|---|
| `security_flags` | `0x0AC8064` | `0x0D8C064` | `0x0D83064` | `0x0D9C064` |
| `allproc` | `0x2859D50` | `0x2875D70` | `0x2885E00` | `0x28C9E80` |
| `kernel_pmap_store` | `0x2E2C848` | `0x2E04F18` | `0x2E1CFB8` | `0x2E88F70`* |
| **`gvmspace`** | `0x2E76090` | `0x2E66570` | `0x2E7E570` | **`0x2EEA570`** |
| `idt` | `0x2E7FDF0` | `0x2E70300` | `0x2E88300` | `0x2EF4300` |
| `rootvnode` | `0x30C7510` | `0x30B7510` | `0x30D7510` | `0x314B510` |

(* `kernel_pmap_store` 13.60 derived from the stable `gvmspace − 0x61600` gap, §4.)

**Key property: drift is monotonic in offset.** `gvmspace` has drifted *non-monotonically* across the
7.00→12.70 span (shrink-then-grow: `−0x11FB20`, `−0x38000`, `+0x114000`, `+0x18000`), because each
Sony release re-lays-out `.data`. The 12.70→13.60 step is a large **+0x6C000** for the whole
`gvmspace`/`idt`/`pcpu` cluster, but only **+0x44080** for `allproc` (an 8.7 MB earlier region). The
region *between* `allproc` and `gvmspace` grew ~0x27B80; the region between `gvmspace` and `rootvnode`
grew ~0x8000. That is why anchoring `gvmspace` on `allproc`'s drift under-predicts it.

---

## 4. Why the prior estimate was wrong

`GPUVM_OFFSETS_1360.md` extrapolated `gvmspace ≈ 0x2E7E570 + (allproc drift) = 0x2E7E570 + 0x44480 ≈ 0x2EC29F0`
and proposed probing `[0x2E80000, 0x2EC0000]`. Two mistakes:

1. **Wrong anchor.** `allproc` (`0x2885E00`, 42.5 MB) is ~6.3 MB *below* `gvmspace` (`0x2E7E570`, 48.7 MB).
   Applying `allproc`'s drift to `gvmspace` assumes the 6.3 MB in between is unchanged in size. It isn't:
   it grew ~0x27B80, so `gvmspace` drifts **+0x6C000**, not **+0x44480**.
2. **The estimate range is entirely below the true value.** True `0x2EEA570` is `0x2A570` above the
   estimate's upper bound `0x2EC0000` (and `0x6A570` above its lower bound `0x2E80000`).

---

## 5. Why the live 16 MB scan "found nothing"

The dump `gvmspace_1360_dump.bin` (`.data 0x2E00000–0x2F00000`) **does** contain the array at `0x2EEA570`.
The negative result had two independent causes:

1. **Drift under-estimated → searched too low.** The array moved to `0x2EEA570`, ~0x2A570 past the
   estimate's `0x2EC0000` ceiling. Anything validating only the `[0x2E80000, 0x2EC0000]` window misses it.
2. **Wrong signature.** The scan used "`start_va@0x08` = huge GPU VA" as a discriminator. That signature
   belongs to the **direct-memory region table** (0x28-byte stride, `0x164000000000…` VAs, at `.data
   0x1D2B00` — see `DATA_DIFF_761_1360.md §2`), **not** `gvmspace`. On 13.60 (and every firmware where
   the GPU VA base is 0) `gvmspace`'s `start_va@0x08` is **`0x0`**; the correct discriminator is
   `page_dir_va@0x38` = a `0xffffff80…`/`0xfffffffe…` **page-aligned kernel VA** (see §2 table). A scan
   keyed on `start_va` correctly returns zero.

Either cause alone produces a false negative; both were present.

---

## 6. Corrected value and defensible range

- **`OFFSET_DATA_GVMSPACE` (13.60) = `0x2EEA570`** (VMID 0 entry; `+0x00 = 0x0`, `+0x18 = 0x1`,
  `page_dir_va@0x38 = 0xFFFFFF80A0C98000`).
- The array is 16 × `0x100` = `0x1000` bytes, spanning `0x2EEA570 – 0x2EEB570`.
- **Probe range `[0x2EEA000, 0x2EEB000]`** (an entry stride of slack either side) is safe to scan.
- Confidence: **high** — the value is pinned to the IDT anchor (measured) and a gap (`0x9D90`) that is
  byte-stable across 11.60/12.70/13.60, and the in-place content matches the documented `gvmspace`
  layout field-for-field.
- `kernel_pmap_store` (13.60) ≈ **`0x2E88F70`** (`gvmspace − 0x61600`; gap stable 8.00–12.70 at
  `0x615B8–0x61678`).

### Field layout correction for 13.60

| offset | field | 13.60 value |
|---|---|---|
| `+0x00` | vmid/state (`0x0`/`n`=live, `0x20`=free) | varies |
| `+0x08` | `start_va` | **`0x0`** (not a huge GPU VA) |
| `+0x10` | `size` | `0xFC00000000` (VMID0) / `0x1000000000000` (apps) |
| `+0x18` | active flag | `0x1` |
| `+0x28`,`+0x30` | GPU PDB2 physical | `0x17E98000` (+0x4000/entry) |
| `+0x38` | `page_dir_va` (kernel VA) | `0xFFFFFF80A0C98000` (+0x4000/entry) |

`OFFSET_VMSPACE_VM_VMID = 0x1EC` is unchanged (struct-field offset, independent of `.data` layout).

---

## 7. References

- YarP2JB / kstuff `prosper0gdb/offsets/{7_61,11_60,12_70}.h` — `allproc`/`kernel_pmap_store`/`idt`
  per firmware (kdata_base convention).
- `Star_Wars_Racer_Revenge_…/lua/offsets.lua` — `DATA_BASE`/`GVMSPACE`/`KERNEL_PMAP_STORE` 4.00–12.00.
- ntfargo/Relapse-Exploit `offsets/13.60.js` — 13.60 `ALLPROC 0x03589E80`, `KERNEL_DATA 0xCC0000`,
  `ROOTVNODE 0x03E0B510`; slopkit/X1NON `data.js` — `BUS_DATA_DEVICES 0x02D481E8`.
- Local: `gvmspace_1360_dump.bin` (16 MB live dump), `GPUVM_OFFSETS_1360.md` (superseded estimate),
  `DATA_DIFF_761_1360.md`.
