# GPUVM offsets — PS5 firmware 13.60

Derived **offline** (own console), 2026-10-05, for `probe73/gpuread.elf` (GPU-DMA read of
kernel `.text` via the GPUVM path). Values below are for **13.60** only; every other firmware
needs its own numbers.

## TL;DR

| Symbol | 13.60 value | Confidence | Source / basis |
|---|---|---|---|
| `OFFSET_VMSPACE_VM_VMID` | **`0x1EC`** | **high (derived)** | 0x1E4 (≤4.51, public) + the documented +8 struct shift at 6.00; stable 6.00→13.60 |
| `OFFSET_DATA_GVMSPACE` | **`0x2E7E570`** (closest confirmed = 12.00) | **low (NOT pinned for 13.60)** | last public value; 13.60 not publicly available, not in the 15 MB dump |

`OFFSET_DATA_GVMSPACE` is the one value that could **not** be pinned for 13.60. Read §3 before
running the payload with it.

---

## 1. `OFFSET_VMSPACE_VM_VMID = 0x1EC` (offset of `u32 vm_vmid` in `struct vmspace`)

`vm_vmid` is a **Sony addition** placed at the **tail of the embedded `struct vm_map`**, i.e.
*after* the `vm_map.pmap` **pointer** field and *before* the inline `struct pmap vm_pmap`
(which sits at the end of `vmspace`). It is a `u32` holding a small index (1..0x10), read via
`kernel_getint(vmspace + OFFSET_VMSPACE_VM_VMID)`.

### The public anchor (firmware ≤ 4.51)

Multiple independent, cross-checked sources use the same two values on 1.00–4.51 (the only
firmwares where the GPU-DMA path is fully public and proven):

- **cragson/ps5-hen** `offsets.h`: `VMSPACE_VM_VMID = 0x1E4`, `VMSPACE_VM_PMAP = 0x1D0`
  (every entry 2.50–4.51).
- **ps5-linux-loader** `source/offsets.c`: `.VMSPACE_VM_VMID = 0x1E4`, `.VMSPACE_VM_PMAP = 0x1D0`
  (every entry 3.00–4.51).
- hammer-83 / EchoStretch `kernel_offset.lua` runtime finder
  `find_vmspace_vmid_offset()`: scans **0x1D4..0x1F4** (step 4) for a dword in [1,0x10] —
  the field is at `0x1E4` on 1.xx, "assumed only increasing" on later FW.

Note: ps5-hen's `VMSPACE_VM_PMAP = 0x1D0` is the **`vm_map.pmap` pointer** (the `pmap_t pmap`
field inside the embedded `vm_map`), *not* the inline pmap struct. This is a different convention
from the ps5-payload-sdk `KERNEL_OFFSET_VMSPACE_VM_PMAP`, which is the **inline** `struct pmap`
(see §1.2).

### The 6.00 struct shift (this is what moves `vm_vmid`)

ps5-payload-sdk `crt/kernel.c` records the *inline-pmap* offset per firmware:

| firmware | `P_ROOT` (vm_map.root) | `VM_PMAP` (inline pmap) |
|---|---|---|
| 1.00–1.02 | `0x1c0` | `0x2c0` |
| 1.05–5.50 | `0x1c8` | `0x2e0` |
| **6.00–13.60** | **`0x1d0`** | **`0x2e8`** |

Between 5.50 and 6.00 Sony added **one 8-byte field to `vm_map` before `root`**, shifting every
later field by +8: `root` `0x1c8→0x1d0`, the `pmap` pointer `0x1d0→0x1d8`, the inline pmap
`0x2e0→0x2e8`. `P_ROOT` and `VM_PMAP` are then **constant from 6.00 through 13.60** (SDK cases
6.00, 7.61, 8.x, 9.x, 10.x, 11.x, 12.x, 13.00/13.20/13.40/13.60 all = `0x1d0`/`0x2e8`).

Cross-check that the `pmap` **pointer** moved `0x1d0→0x1d8` at 6.00: **ps5-linux-loader**
`off_0761` sets `.VMSPACE_VM_PMAP = 0x1D8` (vs `0x1D0` for ≤5.10). ✓

`vm_vmid` is 0x14 bytes **after** the `pmap` pointer (0x1E4 − 0x1D0 = 0x14 on ≤4.51), so it
shifts by the same +8:

```
0x1D0 + 0x14 = 0x1E4   (≤ 5.50)
0x1D8 + 0x14 = 0x1EC   (6.00 – 13.60)   ← ANSWER
```

### Why the "~0x2F0" guess is wrong

`vm_vmid` is **not** after the inline `struct pmap`. On ≤4.51 the inline pmap is at `0x2e0`
(SDK) while `vm_vmid` is at `0x1e4` — i.e. `vm_vmid` is *before* the inline pmap, in `vm_map`'s
tail, ~0x14 after the `pmap` pointer. The hammer-83 finder (which works ≤10.00) scans
0x1D4..0x1F4 for it, confirming it never migrated past the inline pmap.

### Confirm on hardware (60 s)

```
vmid = kernel_getint(vmspace + 0x1EC)   // expect 1..0x10, and it must index a valid gvmspace[]
```
If 0x1EC reads 0 or >0x10, step the offset through 0x1E8/0x1E4/0x1F0/0x1F4 (the dword scan the
public finder uses) and take the first value in [1,0x10].

---

## 2. `OFFSET_DATA_GVMSPACE` — the `.data` offset of the `gvmspace` array (`gbase_vmspaces`)

`gvmspace` is a **`.data` global**, `kdata_base + OFFSET_DATA_GVMSPACE`, indexed by VMID.
Entry stride is **`0x100`** on 2.00+ (`sizeof_gvmspace = fw<0x200 ? 0xF8 : 0x100`, ps5-hen
`hv_defeat.cpp`), fields `start_va@0x08`, `size@0x10`, `page_dir_va@0x38` (the GPU PDB2/PML4,
stored as a **kernel/DMAP VA** — see below), as in ps5-linux-loader `gpu.c`.

### Public values (offset from `kdata_base` = the `.data` base)

| firmware | `DATA_BASE_GVMSPACE` | source |
|---|---|---|
| 9.00/9.05–9.60 | `0x02D8A570` | YarP2JB / EchoStretch |
| 10.00/10.01–10.60 | `0x02D52570` | YarP2JB / EchoStretch |
| 11.00–11.60 | `0x02E66570` | YarP2JB (`FW_OFFSETS_P2JB`) |
| **12.00–12.70** | **`0x02E7E570`** | YarP2JB (working GPU PM4 DMA, 9.00–12.70) |
| **13.60** | **not published** | — |

YarP2JB's convention matches ps5-payload-sdk's `kdata_base` convention exactly
(its 12.00 `ALLPROC = 0x02885E00` == SDK 12.00 `ALLPROC = 0x2885E00`), so these are directly
comparable to the `payload_get_args()->kdata_base_addr` used in `main.c`.

### 13.60 is NOT in the local dump — verified negative

`kdata_1360.bin` is **15,728,640 bytes (0xF00000) = the first 15 MB of `.data`**. The `gvmspace`
array has sat at **~47–49 MB** into `.data` since 7.00 (`0x2E76090`…`0x2E7E570`), so it is
**outside** the dump. A full scan of `kdata_1360.bin` for a run of `0x100`-strided records with a
page-aligned (0x1000) `page_dir_va` at field offsets 0x08–0x40 (stride 0x28–0x100) returned
**zero** candidates — the array is simply not in the file.

(The 0x28-byte-strided array at `.data` offset `0x1D2B00` — huge GPU VAs `0x164000000000…`
incrementing by 256 GB, sizes 2 GB/1 GB/64 MB, a kernel-fn VA at +0x18 — is the **direct-memory
region table**, *not* `gvmspace`.)

### 13.60 estimate

The 12.00→13.60 `.data` drift is small in the `kdata_base` convention (SDK: `ALLPROC`
`0x2885E00→0x28C9E80`, i.e. **+0x44480**; `BUS_DATA_DEVICES` +0x22A40). `gvmspace` sits
~0x61600 after `kernel_pmap_store` (stable 10.00–12.00: 0x61678/0x61658/0x615B8). Extrapolating
the same small drift gives:

```
OFFSET_DATA_GVMSPACE (13.60) ≈ 0x2E80000 – 0x2EC0000     (best guess ~0x2E90000)
```

**This is a guess, not a measured value.** Do not run the read payload against it blind — it is
only safe because `main.c` bounds-checks `page_dir_va` and bails out (no panic) on garbage.

### How to confirm exactly (the only correct way)

1. **Dump the full `.data`** — not the 15 MB window: `kernel_copyout` from
   `kdata_base + 0x2E00000` for ~0x200000 bytes (48 MB in), and scan that for the array
   (0x100-stride records, `page_dir_va@0x38` = a page-aligned **kernel/DMAP VA**, i.e.
   `0xffffff80…`/`0xfffffffe…` canonical, 0x1000-aligned, distinct per VMID).
2. **Runtime anchor** (no dump needed): with kernel r/w, walk the current process's GPU PDB2
   from a known-mapped GPU buffer — i.e. compute `gvmspace_base = gbase_vmspaces` as the value
   that makes `gvmspace[vmid].page_dir_va` a page-aligned DMAP VA whose walked PDEs yield the
   victim buffer's real physical address (the `gpu_find_leaf` self-check in `main.c` already
   compares leaf PA vs victim PA — the payload aborts on mismatch, so it is safe to probe).
3. Quick delta check: if you can run on 12.00 and 13.60 side by side, `0x2E7E570 + delta` where
   `delta` = (13.60 `ALLPROC` − 12.00 `ALLPROC`) = `0x44480` → `≈ 0x2EBF9F0`. This is the single
   most defensible extrapolation point; treat anything in `[0x2E80000, 0x2EC0000]` as a probe
   candidate.

---

## 3. What was patched into `probe73/main.c`

```c
#define OFFSET_VMSPACE_VM_VMID  0x1EC      /* derived (see §1) */
#define OFFSET_DATA_GVMSPACE    0x2E7E570  /* 12.00 confirmed — 13.60 UNVERIFIED (see §2) */
```

`OFFSET_VMSPACE_VM_VMID` is considered good to run. `OFFSET_DATA_GVMSPACE` is left at the closest
confirmed value (12.00) with a loud comment; it will most likely need the 13.60 value from §2's
confirmation procedure before the read succeeds — but a wrong value degrades to a clean bail-out,
never a panic.

## 4. References

- cragson/ps5-hen `offsets.h` / `gpu_dma.h` / `hv_defeat.cpp`
- ps5-linux/ps5-linux-loader `source/offsets.c`, `source/gpu.c`, `include/gpu.h`
- matem6/YarP2JB `p2jb.py` (`FW_OFFSETS_P2JB`: 9.00–12.70 `DATA_BASE_GVMSPACE`)
- EchoStretch/remote_lua_loader + itsPLK `kernel_offset.lua` (hammer-83 runtime finders)
- ps5-payload-dev/sdk `crt/kernel.c` (per-firmware `P_ROOT`/`VM_PMAP`, incl. 13.60 = 0x1d0/0x2e8)
- X1NON-PSJB `offsets/kernel/data.js` (13.40), `offsets/structs/offsets.js`
- local: `Caliper-C0re/kernel/offsets_13.60.js` (Relapse 13.60), `OFFSET_COMPARISON.md`,
  `DATA_DIFF_761_1360.md`, `FIRMWARE_DIFF.md`
