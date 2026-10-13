# GPUVM offsets — PS5 firmware 13.60 (v2, live-data revision)

Revised **offline** from two live artifacts captured 2026-10-05 from a single 13.60 boot
(own console, nothing published):

- `vmspace_dump.json` — 40 × u64 of the running process's `struct vmspace`, offsets
  `0x1C0..0x300`.
- `gvmspace_1360_dump.bin` — 16 MiB (`0x1000000`) of kernel `.data`.
  `probe81/main.c` sets `SCAN_BASE = 0x2F00000`, i.e. the file is
  **`.data[0x2F00000 .. 0x3000000)`** (49.3–50.3 MB). The earlier task notes called the
  window `kdata_base+0x2E00000..0x2F00000`; the probe source is authoritative, and the
  conclusion below does not depend on the ±1 MiB ambiguity because the decisive evidence is
  the *absence* of the live process's own GPU page-directory values in the file.

`kdata_base` for the boot = `0xffffffff90470000`. DMAP base = `0xffffff8000000000`.

---

## TL;DR

| Symbol | 13.60 value | Confidence | Basis |
|---|---|---|---|
| `OFFSET_VMSPACE_VM_VMID` | **`0x1FC`** | **high (measured)** | live dump: `vmspace+0x1FC == 2` (see §1) |
| `OFFSET_DATA_GVMSPACE` | **NOT in the 16 MiB dump** | n/a (negative result) | live process's page-dir PAs absent; 12.00 value zeroed (see §2) |

The prior `0x1EC` for `vm_vmid` is **wrong** (that dword is `0xFFFFFFFF`, the high half of a
Sony sentinel). The prior `0x2E7E570` for `gvmspace` is the **12.00** value; it is zeroed on
13.60 and the array is not in this dump.

---

## 1. `OFFSET_VMSPACE_VM_VMID = 0x1FC` (measured)

### 1.1 Full vmspace dump, mapped to FreeBSD 11.0

The dump maps **cleanly** to the FreeBSD 11.0 `vmspace` order
(`{vm_map; vm_shm; vm_swrss; vm_tsize; vm_dsize; vm_ssize; vm_taddr; vm_daddr;
vm_maxsaddr; vm_refcnt; inline pmap}`):

```
0x1D0: FFFFF62265C09D60   vm_map.root  (RB-tree root, kernel-heap ptr)   [P_ROOT = 0x1D0 ✓]
0x1D8: FFFFF6223CE7F998   vm_map.pmap  (ptr -> vmspace+0x2E8)            [pmap ptr @0x1D8 ✓]
0x1E0: 0000000000000000   vm_map.busy (0)
----- Sony GPU extension (0x1E8..0x29F) -----
0x1E8: FFFFFFFF00000000   sentinel = 0xFFFFFFFF << 32  (NOT a vmid; see §1.2)
0x1F0: 0000000000000000
0x1F8: 0000000200810000   {u32 phys=0x00810000, u32 vmid=0x2}   <-- first GPU-dir pair
0x200: 00000006FF810000   {phys=0xFF810000, vmid=0x6}
0x208: 0000000880A24000   {phys=0x80A24000, vmid=0x8}
0x210: 00000008FFA24000   {phys=0xFFA24000, vmid=0x8}
0x218: 00000007EF088000   {phys=0xEF088000, vmid=0x7}
0x220: 00000007EF087FE0   {phys=0xEF087FE0, vmid=0x7}
0x228: 00000007EF088000   {phys=0xEF088000, vmid=0x7}
0x230: 0000000000000000
0x238: 0000000000000025   (=37, not a vmid)
0x240: 0000000113590001
0x248: 0000000000000000
0x250: FFFFF6223CE7F8F8   (self-ptr: vmspace+0x248)
0x258: 0000000000000000
0x260: FFFFFFFF90A6319B   (.data ptr)
0x268: 0000000001030000
0x270: 0000000000000000
0x278: 0000000000000004
0x280: 7FFFFFFFFFFFFFFF   (INT64_MAX)
0x288: 0000000000000000
0x290: FFFFF622659027A8   (heap ptr)
0x298: 0000000000000000
----- FreeBSD tail (unchanged, SDK vmspace fields) -----
0x2A0: 0000000000000000   vm_shm     = NULL
0x2A8: 0000000000000000   vm_swrss   = 0
0x2B0: 0000000000000015   vm_tsize   = 21 pages
0x2B8: 0000000000000044   vm_dsize   = 68 pages
0x2C0: 0000000000000008   vm_ssize   = 8 pages
0x2C8: 0000000061B6C000   vm_taddr   = 0x61B6C000
0x2D0: 0000000061BE0000   vm_daddr   = 0x61BE0000
0x2D8: 00000007EEE88000   vm_maxsaddr= 0x7EEE88000
0x2E0: 0000000000000001   vm_refcnt  = 1
0x2E8: FFFFFFFF90AF441A   inline struct pmap  [VM_PMAP = 0x2E8 ✓]
0x2F0: 0000000001430000
...
0x300: 0000000000000004
```

The FreeBSD tail (`vm_shm`..`vm_refcnt` + inline `pmap`) is a **perfect** match, which
independently confirms both `P_ROOT = 0x1D0` and `VM_PMAP = 0x2E8`, and pins the whole struct
to the SDK layout. The vmspace is `0xFFFFF6223CE7F6B0`; the `vm_map.pmap` pointer
`0xFFFFF6223CE7F998` equals `vmspace + 0x2E8` exactly.

### 1.2 The VMID field is `0x1FC`, and `0x1EC` is NOT it

`vm_vmid` is a `u32` in `1..0x10`. The only `u32` values in `1..0x10` at the tail of
`vm_map` are the **high halves** of the seven `{phys,vmid}` pairs:

```
0x1FC = 0x2   ← primary VMID (first pair)
0x204 = 0x6   0x20C = 0x8   0x214 = 0x8   0x21C = 0x7   0x224 = 0x7   0x22C = 0x7
```

`0x1EC` (the value the old doc derived as `0x1E4 + 8`) reads **`0xFFFFFFFF`** — it is the
high 32 bits of the sentinel `0xFFFFFFFF00000000` at `0x1E8` (a `-1`/all-flags marker in
Sony's GPU block, not a vmid). The `+8` shift the old doc applied to `vm_vmid` is invalid:
the 6.00 change moved `vm_map.root`/`pmap` by +8 **and** inserted two extra `u64`s into the
Sony GPU block, so `vm_vmid` moved `0x1E4 → 0x1FC` (+`0x18`), not `→ 0x1EC`.

**`OFFSET_VMSPACE_VM_VMID = 0x1FC`**, confirmed value `2` on the live process.
`probe81`'s self-check at `0x1EC` (which logged `(BAD)` on `0xFFFFFFFF`) was probing the
wrong dword for exactly this reason.

---

## 2. `OFFSET_DATA_GVMSPACE` — negative result (not in this dump)

### 2.1 Decisive evidence: the live process's page-directory values are absent

The live process uses VMID **2**. From §1.1 its GPU page directories (the `{phys,vmid}`
pairs) are the physical addresses `0x00810000`, `0xFF810000`, `0x80A24000`, `0xFFA24000`,
`0xEF088000`, `0xEF087FE0`. `gvmspace[2].page_dir_va` (field `@0x38`, the GPU PDB2/PML4)
must therefore equal `0x00810000` (raw PA) or `0xffffff8000810000` (DMAP VA).

A full scan of the 16 MiB dump for every one of those six values — as a raw `u64`, as the
low 32 bits, as the high 32 bits, and as their `0xffffff80…` DMAP aliases — returns
**zero hits**. `gvmspace[vmid].page_dir_va` for the running process is simply not stored
anywhere in the file, so the array itself is not in the dump (no stride/field-layout
variation can fix that).

### 2.2 The 12.00 anchor is zeroed

The last published value, `DATA_BASE_GVMSPACE = 0x2E7E570` (12.00–12.70, YarP2JB), maps to
file offset `0x7E570` if the dump began at `0x2E00000` — it reads **all zeros**, so the
array moved on 13.60.

### 2.3 Exhaustive structural scan — negative

Across the whole 16 MiB, for strides `0x28..0x200` and page-dir offsets `0x00..0x80`:

- No `0x100`-strided array has a "huge GPU VA" (`0x150000000000..0x250000000000`) at
  `start_va@0x08`.
- The only huge-GPU-VA array is the **direct-memory region table** (stride `0x28`,
  `.data 0x3239B68` if the dump starts at `0x2F00000`, i.e. file `0x239B68`), which the
  previous doc already ruled out as `gvmspace`.
- The only `0x100`-strided array with page-aligned DMAP VAs at `@0x38` is at
  `.data 0x2FEA570` (file `0xEA570`): entries `[0x00]` = `0,0x20,2,3,4,5,0x20…`,
  `[0x28]=[0x30]=0x17E98000`, `[0x38]=0xffffff80a0c98000 (+0x4000/entry)`. That is a
  FreeBSD VM/pmap allocation table (indexed by a small id, page-table allocations), **not**
  `gvmspace` — it has no huge `start_va` and no `size@0x10`.

### 2.4 Why the prior scan missed it, and the correct next step

The doc's own confirmation recipe was: *"dump `kdata_base + 0x2E00000` for ~`0x200000`
bytes"*. `probe81` instead dumped from **`0x2F00000`** (49.3 MB), i.e. **~0.4 MB past** the
estimated array location (`0x2E80000–0x2EC0000`, best single points `0x2EBF9F0`/`0x2EC29F0`,
per the doc's quick-delta and the `kernel_pmap_store + 0x61600` rule). The array is most
likely *just below* this dump's start.

**Exact confirmation (pick one):**

1. **Re-dump lower.** `kernel_copyout` from `kdata_base + 0x2D80000` for `0x80000` bytes
   (cover `0x2E00000–0x2EC0000`), and scan for the array: `0x100`-strided records with
   `start_va@0x08` = a huge GPU VA and `page_dir_va@0x38` = a page-aligned DMAP VA
   (`0xffffff80…000`, distinct per VMID).
2. **Runtime anchor (no dump).** With kernel r/w, walk the current process's GPU PDB2 from a
   known-mapped GPU buffer and solve for the `gbase_vmspaces` value that makes
   `gvmspace[vmid].page_dir_va` a page-aligned DMAP VA whose walked PDEs yield the buffer's
   real PA. `gpuread.elf`'s `gpu_find_leaf` self-check already aborts on mismatch, so this
   is safe to probe.

Do **not** run the read/write payload with `0x2E7E570` on 13.60: it is the 12.00 value and
is zeroed on 13.60.

---

## 3. Field layout recap (for the payload)

```
gvmspace entry (stride 0x100):
  +0x08  start_va       (huge GPU VA, e.g. 0x164000000000)
  +0x10  size           (0x80000000 / 0x40000000 / 0x4000000)
  +0x38  page_dir_va    (GPU PDB2/PML4, stored as page-aligned DMAP VA)
gvmspace base = kdata_base + OFFSET_DATA_GVMSPACE, indexed by vm_vmid (u32 @ vmspace+0x1FC)
```

## 4. References

- cragson/ps5-hen `offsets.h` / `gpu_dma.h` / `hv_defeat.cpp`
- ps5-linux/ps5-linux-loader `source/offsets.c`, `source/gpu.c`
- matem6/YarP2JB `p2jb.py` (`FW_OFFSETS_P2JB`: 9.00–12.70 `DATA_BASE_GVMSPACE`)
- ps5-payload-dev/sdk `crt/kernel.c` (per-FW `P_ROOT`/`VM_PMAP`; 13.60 = `0x1d0`/`0x2e8`)
- local: `Caliper-C0re/kernel/offsets_13.60.js`, `GPUVM_OFFSETS_1360.md` (superseded by this)
