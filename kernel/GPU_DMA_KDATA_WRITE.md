# GPU-DMA write into kernel .data (13.60) — result

## Goal
Prove that the GPU-DMA arbitrary-WRITE primitive bypasses the CPU NPT `.data`
write-protect by writing a sentinel (`0xDEADBEEFCAFEBABE`) into a verified-safe
zeroed kernel `.data` field, reading it back via `kernel_copyout`, then restoring.

## Result: **FAIL — write does not land** (kdata_write_pass = false)

The garlic `/dev/gc` (vmid 6) write path is **VRAM-only on 13.60** and cannot
reach system RAM (kernel `.data`). The primitive is confirmed live for
VRAM→VRAM (T2 PASS), but the VRAM→system-RAM retarget does not land.

## Runtime values (this boot)

| Item | Value |
|---|---|
| TEXT_BASE | `0xffffffff8de00000` |
| DATA_BASE / kdata_base | `0xffffffff8eac0000` |
| target offset | `0x299AD0` |
| target_kva | `0xffffffff8ed59ad0` |
| target_pa (kernel CR3 walk) | `0xed59ad0` |
| target 2MB base / off | `0xec00000` / `0x159ad0` |
| kernel_cr3 | `0x11c54000` (anchor cross-check PASS) |
| victim leaf (vmid 6, garlic) | gva `0x200e00000`, phys `0x47bc00000`, raw `0x004000047bc004f7`, is_2m=1 |
| sentinel | `0xDEADBEEFCAFEBABE` |

## What PASSES

- **Safety gates**: target reads `0` via `kernel_copyout` twice (zero + stable);
  DMAP self-check (`dmap + target_pa` == `kernel_copyout(target_kva)`) PASS.
- **T2 (VRAM→VRAM retarget)**: retarget victim 2MB leaf `0x004000047bc004f7` →
  staging phys `0x47be00000`, DMA write, read-back == sentinel. **PASS** — the
  `/dev/gc` DMA + 2MB-leaf retarget primitive is live this run.

## What FAILS

**T3 (VRAM→system-RAM retarget)** — retarget the victim 2MB leaf to the
2MB-aligned base `0xec00000`, DMA `src=staging -> dst=victim_cpu_va + 0x159ad0`,
length 8. All three read-backs return 0:

- `kernel_copyout(target_kva)` after = `0`
- `read_phys(target_pa)` (DMAP) after = `0`
- GPU DMA read-back (victim+off -> staging) after = `0`

Attempted with:

1. Original flags, physical field swapped: `new = 0x004000000ec004f7` → FAIL.
2. Plus bit 50 (`0x0004000000000000`, "system coherent" — present on the onion
   leaf `0x0004000033400177`, absent on the garlic VRAM leaf) →
   `new = 0x004400000ec004f7` → still FAIL.

PTE is restored (`0x004000047bc004f7`) after every attempt; no panic.

## Root cause

On 13.60 the GPU exposes two separate address spaces for a direct-memory buffer:

- **vmid 6 (the "dev" vmid opened by `/dev/gc`)**: the buffer maps at its CPU VA
  → **VRAM** (garlic window), physical `0x47bc00000`. This vmid is garlic-only; a
  leaf physical `< 16 GB` (system RAM) is not reachable through it, regardless of
  flag bits.
- **vmid 2 (the process vmid)**: the same buffer has an **ONION (system-RAM)**
  mapping at the fixed garlic GPU VA base `0xc80000000` → physical `0x33400000`
  (system RAM). This is the address space that can reach system RAM.

The reference implementation that the "2MB leaf + offset" recipe comes from
(`etaHEN gpu_dma.cpp` / `flatz gpu.lua`) reaches system RAM by using **MAIN
(onion) direct memory** (`sceKernelAllocateMainDirectMemory`, mem_type=1) and the
**process vmid (2)** onion mapping, submitted via **`sceGnmSubmitCommandBuffers`
(GNM)** — *not* via the `/dev/gc` ioctl. On those firmware revisions `/dev/gc` is
bound to the process vmid and MAIN memory is system-RAM-backed at the CPU VA, so
the garlic/onion split does not bite.

On 13.60 the split does bite: `/dev/gc` → vmid 6 → VRAM only, and the onion path
lives in vmid 2 (GNM). In this elfldr payload context the GNM submission path
additionally shows driver-init problems (`"Failed to get trap handler code"`,
`sceGnmSubmitDone` returns `0x80D4FFFF`), and the onion buffer's GPU page-table
leaves are lazily populated (only ~280 KB of the victim is mapped), so a separate
staging/cmd buffer is not yet reachable in vmid 2. A victim-only GNM variant that
keeps packet+sentinel inside the victim's already-mapped region was written
(`kwrite3.c`) but **not deployed** (per instruction to stop the GNM/vmid-2 path).

## Conclusion

The garlic `/dev/gc` (vmid 6) DMA primitive is VRAM-only and cannot prove a
system-RAM (kernel `.data`) write on 13.60. Demonstrating the NPT-bypass write
requires the **MAIN/onion direct-memory + process-vmid (2) onion mapping
submitted via GNM**, whose GNM-driver-init and lazy-population issues must be
resolved first (see `kwrite3.c`).
