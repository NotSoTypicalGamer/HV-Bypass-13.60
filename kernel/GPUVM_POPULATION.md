# GPUVM Population — forcing full GPU page-table leaves for onion/direct-memory (vmid 2, 13.60)

**Goal:** get the ONION direct-memory victim, its staging buffer, and its command buffer all
reachable in the **process vmid (2)** GPU page tables so the GNM DMA write can retarget the
victim leaf and land a write in system RAM (kernel `.data` / VMCB). Offline research — do NOT
deploy.

**Follow-up to:** `GPU_DMA_KDATA_WRITE.md` ("onion leaves lazily populated, ~280 KB of the 2 MB
victim mapped, staging/cmd unreachable"), `GPU_DMA_PHYS_FIX.md` §5 ("36 leaves ≈ 288 KB … lazy/
demand"), `GPU_DMA_MEMORY_MODEL.md`, `GPU_DMA_GARLIC_FIX.md`.

---

## TL;DR — the answer to (a)/(b)/(c)

| Mechanism | Populates GPU leaves? | Confidence | Why |
|---|---|---|---|
| **(a) CPU read/write touching every page** | **NO** | high (amdgpu architecture + measured) | CPU and GPU use separate page tables. The CPU VA is mapped eagerly at `sceKernelMapDirectMemory` time, which is *why* the CPU can read/write the full 2 MB today even though only 288 KB of GPU leaves exist. A CPU data access does not write GPU leaf PTEs. |
| **(b) GPU-side operation touching the range** | **YES** — the reliable lever | high | Population is demand-driven on 13.60: a GPU access to an unmapped leaf faults, the GPUVM fault handler populates the leaf, the GPU retries (amdgpu retry-fault / SVM model). This is exactly how the first ~288 KB got populated. A full-range copy/draw/fill forces every remaining leaf. |
| **(c) syscall / flag / mlock / ioctl to "populate"** | **No dedicated one exists** | high (negative) | No `sceKernel*` syscall or `sceKernelMapDirectMemory` flag forces GPU-leaf population. `mlock` pins CPU pages only. The only syscall-level *lever* is the **GNM submit path** (which triggers amdgpu's CS-validate eager population) — but that is just (b) by another name. |

**Bottom line:** the reliable way to get the onion victim (and staging + cmd) fully mapped in
vmid 2 is to make the **GPU itself traverse the whole range** — a GNM submission whose PM4
packet reads/writes the full 2 MB of each buffer. Each unmapped 8 KB leaf faults and is
populated on demand. The chicken-and-egg (staging/cmd not yet mapped) resolves itself because
the command processor faults in the cmd buffer's leaf when it fetches the IB, and the DMA
engine faults in the src/dst leaves as it walks them.

---

## 1. What the observed "lazy" population actually is

Measured on 13.60 (own console, `probe76`): the onion victim's GPU tree has **36 × 8 KB leaves
≈ 288 KB** of its 2 MB present (`GPU_DMA_PHYS_FIX.md`). The tree itself is a 5-level
`PDB2/PML4 → PDB1/PDPT → PDB0/PD → PTB(frag=4) → 8 KB leaf` structure with `TF` (bit 56) sub-tables
— i.e. **8 KB-granularity leaves**, not the single 2 MB `IS_PTE` (bit 54) leaf the older firmware
used. Only the region the GPU has actually touched is populated.

This is **amdgpu demand paging**, not a bug. In the AMDGPU driver there are three distinct ways a
GPUVM page table gets its PTE entries written, and which one the PS5 uses is what decides the fix:

1. **Eager at map time** — `amdgpu_gem_va_ioctl` (`AMDGPU_VA_OP_MAP`) → `amdgpu_vm_bo_update`
   → `amdgpu_vm_update_range` → `amdgpu_vm_update_ptes` writes **every** PTE for the whole BO
   range when the mapping is created. (`AMDGPU_VM_DELAY_UPDATE` defers this to the next CS; without
   it, mapping is immediate and full.)
2. **Eager at command-submission (CS) validate** — `amdgpu_cs_ioctl` →
   `amdgpu_bo_list_validate` → `amdgpu_vm_validate_pt_bos` → `amdgpu_vm_bo_update` populates the
   page tables for **every BO in the submission's resource list** before the job runs.
3. **Lazy fault/retry (SVM-style)** — `amdgpu_vm_handle_fault` / `amdgpu_svm_handle_fault`
   populates PTEs **on demand** when the GPU faults on an invalid entry, then the GPU retries the
   access ("XNACK on" / retry-fault model). The amdgpu SVM patch series is explicit: *"GPU page
   faults are retried after the driver lazily populates PTEs on demand. The XNACK-off/eager-mapping
   path is deferred."*

The 13.60 onion buffer behaves like mode **3** (fault/retry), which is why only the touched
~288 KB has leaves. The ≤7.61 behaviour the references were written against was mode **1/2**
(eager), which is why `flatz gpu.lua` / `ps5-hen` / `ps5-linux-loader` all `error()` /
`WARN()` when `page_size != dmem_size` — they *require* the victim to already be a single fully
mapped 2 MB leaf.

---

## 2. (a) CPU read/write touch — does NOT populate GPU leaves

- On amdgpu (and the PS5, whose GPU MMU is the same design, mediated by the A53/PSP `a53mm`
  module that "owns the GPU MMU: VMID alloc, CPU/GPU page tables, page migration"), the **CPU and
  GPU each walk their own page tables**. A CPU access to the direct-memory VA goes through the
  x86-64 page tables that `sceKernelMapDirectMemory` installed — which are fully populated at map
  time (that is why the CPU can already touch the entire 2 MB without a fault). It does not touch
  the GPU PDB/PTB/leaf tree.
- **Measured confirmation of the split:** `probe76` observed 36 GPU leaves for a 2 MB buffer the
  CPU could freely read/write end-to-end (`GPU_DMA_PHYS_FIX.md` §1/§5). If CPU touch populated GPU
  leaves, the full 2 MB would have been mapped. It was not.
- `mlock()` pins CPU pages; it has no effect on GPU page tables. Same for plain `memset`/`memcpy`.

**Nuance worth recording (do not over-read it):** `mprotect(victim_va, len, PROT_…)` on the
direct-memory CPU VA **does** change the GPU PTE — `flatz gpu.lua` and `ps5-hen gpu_dma.cpp` both
re-read the victim PTE after an `mprotect(...PROT_GPU_READ)` and see the GPU_WRITE bit drop (that
is how they capture `cleared_ptbe = pte & ~victim_real_pa`). So *VMM ops* (mprotect /
`sceKernelMprotect` / `sceKernelMtypeprotect`) propagate CPU→GPU at the PTE-flag level. But that is
a protection/coherency change on an already-present leaf, **not population** — an unmapped leaf is
still not created by mprotect alone, and a data load/store never goes through that path. Keep the
distinction: *data access* = no GPU effect; *explicit VMM operation* = flag-level GPU effect.

---

## 3. (b) GPU-side touch — the reliable forcing mechanism

Population is demand-driven, so the thing that forces it is a GPU access to the unmapped range.
This is the same mechanism that already produced the 288 KB (the partial GNM submit / driver init
touched the victim's head). To get the *rest*, touch the *rest*:

**Concrete recipe (offline plan):**

1. **Command buffer:** build a PM4 type-3 `PACKET3_DMA_DATA` (opcode `0x50`) — the same
   `pm4_build_dma_data` already in the codebase — but sized for the **full 2 MB**, not 8 bytes:
   `src = victim.gpu_va`, `dst = staging.gpu_va`, `length = 0x200000`. (Or `PACKET3_COPY_DATA` /
   a `PACKET3_WRITE_DATA` fill / a compute shader that writes each page; any op that walks the full
   range works.)
2. **Submit via GNM** (`sceGnmSubmitCommandBuffers` + `sceGnmSubmitDone`, vmid 2). Fault-in order:
   the CP fetches the IB → **cmd leaf** is faulted in; the DMA engine reads `victim` → **victim
   leaves** faulted in; it writes `staging` → **staging leaves** faulted in. One full-range pass
   leaves all three buffers populated.
3. **Re-walk** the GPU tree and confirm the leaf count is now `0x200000 / 0x2000 = 256` leaves
   per 2 MB buffer (victim, staging, cmd), then proceed with the normal retarget → submit →
   restore sequence.

**Key open question to answer before betting the primitive on it** (test first, cheaply): *is a
GPU fault on an unmapped **onion** leaf recoverable (populate+retry), or does it hang the queue?*
The 288 KB partial population is evidence faults *are* serviced, but the payload has never
deliberately faulted past the populated window. Safe probe: extend a DMA copy by **one 8 KB leaf
past the current 288 KB boundary**, re-walk, and check whether that leaf appeared. If yes, scale to
the full 2 MB. If the queue hangs instead, fall back to §4 (the CS-validate path) which populates
without faults.

**Second lever (the amdgpu CS-validate path):** a *correctly resource-registered* GNM submission
runs `amdgpu_vm_validate_pt_bos` → `amdgpu_vm_bo_update` over every buffer in its resource list,
which populates all of them **eagerly and without relying on faults**. This is the cleanest fix,
but it is currently blocked by the GNM driver not initialising in the elfldr payload
(`"Failed to get trap handler code"`, `sceGnmSubmitDone` → `0x80D4FFFF`). Fixing that init is the
highest-value unlock: once `sceGnmSubmitCommandBuffers` actually validates resources, the
victim+staging+cmd buffers should populate fully on the first submit without any touch trick.

---

## 4. (c) syscalls / flags / ioctls — none force population

Enumerated and ruled out (offline, from the PS5 kernel syscall surface + amdgpu):

- **`sceKernelMapDirectMemory` / `sceKernelMapNamedDirectMemory` flags** — the only flag the
  references pass is `MAP_NO_COALESCE`; there is no "populate"/"prefault" flag. (PS4/PS5 Libkernel
  docs list only protection + flags; no populate bit.)
- **`sceKernelAllocateMainDirectMemory` `mem_type`** — selects the pool (1 = onion/main); it does
  not control GPU-leaf population.
- **`mlock` / `madvise`** — CPU page residency only. No GPU effect.
- **`sceKernelMtypeprotect(addr, len, type, prot)` / `sceKernelMprotect`** — change the memory
  coherency *type* (UC/NC/CC/RW = the GPU PTE coherency/flag bits, incl. the "system coherent"
  bit 50 seen on the onion leaf `0x0004000033400177`) and protection. These re-write flags on
  **already-present** leaves; they are the syscall side of the mprotect behaviour in §2, not a
  populate primitive. Unproven whether a full-range `mtypeprotect` forces leaf creation — do not
  rely on it.
- **`sceKernelGetPageTableStats(cpu_total, cpu_available, gpu_total, gpu_available)`** — query only
  (confirms the kernel tracks a separate **GPU** page-table budget, consistent with §2's CPU/GPU
  split), no populate.
- **amdgpu "prefetch" / SVM ioctl** — exists upstream (`AMDGPU_GEM_SVM`, prefetch_loc) but is not
  exposed through the PS5 libkernel/syscall ABI. Not reachable from a payload.
- **`/dev/gc` ioctl** — the `0xC0108102` submit path is **vmid 6 (VRAM-only)** on 13.60 and cannot
  populate/reach the onion vmid-2 leaves at all (`GPU_DMA_KDATA_WRITE.md`).

**Conclusion for (c):** there is no syscall that forces GPU-leaf population. The syscall-level
action that *does* force it is `sceGnmSubmitCommandBuffers` — because it drives the amdgpu
CS-validate population of §3, i.e. it is (b) in disguise.

---

## 5. Root cause: the population strategy changed across firmware

- **≤7.61 (what `flatz gpu.lua` / `ps5-hen` / `ps5-linux-loader` target):** `sceKernelAllocateMain
  DirectMemory` + map produces a **single, fully-populated 2 MB leaf** (`IS_PTE` bit 54). That is
  why all three implementations `error()`/`WARN()` on `page_size != dmem_size` — they *rely* on
  eager full mapping existing at setup time, and never touch/populate anything themselves.
  `flatz gpu.lua` has **no** populate step; its `gpu.setup()` allocates 3 × 2 MB and immediately
  walks the victim, expecting the 2 MB leaf.
- **13.60:** the *same* allocation yields a **5-level 8 KB-granularity tree** (`TF` bit 56) whose
  leaves are populated **lazily** on GPU demand. `gvmspace.start_va` is `0x0` and the walk returns
  8 KB (`0x2000`) leaves, so the old `page_size == dmem_size` guard fails and the old `rel_va =
  va - start_va` formula breaks (`GPUVM_OFFSETS_1360_v2.md`, `GPU_DMA_MEMORY_MODEL.md`). The
  "victim+staging+cmd unreachable" blocker is *this* lazy population on top of the broken GNM init,
  not an address-space error.

---

## 6. Recommended path (for the write primitive)

1. **Fix GNM driver init first** (`"Failed to get trap handler code"`, `sceGnmSubmitDone →
   0x80D4FFFF`). A working `sceGnmSubmitCommandBuffers` with the three buffers in its resource
   list populates all of them via the CS-validate path (§3 second lever) — no touch trick needed.
2. **If GNM init stays broken**, force population by fault-driven touch (§3 recipe): submit one
   full-range `PACKET3_DMA_DATA` (victim→staging, 2 MB) and let the GPUVM fault handler populate
   every leaf. Test one leaf past the 288 KB boundary first to confirm faults are recoverable.
3. After population, run the existing retarget → submit → restore sequence (`references/
   gpu-dma-primitive.md`), keeping the sentinel/packet inside the now-fully-mapped region.

---

## 7. References

- **flatz gpu.lua** (`shahrilnet/remote_lua_loader` mirror, "credit to flatz and shadPS4"):
  `gpu.setup()` / `alloc_main_dmem()` / `get_ptb_entry_of_relative_va()` — allocates 3 × 2 MB onion
  buffers, walks the victim, captures `cleared_ptbe` via an `mprotect(PROT_GPU_READ)` round-trip;
  **no populate step** (relies on the ≤7.61 eager 2 MB leaf; errors if `page_size ~= dmem_size`).
- **cragson/ps5-hen `gpu_dma.cpp`** — same walk + mprotect PTE-capture; `/dev/gc` ioctl submit.
- **ps5-linux-loader `source/gpu.c`** — same walk; `gpu_transfer_physical` (2 MB-leaf retarget
  + `PACKET3_DMA_DATA` via `/dev/gc` ioctl).
- **Linux amdgpu VM semantics** (the PS5 GPU MMU is the same design):
  `amdgpu_vm_bo_update` / `amdgpu_vm_update_range` / `amdgpu_vm_update_ptes` (eager, from
  `amdgpu_gem_va_ioctl` MAP and from CS via `amdgpu_vm_validate_pt_bos` / `amdgpu_bo_list_validate`);
  `amdgpu_vm_handle_fault` / `amdgpu_svm_handle_fault` (lazy retry-fault, "XNACK on" model);
  `AMDGPU_VM_DELAY_UPDATE` flag. (freedesktop amd-gfx lore threads; AMDGPU glossary: GPUVM / GART.)
- **PS5 syscall surface** (shadPS4 kernel shim + ps5-payload-dev): `sceKernelAllocateDirectMemory`
  / `sceKernelMapDirectMemory` / `sceKernelMprotect` / `sceKernelMtypeprotect` /
  `sceKernelGetPageTableStats` / `sceKernelBatchMap2` (OpMapDirect) — no populate op.
- **Local corpus:** `GPU_DMA_KDATA_WRITE.md`, `GPU_DMA_PHYS_FIX.md`, `GPU_DMA_MEMORY_MODEL.md`,
  `GPU_DMA_GARLIC_FIX.md`, `GPU_DMA_READ_FIX.md`, `GPUVM_OFFSETS_1360_v2.md`,
  `references/gpu-dma-primitive.md` (ps5-hypervisor-defeat skill).
