# GPU DMA → kernel .data write primitive (the "GPU can write to kernel .data via DMA" trick)

**Status:** Publicly documented and implemented. Fully working through at least FW 12.70;
psdevwiki lists it **"Patched: No as of PS5 FW 12.00. Probably unpatchable."**
**Scope note:** this is a WRITE-path *bypass* for the hypervisor's kernel-`.data`
write-protection. It is **not** a standalone kernel exploit — you still need an
independent kernel R/W primitive (to defeat kASLR, translate VA→PA, and retarget a
GPU page-table entry). It also does **not** defeat `.text` XOM (no kernel code exec).

---

## 1. What it is

Since PS5 firmware **6.00**, a *CPU* write to kernel `.data` (through the normal
kernel R/W primitive, e.g. `kernel_write8`) panics, because the hypervisor enforces
write-protection on kernel `.data` for CPU accesses (NPT/SLAT write-protect +
interception of `CR0.WP` / `CR4.SMAP`). The workaround: **let the GPU perform the
write as a DMA copy.** The GPU's memory accesses are translated by the GPU's *own*
MMU (GPUVM, the per-VMID `gvmspace` page tables), which are kernel-managed and
guest-controllable — the hypervisor's CPU-side `.data` write-protection does not gate
the GPU DMA path. So the write lands without a panic.

psdevwiki entry: *"Kernel .data section write protection (SMAP) bypass via GPU DMA
copy"* — <https://www.psdevwiki.com/ps5/Vulnerabilities> (section 10.1).

---

## 2. (a) Exact mechanism — which engine, which DMA path

The primitive is a **GPU direct-memory copy (memcpy) between two GPU-mapped buffers**,
driven through one of **two** public paths. Both paths use the *same* core trick
(retarget a GPU PTE to an arbitrary physical address), they differ only in **which GPU
engine executes the copy** and **how the copy is submitted**:

### Path A — AGC / GnmAwt display copy (BD-J / high-level)
- Call `Java.sun.awt.GnmUtils.copyPlanesBackgroundToPrimary` (BD-J entrypoint), which
  bottoms out in the **AGC** (GnmAwt) library's direct-memory copy:
  `sceGnmAwtInternalDirectMemoryCopy` / `LibGnmAwt.internalDirectMemoryCopy(dst, src, size)`
  plus a `getSyncValue()` / `waitSync(n)` fence.
- Used by **flatz** (BD-JB), **hammer-83** (`KernelAccessorAgc.java`), **Gezine** (`GPU.java`).

### Path B — GFX Command Processor, PM4 `PACKET3_DMA_DATA` (game / raw)
- Build a **PM4 type-3 `DMA_DATA` packet** (opcode **`0x50`**) that copies N dwords from
  `src_va` to `dst_va` (both 64-bit GPU virtual addresses), and submit it to the GFX ring.
- Two submission methods for the same packet:
  1. **Raw `/dev/gc` ioctl** — `ioctl(fd, 0xC0108102, {u32 pipe_id=0; u32 count=1; u64 cmd_buf_ptr})`
     (cragson's **ps5-hen**; **tcphdr/PS5-Firmware-Spoofer**).
  2. **libSceGnmDriverForNeoMode.sprx** — `sceGnmSubmitCommandBuffers(dcbCount, dcbGpuAddr,
     dcbSizesInBytes, 0, 0)` + `sceGnmSubmitDone()` (Znullptr's `gpu.lua`, flatz's game path).

### The core trick (shared by A and B)
1. Allocate a **"victim"** GPU buffer (`sceKernelAllocateMainDirectMemory` +
   `sceKernelMapNamedDirectMemory` with `PROT_GPU_READ|PROT_GPU_WRITE`) and a
   **"transfer/staging"** buffer.
2. Use the kernel R/W primitive to walk the **GPU page tables** for this process's VMID
   and locate the victim buffer's PTE ("PTBE").
3. Rewrite that PTE's physical-address field to point at an **arbitrary physical page**
   (the kernel `.data` page you want to write).
4. Issue the GPU copy between the staging buffer and the retargeted victim buffer.
5. The GPU DMA engine performs the read/write *through the GPU page tables*, so the target
   physical memory is accessed by the GPU, not the CPU — no CPU-side protection triggers.
6. Restore the victim PTE.

---

## 3. (b) Why it bypasses the HV/IOMMU write protection

- The HV enforces `.data` write-protection at the **CPU's nested page tables (NPT/SLAT)**
  level and by intercepting `CR0.WP`/`CR4.SMAP`/`CR4.SMEP` writes (see
  <https://psdevwiki.com/ps5/Hypervisor>). A *CPU* store to a write-protected `.data`
  guest page faults → VMEXIT → panic.
- The **GPU does not use the CPU's NPT.** GPU memory accesses are translated by the
  **GPU MMU (GPUVM)** using per-VMID page tables — the `gvmspace` array in kernel `.data`
  (`gbase_vmspaces`, entries `struct gvmspace` 0x100 bytes each, holding `page_dir_va`
  = GPU PDB2/PML4, `start_va`, `size`, and the VMID). These GPU page tables live in
  ordinary RAM and are **guest/kernel-controllable**; the hypervisor does **not** apply
  its CPU-side `.data` write-protection to the GPU's DMA transactions.
- Therefore: a payload that already has kernel R/W can (i) read the GPU page tables,
  (ii) rewrite one GPU PTE to alias the physical page of a kernel `.data` structure,
  (iii) make the GPU write it. The CPU never issues a protected store, so no panic.
- Public sources label the protection loosely ("SMAP" / "write protection"); the exact
  HV-side mechanism (NPT write-protect vs `CR0.WP` filter) is not spelled out in the
  public writeup, but the operational fact is unambiguous: **CPU write = panic, GPU DMA
  write = success**, on the same kernel `.data` page.

---

## 4. (c) Concrete trigger path + constants

All values below are from **cragson/ps5-hen** (as vendored in
`ps5-linux/ps5-linux-loader`) and independently cross-checked against flatz's and
Znullptr's Lua implementations (all agree on opcode `0x50` and the PDE bit layout).

### Constants (`include/gpu.h`, header comment: "Source: ps5-hen by cragson")

| Symbol | Value | Meaning |
|---|---|---|
| `GPU_SUBMIT_IOCTL` | `0xC0108102` | `/dev/gc` submit ioctl (in/out, 16-byte arg) |
| `PM4_TYPE3` | `3` | type-3 packet tag |
| `PM4_OPCODE_DMA_DATA` | `0x50` | PS5 GFX DMA_DATA opcode (note: stock amdgpu uses `0x32`; PS5 CP = `0x50`) |
| `PM4_OPCODE_INDIRECT_BUF` | `0x3F` | indirect-buffer opcode |
| `PM4_SHADER_COMPUTE` | `1` | compute-shader packet flag |
| `PROT_GPU_READ` | `0x10` | mmap/direct-mem GPU-read protection bit |
| `PROT_GPU_WRITE` | `0x20` | GPU-write protection bit |
| `MAP_NO_COALESCE` | `0x00400000` | direct-mem map flag |
| GPU PDE `VALID` | bit 0 | |
| GPU PDE `IS_PTE` | bit 54 | 2 MB leaf if set |
| GPU PDE `TF` | bit 56 | |
| GPU PDE `BLOCK_FRAGMENT_SIZE` | bit 59 (0x1F) | |
| GPU PDE `ADDR_MASK` | `0x0000FFFFFFFFFFC0` | physical-address field |

### PM4 type-3 header construction
```
header = ((3      & 0x3)   << 30)   // PM4_TYPE3
       | ((count-1 & 0x3FFF) << 16)  // dwords-1 in body
       | ((opcode & 0xFF)  << 8)
       | ((1 & 0x1) << 1)            // PM4_SHADER_COMPUTE
```

### DMA_DATA packet (count=6 → 7 dwords)
```
pkt[0] = type3 header (opcode 0x50)
pkt[1] = dma_hdr:  (1<<31) cp_sync
                 | (2<<25) dst_cache_policy
                 | (1<<27) dst_volatile
                 | (2<<13) src_cache_policy
                 | (1<<15) src_volatile
pkt[2..3] = src_va  (GPU virtual address, 64-bit)
pkt[4..5] = dst_va  (GPU virtual address, 64-bit)
pkt[6]    = length & 0x1FFFFF
```
(`engine=0` → GFX; `src_sel=0`/`dst_sel=0` → memory. See `gpu.lua` for the fully
annotated bit layout — identical across implementations.)

### Submission
- Raw: `ioctl(gc_fd, 0xC0108102, &{pipe_id=0, count=1, cmd_buf_ptr=desc_va})` where
  `desc_va` points at a 16-byte command descriptor:
  ```
  d[0] = ((gpu_addr & 0xFFFFFFFF) << 32) | 0xC0023F00   // INDIRECT_BUF-like descriptor
  d[1] = ((size_dwords & 0xFFFFF) << 32) | ((gpu_addr >> 32) & 0xFFFF)
  ```
- GNM: `sceGnmSubmitCommandBuffers(1, &cmd_gpu_addr, &cmd_size_bytes, 0, 0)` then
  `sceGnmSubmitDone()`.

### Kernel offsets needed (per-firmware, in `.data`)
| Field | Note |
|---|---|
| `proc->p_vmspace` | to reach `vmspace` |
| `vmspace->vm_vmid` | the GPU VMID for this process |
| `DATA_BASE_GVMSPACE` | `.data` offset of the `gvmspace` array (`gbase_vmspaces`) |
| `sizeof_gvmspace` | `0x100` |
| `gvmspace->page_dir_va` @ `0x38` | GPU PDB2 (PML4) base |
| `gvmspace->size` @ `0x10`, `start_va` @ `0x08` | GPU-VA range for this VMID |

### Page-table walk (GPU VM, 4-level, 64 KB / 2 MB leaf granularity)
```
pml4e_idx = (gpu_va >> 39) & 0x1FF
pdpe_idx  = (gpu_va >> 30) & 0x1FF
pde_idx   = (gpu_va >> 21) & 0x1FF
pml4e = *(pdb2_addr + pml4e_idx*8)          // read via kernel R/W (dmap + PA)
pdpe  = *(dmap + (pml4e & ADDR_MASK) + pdpe_idx*8)
pde   = *(dmap + (pdpe  & ADDR_MASK) + pde_idx*8)
// if pde[IS_PTE] → 2 MB leaf; else descend by BLOCK_FRAGMENT_SIZE (64 KB / 8 KB)
```
Then the PTE ("PTBE") that must be retargeted is the final leaf entry.

### Transfer sequence (per operation)
```
mprotect(victim_va, size, PROT_READ|PROT_WRITE|PROT_GPU_READ)      // read-only to GPU
kernel_write64(victim_ptbe_va, cleared_ptbe | target_phys_addr)     // retarget PTE
mprotect(victim_va, size, PROT_READ|PROT_WRITE|PROT_GPU_READ|PROT_GPU_WRITE) // GPU-write
build DMA_DATA(src=transfer, dst=victim+off)   // write: staging → victim
submit; usleep(100ms)                          // (TODO proper fence in ps5-hen)
kernel_write64(victim_ptbe_va, cleared_ptbe | victim_real_pa)       // restore PTE
```

---

## 5. (d) Presence on 8.00–13.60

- **6.00** = the firmware that *added* the CPU-side `.data` write-protection (making the
  bypass necessary). The bypass itself is present on **everything 6.00+**.
- psdevwiki **Patched: "No as of PS5 FW 12.00. Probably unpatchable."**
- Independently confirmed working on: **9.00–12.70** (matem6/YarP2JB, "GPU PM4 DMA"
  debug-menu enable), **11.20** (tcphdr/PS5-Firmware-Spoofer, `/dev/gc` path), and in
  Gezine's BD-UN-JB (2026-05) and the `cr_ref`-overflow chains.
- **No public report of it being patched through 13.60.** Given the "probably
  unpatchable" assessment (it's a fundamental property of the GPU having its own
  guest-controlled MMU, not a single buggy check), it is expected to still be live on
  **8.00–13.60**. The only *actual* requirement that changes per-firmware is the set of
  kernel `.data` offsets (kASLR base + `gvmspace` layout), which must be re-derived for
  13.60.

---

## 6. Public implementations / references

- psdevwiki Vulnerability (mechanism + credits + patched status):
  <https://www.psdevwiki.com/ps5/Vulnerabilities#Kernel_.data_section_write_protection_(SMAP)_bypass_via_GPU_DMA_copy>
- psdevwiki Hypervisor (why CPU writes panic): <https://psdevwiki.com/ps5/Hypervisor>
- **cragson/ps5-hen** (canonical low-level impl; the `gpu.h` constants above):
  vendored in **ps5-linux/ps5-linux-loader** — `source/gpu.c`, `include/gpu.h`
  (<https://github.com/ps5-linux/ps5-linux-loader>)
- flatz Java (BD-JB, AGC path): <https://gist.github.com/flatz/d6fbf7ef020b20c604a88dcbd8baefe6>
- hammer-83 Java (AGC `LibGnmAwt`, chained with UMTX): `KernelAccessorAgc.java`
  (<https://github.com/hammer-83/ps5-jar-loader/blob/main/sdk/src/main/java/org/ps5jb/sdk/core/kernel/KernelAccessorAgc.java>)
- Znullptr Lua (PM4 `DMA_DATA` via `sceGnmSubmitCommandBuffers`, chained with UMTX):
  <https://github.com/shahrilnet/remote_lua_loader/blob/main/savedata/gpu.lua>
  (also mirrored/evolved in `itsPLK/ps5-lua-autoloader/savedata/gpu.lua`)
- tcphdr `/dev/gc` ioctl impl (FW 11.20): `tcphdr/PS5-Firmware-Spoofer`
- matem6/YarP2JB (9.00–12.70, GPU PM4 DMA): <https://github.com/matem6/YarP2JB>
- Gezine BD-UN-JB `GPU.java`: <https://github.com/Gezine/BD-UN-JB>

---

## 7. Open questions / caveats

- **Exact HV-side reason is not public** — sources call it "SMAP"/"write protection"
  interchangeably; the precise NPT-vs-CR0.WP-vs-SMAP split is inferred, not documented.
- **Fence/sync**: ps5-hen uses a crude `usleep(100ms)` (TODO fence); AGC path uses a real
  `getSyncValue/waitSync` counter.
- **Requires prior kernel R/W** to defeat kASLR and rewrite the GPU PTE — it is a
  *bypass of the .data write-protection*, not a new escalation primitive by itself.
- **Does not touch .text (XOM)** — cannot be used to install kernel code on 6.00+.
- The PM4 `DMA_DATA` opcode is `0x50` on PS5 (stock amdgpu `PACKET3_DMA_DATA` = `0x32`);
  all three independent implementations agree on `0x50`.
