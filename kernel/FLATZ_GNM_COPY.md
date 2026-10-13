# flatz GPU-DMA copy — exact primitive extraction (ONION + GNM)

**Goal:** document the *exact* working path of flatz's GPU-DMA copy primitive
(the "Kernel .data write-protect / SMAP bypass via GPU DMA", "probably
unpatchable" per psdevwiki) and turn it into a buildable 13.60 kernel-.data write
probe (`probe79/flatcopy.elf`).

**Verdict:** flatz's primitive is **not** the `/dev/gc` ioctl path. It is
**MAIN (ONION) direct memory + the *process* vmid + a `PACKET3_DMA_DATA` (opcode
`0x50`) submitted through GNM** (`sceGnmSubmitCommandBuffers` /
`sceGnmSubmitDone`). The BD-J entrypoint wraps the *same* GPU copy in
`sun.awt.GnmUtils.copyPlanesBackgroundToPrimary` (JNI native
`Java_sun_awt_GnmUtils_copyPlanesBackgroundToPrimary` in `libgnmawt.prx`). This is
why the garlic-only `/dev/gc` (vmid 6) path could never reach system RAM on 13.60.

---

## Sources (all actually fetched and read)

| Source | What it is | URL |
|---|---|---|
| `flatz gpu.lua` (Lua impl, credits "flatz and shadPS4") | definitive Lua reference: onion alloc + PM4 `DMA_DATA` + `sceGnmSubmitCommandBuffers` | `itsPLK/ps5-lua-autoloader@savedata/gpu.lua` (mirror of flatz's `gpu.lua`) |
| `flatz GpuMemoryUtil.java` | flatz's BD-J Java primitive (gist d6fbf7ef) | `gist.github.com/flatz/d6fbf7ef020b20c604a88dcbd8baefe6` |
| `LibGnmAwt.java` | ps5-jar-loader wrapper that resolves the JNI native + sync object | `hammer-83/ps5-jar-loader@sdk/.../lib/LibGnmAwt.java` |
| `KernelAccessorAgc.java` | full BD-J chain (alloc + PTE remap + `internalDirectMemoryCopy`) | `hammer-83/ps5-jar-loader@sdk/.../KernelAccessorAgc.java` |
| `cragson gpu_dma.cpp/.h` | C++ port (etaHEN), onion alloc + PM4 + `/dev/gc` ioctl submit | `cragson/ps5-hen@gpu_dma.{cpp,h}` |
| psdevwiki "Vulnerabilities" | authoritative description + implementation links | `psdevwiki.com/ps5/Vulnerabilities` |

Note: `github.com/flatz/ps5_js` **404s now** (repo gone/renamed). The `gpu.lua`
content survives in the Lua-loader mirrors and is credited to flatz; the
psdevwiki "Implementation" section cites flatz's Java gist as the canonical
implementation.

---

## (a) ONION / MAIN direct-memory allocation (exact)

Both flatz's Lua and the C++/Java ports allocate **MAIN (onion, system-RAM-backed)
direct memory** — *never* the garlic `sceKernelAllocateDirectMemory` path.

```
// flatz gpu.lua  (alloc_main_dmem, mem_type = 1)
sceKernelAllocateMainDirectMemory(size, size, 1, &phys)     // len, alignment, mem_type=1, &phys_out
sceKernelMapDirectMemory(&va, size, prot, MAP_NO_COALESCE, phys, size)
```

```
// cragson gpu_dma.cpp  (gpu_alloc_dmem) — same, but the named variant
sceKernelAllocateMainDirectMemory(size, size, 1, &phys_out)
sceKernelMapNamedDirectMemory(&va, size, prot, MAP_NO_COALESCE, phys_out, size, "gpudma")
```

```
// flatz GpuMemoryUtil.java (MemoryUtil.allocateMainDirectMemory / mapDirectMemory)
allocateMainDirectMemory(2*1024*1024, 2*1024*1024)      // -> phys
mapDirectMemory(phys, 2MB, 0, PROT_CPU_READ|PROT_CPU_WRITE|PROT_GPU_READ|PROT_GPU_WRITE,
                MAP_NO_COALESCE, 2MB)
scratchBufferRealPhysAddress = phys + Constants.DIRECT_MEM_PHYS_ADDRESS_DISPLACEMENT
```

Exact parameters:

- `len = 2 MiB`, `alignment = 2 MiB` (page-size == buffer-size; this is what makes
  the PTE retarget page-aligned).
- `mem_type = 1` (flatz gpu.lua comment says the valid range is "1-10"; cragson
  also uses `1`; hammer-83's AGC port uses `12` on 7.61 — firmware-dependent, `1`
  is the flatz canonical value and is what probe79 uses).
- `prot = PROT_CPU_READ|PROT_CPU_WRITE|PROT_GPU_READ|PROT_GPU_WRITE`
  (`0x1|0x2|0x10|0x20` = `0x33`).
- `flags = MAP_NO_COALESCE = 0x00400000`.
- `alignment (map) = 2 MiB`.

**Key detail — the physical-address displacement.** flatz computes
`realPhys = phys + DIRECT_MEM_PHYS_ADDRESS_DISPLACEMENT`. The `phys` returned by
`AllocateMainDirectMemory` is the *GPU-domain* address; the value the GPU page
table actually stores (and therefore the value you must OR into a retargeted PTE)
can differ. On 13.60 this manifests exactly as documented in `GPU_DMA_PHYS_FIX.md`:
`AllocateDirectMemory`'s `off` is a **bus address** (`0x2027a00000` =
`0x2000000000 + 0x27a00000`), not the CPU-visible physical. The robust, fw-agnostic
recovery is to **read the real physical out of the GPU leaf PTE** during the page
walk (probe79 does this; see §13.60 adaptation).

---

## (b) The copy: GNM call chain (exact)

There are two entrypoints that reach the *same* GPU copy; psdevwiki states both:

> "With a PS4 game savedata exploit, one has to implement the filling of the DMA
> command buffer and the submission to GPU. Instead, with BD-JB, one just has to
> call `Java.sun.awt.GnmUtils.copyPlanesBackgroundToPrimary`. Using a game
> entrypoint, one can call `sceGnmSubmitCommandBuffers` and `sceGnmSubmitDone`
> from `libSceGnmDriverForNeoMode.sprx`."

### BD-J Java chain (flatz's `GpuMemoryUtil` + `LibGnmAwt`)

```
sun.awt.GnmUtils.copyPlanesBackgroundToPrimary(primaryPlane, bgPlane, ...)   // Java
  └─ JNI native  Java_sun_awt_GnmUtils_copyPlanesBackgroundToPrimary          // in libgnmawt.prx
       ├─ +0x0D  call  lockFunc        (internalLock)
       ├─ +0x73  call  dmaFunc         (internalDirectMemoryCopy(dst, src, size))  ← THE COPY
       ├─ +0xFE  jmp   unlockFunc      (internalUnlock)
       └─ dmaFunc increments a sync counter (syncObject) when the GPU finishes
```

`LibGnmAwt.resolveInternal()` recovers `dmaFunc`/`lock`/`unlock`/sync object by
parsing the `Java_sun_awt_GnmUtils_copyPlanesBackgroundToPrimary` prologue (call
rel32 at `+0x0D` → lock, `+0x73` → dma, jmp at `+0xFE` → unlock; sync object and
sync-value pointer are read out of the dma function's body at `+0x10F`/`+0x133`).
The copy is then:

```java
libGnmAwt.internalLock();
int old = libGnmAwt.getSyncValue();
libGnmAwt.internalDirectMemoryCopy(dst, src, size);     // dmaFunc(dst, src, size)
success = libGnmAwt.waitSync(old + 1, 1000);            // fence/wait
libGnmAwt.internalUnlock();
```

`internalDirectMemoryCopy(dest, src, size)` is literally a GPU memcpy between two
GPU-mapped buffers — the onion victim buffer (retargeted PTE → kernel .data) and
the onion transfer buffer. The `libgnmawt.prx` "AGC graphics API" does the copy
via the GNM copy hardware (the same engine `DMA_DATA` drives).

### Game / payload entrypoint (what probe79 uses)

flatz gpu.lua resolves the GNM symbols and calls them directly (no Java):

```lua
sceGnmSubmitCommandBuffers = fcall(dlsym(libSceGnmDriver.handle, "sceGnmSubmitCommandBuffers"))
sceGnmSubmitDone          = fcall(dlsym(libSceGnmDriver.handle, "sceGnmSubmitDone"))
```

The copy is a hand-built PM4 `DMA_DATA` packet (see (c)) submitted with:

```lua
sceGnmSubmitCommandBuffers(dcb_count, dcb_gpu_addr, dcb_sizes_in_bytes, 0, 0)
sceGnmSubmitDone()
```

probe79 does the same via `dlsym(RTLD_DEFAULT, …)` with a
`dlopen("libSceGnmDriverForNeoMode.sprx")` fallback.

---

## (c) The PM4 command: `PACKET3_DMA_DATA` (opcode `0x50`)

**It is `DMA_DATA` `0x50`, not `COPY_DATA`, and not a compute shader.** (The type-3
header *does* set the "compute shader" shader-type bit — flatz `shader_type = 1` —
but the packet is a DMA copy; the bit selects the CP micro-engine queue class.)

Header + 6 info dwords = 7 dwords (28 bytes):

| dword | value (flatz `pm4_dma_data`) |
|---|---|
| `pkt[0]` | type3 header: `(3<<30) | ((6-1)<<16) | (0x50<<8) | (1<<1)` = `0xC0055002` |
| `pkt[1]` | `dma_data_header`: `cp_sync(1<<31) | dst_cache_policy=2(<<25) | dst_volatile(1<<27) | src_cache_policy=2(<<13) | src_volatile(1<<15)` = `0xA3006000` |
| `pkt[2]` | `src_va` lo32 |
| `pkt[3]` | `src_va` hi32 |
| `pkt[4]` | `dst_va` lo32 |
| `pkt[5]` | `dst_va` hi32 |
| `pkt[6]` | `length & 0x1FFFFF` (bytes) |

Header field decode (flatz `pm4_type3_header`):

```
predicate=0, shader_type=1 (compute), opcode=0x50, count-1=5, packet_type=3
```

`dma_data_header` field decode: engine=0 (DMA), src_sel=0 (memory), dst_sel=0
(memory), src/dst ATC=0, src/dst cache policy=2, src/dst volatile=1, cp_sync=1
(wait for completion). This is byte-for-byte identical across flatz gpu.lua,
cragson gpu_dma.cpp, and probe76's already-verified `/dev/gc` packet — the *only*
difference between the garlic `/dev/gc` path and the onion GNM path is **how the
packet is submitted and which vmid's page tables translate src/dst**.

The **src/dst are GPU virtual addresses** (garlic-window VAs in the process vmid,
e.g. `0xc80000000…` on 13.60), and the copy goes through the *retargeted* victim
leaf PTE so the GPU writes to an arbitrary physical page (kernel `.data`).

---

## (d) Submit mechanism + fence/wait

- **GNM (flat binary / payload):**
  ```
  sceGnmSubmitCommandBuffers(count=1, &dcb_gpu_addr, &dcb_size_bytes, NULL, NULL)
  sceGnmSubmitDone()            // flush / wait for the submission to complete
  ```
  (`dcb_gpu_addr` = GPU VA of the packet buffer; `dcb_size_bytes` = 28.)
  flatz gpu.lua then `sleep(1)`-free — it relies on `sceGnmSubmitDone()`; cragson
  and probe76 additionally `usleep(500ms)` for safety.

- **BD-J Java:** the `libgnmawt` dma function **increments a sync counter** in
  `libgnmawt.prx` data when the GPU finishes; the wait is `waitSync(old+1, timeout)`
  polling `syncObject.read4()`. (This is the fence the native AGC API uses; there is
  no `sceGnmSubmitDone` in the BD-J path.)

- **`/dev/gc` (cragson C++ port, NOT flatz):** `ioctl(fd, 0xC0108102,
  {pipe_id=0, count=1, cmd_buf_ptr=desc_va})` with a 16-byte command-buffer
  descriptor `{ (gpu_addr&0xFFFFFFFF)<<32 | 0xC0023F00, (size_dwords<<32) |
  (gpu_addr>>32) }`. This is the variant that is **garlic/vmid-6 only** on 13.60.

---

## The complete flatz write sequence (normalized)

1. Allocate 2–3 onion (MAIN) buffers, 2 MiB each, mem_type=1, MAP_NO_COALESCE
   (victim = the buffer whose PTE will be retargeted; transfer = staging; cmd =
   PM4 packet buffer).
2. Walk the **process** vmid's GPU page tree to find the victim leaf (PTB entry),
   record `initial_ptb_entry` and `cleared = initial & ~realPhys`.
3. To write PA `P`:
   - `mprotect(victim, RO)` → write `cleared | (P & ~(2MiB-1))` into the victim
     PTB entry (kernel RW) → `mprotect(victim, RW)`. (The `mprotect` drop/restore is
     a TLB-invalidating dance; on 13.60 probe76 showed it's not strictly required.)
   - fill transfer buffer with the data, build the `DMA_DATA` packet
     `(src=transfer_gva, dst=victim_gva + (P & (2MiB-1)), len=8)`.
   - submit (GNM or BD-J as above), wait.
4. Restore the victim PTB entry.

---

## 13.60 adaptation (why the raw ≤7.61 recipe needs a tweak)

On ≤7.61 the direct-memory window is small (`gvmspace.start_va ≈ direct window
base`) so `relative_va = cpu_va - start_va`, and onion buffers are system-RAM
backed at the CPU VA in the process vmid — the garlic/onion split does not bite.

On 13.60 (measured, see `GPU_DMA_KDATA_WRITE.md` / `GPU_DMA_PHYS_FIX.md`):

- `gvmspace[vmid].start_va = 0`, `.size = 2^48` → `relative_va = cpu_va` is **not**
  the GPU VA.
- The onion (MAIN) buffer maps in the **process vmid (2)** at fixed garlic GPU VA
  base **`0xc80000000`**, 8 KB leaves, phys `0x33400000` (system RAM), populated
  lazily (~288 KB of 2 MB present).
- The `/dev/gc` **dev vmid (6)** maps the same buffer at its CPU VA but **VRAM-only**
  (garlic leaf phys `0x47bc00000` > 16 GiB) — retargeting it to a system-RAM PA
  never lands.

So probe79 mirrors flatz but with the 13.60-specific adjustments:

1. **ONION alloc with `mem_type=1`** (flatz exact).
2. **Walk the process vmid (2)** — read `vmspace.vm_vmid` from the current proc.
3. **Recover the real physical from the GPU leaf PTE** (not from `off`).
4. **Use the fixed onion GPU VA `0xc80000000`** for packet/src/dst (not the CPU VA).
5. **Single victim buffer, 4 leaves** (leaf0=retarget, leaf1=sentinel src,
   leaf2=DMA_DATA packet, leaf3=T2 sanity target) so the whole primitive lives
   inside the lazily-populated region — no separate staging/cmd buffer needed.
6. **Kernel VA→PA via the validated kernel CR3 walk** (anchor: `kernel_pmap_store`
   at `kdata + 0x28c84a8`, invariant `kernel_pml4_kva - DMAP == CR3`), target a
   **zeroed 8-byte `.data` field** at `kdata + 0x299AD0`, self-check DMAP.
7. **Submit via GNM** `sceGnmSubmitCommandBuffers` + `sceGnmSubmitDone` (not the
   `/dev/gc` ioctl).

---

## probe79 (buildable, verified)

- `C:\Users\USER\AppData\Local\kex\cache\scratch\ps5\probe79\main.c`
- `.../probe79/Makefile` → `flatcopy.elf`

**Build verified** (WSL Ubuntu, ps5-payload-sdk v0.43, clang-18):
`make` → `flatcopy.elf` (ELF64 x86-64 PIE, 120 KB), no warnings/errors; undefined
symbols are only libc/libkernel (`open/snprintf/usleep/getpid/memset/strlen/
write/fsync/printf/dlsym/dlopen`) — all `sce*` functions are resolved at runtime
via `dlsym` exactly like flatz. **Not deployed** (offline; console in use by
another session). Log target: `/data/kex_flatcopy.txt`.

`main.c` T2 (self-test: retarget leaf0→leaf3, DMA leaf1→leaf0) then T3 (retarget
leaf0→kernel-.data 8 KB base, DMA leaf1→leaf0+off, sentinel), then restores the
PTE and DMAs zeros back. PASS criteria: `kernel_copyout(target_kva)` and
`read_phys(target_pa)` both equal the sentinel → `RESULT: KDATA_WRITE_PASS`.

Prior work preserved: the old `probe79/main.c` (an IOMMU-MMIO read probe) is saved
as `probe79/mmioread.c`.
