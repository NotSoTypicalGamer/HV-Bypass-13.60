# Y2JB GPU-DMA kernel-.data write — 13.60 reuse & port assessment (OFFLINE)

**Task:** determine (1) exactly how the Y2JB-shipped GPU-DMA kernel-.data write is
implemented, (2) whether the Y2JB *host* works on 13.60 and whether the p2jb *kernel*
exploit is capped at 12.40, (3) whether the gpu.js module can be reused as our 13.60
GPU-DMA system-RAM write with Relapse kernel R/W, and what must be ported.

**Status:** offline source-level research. All repos fetched and read. No console work.
Own console, nothing published.

**Provenance note:** `tcphdr/P2JB-Y2JB-Porting` and `tcphdr/P2JB` **404** — the account was
renamed. The live repo is **`matem6/P2JB-Y2JB-Porting`** (tcphdr is the credited author in
issue threads; matem6 maintains it). `Gezine/Y2JB` and `Gezine/Luac0re` are intact. All four
cloned to `scratch` and read in full.

---

## TL;DR verdict

| Question | Answer |
|---|---|
| Q1: which module does the GPU-DMA .data write, and what does it submit through? | `p2jb.js`'s inline `gpu` object (a JS port of Y2JB's now-removed `gpu.js`). **Submit = `ioctl("/dev/gc", 0xC0108102, …)` — the direct-ioctl path, NOT `sceGnmSubmitCommandBuffers`.** |
| Q2a: does the Y2JB *host* work on 13.60? | **YES.** Y2JB 1.7 ships ROP/offset sets for 13.20/13.40 and an `elfldr-ps5-1360.elf`; README supports "12.60 and up" (YouTube app 01.000.030 PKG). |
| Q2b: is the p2jb *kernel* exploit capped at 12.40? | **YES.** `kqueueex` cr_ref overflow, patched in **13.00**. p2jb.js bundles offsets only 9.00–12.40. |
| Q3: can gpu.js be reused on 13.60 with Relapse R/W? | **YES, in principle** — but the `/dev/gc` submit must switch to **GNM** (the flatz path), because on 13.60 `/dev/gc` is VRAM-only (vmid 6). Y2JB is a GNM-initialized process, which is exactly the context our elfldr-based attempts were missing. |

---

## 1. Q1 — exact implementation of the GPU-DMA kernel-.data write

### 1.1 Where the code lives

- `matem6/P2JB-Y2JB-Porting/p2jb.js` — the inline `gpu` object + helpers. The debug-menu
  apply is `stage_debug_menu(S)` (≈ lines 1902–1992).
- `Gezine/Y2JB` tag `1.2.1` / `1.3` — `…/tv=/gpu.js` (441 lines), the standalone module the
  p2jb.js code was copied from. **Removed in Y2JB 1.4** ("Deprecated GPU RW", commit
  `02eda2e`, -442 lines). Credits: *"flatz, LM, hammer-83 and shadPS4"*; Y2JB README credits
  *"flat_z and LM — Helping implement GPU rw using direct ioctl"*.
- p2jb.js `gpu.js` debug-menu flow is credited in the P2JB README to **lapse (Y2JB)** — i.e.
  the gpu.js module predates p2jb and is reused verbatim.

### 1.2 The five pieces

**(a) Onion (MAIN) direct-memory alloc** — `alloc_main_dmem()` (p2jb.js ≈1850–1866):

```js
sceKernelAllocateMainDirectMemory(size, size, mem_type=1, &phys)   // 3 × 2 MiB: victim/transfer/cmd
sceKernelMapNamedDirectMemory(&va, size, 0x33, MAP_NO_COALESCE=0x400000, phys, size, "mem")
```

`prot = PROT_READ|PROT_WRITE|GPU_READ|GPU_WRITE = 0x33`; `mem_type=1` = onion/main
(system-RAM-backed), never garlic. This is identical to flatz `gpu.lua` and cragson
`gpu_dma.cpp`.

**(b) GPU page-table walk** — walks the **process vmid** GPU tree (p2jb.js ≈1655–1697):

```js
vmid      = get_curproc_vmid()                       // u32 @ vmspace + VMSPACE_VM_VMID
gvmspace  = data_base + DATA_BASE_GVMSPACE + vmid*SIZEOF_GVMSPACE(0x100)
pdb2      = gvmspace.PAGE_DIR_VA(0x38)               // top of the GPU page tree
// 4-level walk: PDB2/PML4 -> PDB1/PDPT -> PDB0/PD -> PTB/PTE
//   IS_PTE (bit 54)            -> 2 MB leaf  [page_size 0x200000]
//   BLOCK_FRAGMENT_SIZE (59)   -> frag=4: 64 KB, or 8 KB via TF (bit 56)
//                              -> frag=1: 8 KB
```

**(c) PTE retarget** — mprotect(RO) round-trip to capture `cleared = pte & ~victim_real_pa`,
then kernel-write `cleared | trunc_phys_addr` into the victim leaf PTE, mprotect(RW). (`gpu.setup`
≈1722–1753, `transfer_physical_buffer` ≈1807–1830.)

**(d) PM4 packet** — `PACKET3_DMA_DATA`, opcode **0x50**, type-3 header + 6 info dwords
(28 bytes). Header `0xC0055002`; `dma_data_header = 0x8C00C000`
(cp_sync|dst_cache_policy=2|dst_volatile|src_cache_policy=2|src_volatile). src/dst = GPU VAs;
length = bytes & 0x1FFFFF.

> **Correction vs our own notes:** `FLATZ_GNM_COPY.md §(c)` lists `0xA3006000`; the actual
> code in gpu.js / p2jb.js / cragson / the on-console-verified probe76 all emit **`0x8C00C000`**
> (the doc transposed src/dst cache-field shifts). See `FLATZ_GPU1360_LUA.md §3`.

**(e) Submit** — `gpu.ioctl_submit_commands()` (p2jb.js ≈1713–1720):

```js
ioctl(fd, 0xC0108102, { pipe_id=0 (dword), count=1 (dword), cmd_desc_ptr (qword) })
// cmd descriptor (16 B): qword0 = (gpu_addr_lo32 << 32) | 0xC0023F00
//                       qword1 = (size_dwords << 32) | (gpu_addr >> 32)
```

**This is the answer to "GNM or something else": something else.** It is the **`/dev/gc`
direct ioctl `0xC0108102`** (the cragson / "flat_z + LM direct-ioctl" variant), **not**
`sceGnmSubmitCommandBuffers`. The flatz *Lua* original uses GNM; the Y2JB/p2jb JS port uses
the ioctl. Both share the same onion alloc + process-vmid walk + `DMA_DATA` packet and differ
only in the submission channel.

### 1.3 What it writes (the "Debug Settings menu" side effect)

`stage_debug_menu` (p2jb.js ≈1955–1986) writes four kernel `.data` fields via
`gpu.write_dword/byte`:

| field | offset (from data_base) | written |
|---|---|---|
| security_flags | `DATA_BASE_SECURITY_FLAGS` | `|= 0x14` |
| target_id | `DATA_BASE_SECURITY_FLAGS + 0x09` | `= 0x82` |
| qa_flags | `DATA_BASE_SECURITY_FLAGS + 0x24` | `|= 0x10300` |
| utoken_flags | `DATA_BASE_SECURITY_FLAGS + 0x8C` | `|= 0x1` |

Each `gpu.write_*` does: `virt_to_phys(addr, kernel_cr3)` → `transfer_physical_buffer` (retarget
victim leaf → target PA → DMA transfer→victim). Verification re-reads via `kernel.read_*`
and asserts the bits landed.

### 1.4 External dependencies the module requires (the "kernel" table)

The gpu.js module consumes, but does not itself produce:

```
kernel.read_qword / write_qword     (arbitrary kernel VA R/W  — the JB chain's kread/kwrite)
kernel.addr.data_base / curproc / dmap_base / kernel_cr3
kernel_offset.{DATA_BASE_GVMSPACE, DATA_BASE_KERNEL_PMAP_STORE, VMSPACE_VM_VMID, ...}
```

In p2jb.js these are wired to `S.kread/S.kwrite` + `S.data_base/S.curproc` (the p2jb
kernel-exploit output). On 13.60 these would be wired to **Relapse** instead (see §3).

---

## 2. Q2 — firmware support

### 2.1 Y2JB **host** (userland V8 entrypoint): works on 13.60

- `Gezine/Y2JB` `main.js` → `version_string = "Y2JB 1.7 by Gezine"`.
- `global.js` carries **four** ROP + offset sets keyed to the YouTube/Cobalt build:
  `ROP_403`/`Y2_OFFSET_403` (eboot-based, old app), `ROP_1220`, `ROP_1320`, `ROP_1340`
  (libcobalt/libstarboard-based). `Y2_OFFSET_1320`/`Y2_OFFSET_1340` correspond to the
  12.60+ / 13.x YouTube app.
- README (main + git.etawen.dev mirror): *"For firmware 4.03 to 12.40 get YouTube app
  (PPSA01650) version 01.000.003 PKG; **for firmware 12.60 and up get YouTube app version
  01.000.030 PKG**."*
- Releases: Y2JB 1.6 — *"Added support for 12.60 and higher firmware; Updated elfldr with
  13.40 support"*.
- The host ships **`elfldr-ps5-1360.elf`** + `kexp_2026_05_25.bin` (ufm42's post-JB shellcode)
  in `download0/cache/splash_screen/…/tv=/`, loaded by `aioshellcode.js`
  (`load_aioshellcode` → `jitshm_create` + `mmap` RWX + `Thrd_create`).

**Conclusion:** the Y2JB userland entrypoint (V8 addrof/fakeobj → ROP → syscall) is live on
13.60 with the 01.000.030 YouTube PKG. This is the second GNM-initialized context we hold
(the other being the now-dead Luac0re/PS2EMU save-data path).

### 2.2 p2jb **kernel** exploit: capped at 12.40 (patched 13.00)

- p2jb.js header: *"offsets bundled for FW 9.00 – 12.40"*; README: *"works on 9.00 – 12.40"*.
- `FW_OFFSETS_P2JB` = {9.00, 9.05, 10.00, 11.00, 12.00}; `FW_ALIAS_P2JB` maps 12.60/12.70 →
  12.00 (best-effort only; no 13.x). `ensure_kernel_offset()` throws *"p2jb: FW X not
  supported"* for any 13.x.
- The bug (`sys_kqueueex` missing `crfree(kq->kq_cred)` in the copyinstr-error path → cr_ref
  overflow) is **patched in 13.00** (Sony adds the missing `crfree`) — see `PUBLIC_P2JB.md`.

**Consequence for 13.60:** there is **no p2jb kernel R/W** on the target. The kernel-R/W source
that the gpu.js module needs must be **Relapse** (aio_multi_wait UAF, 7.00–13.60), which we
already have. p2jb's exploit stages (leak → triple-free → pipe/IPv6 R/W → root → elfldr) are
irrelevant to the GPU-DMA port; only the *kernel read/write primitive output* matters, and
Relapse provides the equivalent (`kread/kwrite` + `kdata_base` + `dmap`).

---

## 3. Q3 — reusing gpu.js as our 13.60 system-RAM write

### 3.1 What carries over unchanged

The gpu.js algorithm (onion MAIN alloc → process-vmid walk → leaf retarget → `DMA_DATA`
packet) is firmware-agnostic in *shape*. The 13.60-specific deltas are already solved in our
corpus (see `FLATZ_GPU1360_LUA.md` + `gpu1360.lua`, the flatz gpu.lua port we already wrote):

| gpu.js / p2jb.js (≤12.40) | 13.60 replacement | source |
|---|---|---|
| `VMSPACE_VM_VMID = 0x1E4/0x1EC` | **`0x1FC`** (measured; u32 = 2) | `GPUVM_OFFSETS_1360_v2.md` |
| `DATA_BASE_GVMSPACE = 0x2E7E570` (12.00) | **`0x2EEA570`** (IDT anchor `idt−0x9D90`) | `FLATZ_GPU1360_LUA.md §4` |
| `rel_va = cpu_va − gvmspace.start_va` (start_va≈window base) | **fixed onion GPU VA `0xc80000000`** (start_va=0 on 13.60) | `GPU_DMA_PHYS_FIX.md` |
| 4-level walk, 2 MB `IS_PTE` leaf required | **5-level walk, 8 KB leaves** (`TF` bit 56) | `GPUVM_POPULATION.md §1` |
| `victim_real_pa = virt_to_phys(victim_va)` | **recover PA from the leaf PTE** (`& 0xFFFFFFFFE000`) | `FLATZ_GPU1360_LUA.md §3` |
| `page_size != dmem_size → error()` | **accept 8 KB leaves**; single victim, first 4 leaves | `gpu1360.lua` |
| `mprotect(RO)/mprotect(RW)` PTE dance | direct `kwrite64(dmap+pte, new)` (dance unnecessary) | probe76 |

### 3.2 The one real blocker: the submission channel

p2jb.js / gpu.js submit via **`/dev/gc` ioctl 0xC0108102**. On 13.60 our measurements
(`GPU_DMA_KDATA_WRITE.md`, `GPUVM_POPULATION.md §4`) show this path is **vmid 6 / garlic /
VRAM-only** — a retargeted leaf pointing at a system-RAM PA never lands. The system-RAM
(onion) mapping lives in the **process vmid (2)** at GPU VA `0xc80000000` and is reached via
**GNM** (`sceGnmSubmitCommandBuffers` + `sceGnmSubmitDone`) — the flatz `gpu.lua` path, which
our `gpu1360.lua` already implements.

**Why this is now viable (the key insight):** our prior GNM attempts failed because
`Gnm::Initialize()` cannot complete in a **bare elfldr process** (`GPU_DMA_SYSRAM_WRITE.md`:
`"Failed to get trap handler code"`, `sceGnmSubmitDone → 0x80D4FFFF`). The **YouTube process is
a real, GNM/AGC-initialized app** — exactly the pre-initialized-driver context where flatz
`gpu.lua` works ("a game entrypoint … call sceGnmSubmitCommandBuffers and sceGnmSubmitDone").
So the submit-side blocker that stopped the elfldr path does not apply inside Y2JB.

Y2JB has the two helpers needed to resolve GNM, gated only on being jailbroken (which Relapse
satisfies): `find_mod_by_name("libSceGnmDriverForNeoMode.sprx")` + `dlsym(handle,
"sceGnmSubmitCommandBuffers"/"sceGnmSubmitDone")` (`misc.js` ≈360–388). After the JB, `dlsym`
is unrestricted (`dynlib`/`syscall` maximized, as p2jb's stage7 does).

### 3.3 Concrete port plan (translate `gpu1360.lua` → Y2JB JS)

1. **Wire the `kernel` table to Relapse** (replaces p2jb's `S.kread/S.kwrite`):
   `kernel.read_qword/write_qword`, `kernel.addr.{data_base, curproc, dmap_base, kernel_cr3}`.
   `kdata_base`/`dmap` are per-boot (KASLR) — use `payload_get_args()->kdata_base_addr` /
   `KERNEL_ADDRESS_DMAP_BASE`, never hardcode.
2. **Port `gpu1360.lua` to JS** — the 5-level 8 KB walk, onion GPU VA `0xc80000000`, leaf-PTE
   PA recovery, `0x8C00C000` header — keeping the gpu.js onion-alloc + `pm4_dma_data` skeleton.
3. **Swap the submit**: `ioctl_submit_commands` → `sceGnmSubmitCommandBuffers(count, &gva,
   &size, 0, 0)` + `sceGnmSubmitDone()`, with `dcb_gpu_addr`/`dcb_sizes` as heap buffers holding
   `{cmd_gva}`/`{size}` (per flatz gpu.lua). Keep the retarget→submit→restore sequence.
4. **Update the debug-menu targets** for 13.60 `.data` offsets (security_flags/qa_flags/
   utoken_flags/target_id moved vs 12.00 — same fields, re-derived like `DATA_BASE_GVMSPACE`).
5. **Lazy-population guard**: use only the first four 8 KB onion leaves (already present),
   error cleanly if missing; if a larger copy is ever needed, the fault-driven populate recipe
   is `GPUVM_POPULATION.md §3`.

### 3.4 Open questions (probe before betting the primitive)

1. **Does the YouTube process actually have `libSceGnmDriverForNeoMode.sprx` loaded + GNM
   initialized?** It may use the native **SceAgcGnmp / libgnmawt (AGC)** stack instead of the
   PS4-compat GNM driver (same concern flagged for PS2EMU in `FLATZ_GPU1360_LUA.md §6.1`). If
   GNM is absent, the BD-J fallback is the AGC copy (`sun.awt.GnmUtils.copyPlanesBackgroundToPrimary`
   / `libgnmawt` `internalDirectMemoryCopy`) — the flatz Java path. Cheap probe:
   `sceKernelLoadStartModule("libSceGnmDriverForNeoMode.sprx", …)` + `dlsym` for the two
   submit symbols; ≥0x80000000 return = not available.
2. **Is `/dev/gc` 0xC0108102 VRAM-only *in the YouTube process*, or only in the bare elfldr
   process?** Our vmid-6 measurement was elfldr-context; a registered GPU client *might* bind
   `/dev/gc` to the process vmid. If the ioctl path turns out to reach system RAM in Y2JB, the
   port shrinks to offsets-only (no GNM swap). Worth a one-shot test before committing to GNM.
3. **Relapse R/W wiring**: does our Relapse payload expose `kread/kwrite` as callable
   functions in-process, or only over its daemon socket? (`FLATZ_GPU1360_LUA.md §5` lists both
   wirings.)

---

## 4. Files / sources

- Cloned to `scratch/y2jb_research/`: `matem6/P2JB-Y2JB-Porting`, `Gezine/Y2JB`,
  `Gezine/Luac0re`. (`tcphdr/P2JB-Y2JB-Porting`, `tcphdr/P2JB` 404 → matem6 mirror.)
- Read: `p2jb.js` (full), `gpu.js` @ tag 1.3 (full), `kernel.js` / `global.js` / `misc.js` /
  `aioshellcode.js` / `main.js` (Y2JB host), `payloads/p2jb.lua` + `lua/memory.lua` (Luac0re).
- Cross-referenced local corpus: `PUBLIC_P2JB.md`, `FLATZ_GNM_COPY.md`, `FLATZ_GPU1360_LUA.md`
  (+ `gpu1360.lua`), `GPU_DMA_KDATA_WRITE.md`, `GPU_DMA_SYSRAM_WRITE.md`, `GPUVM_OFFSETS_1360_v2.md`,
  `GPUVM_POPULATION.md`, `GPU_DMA_PHYS_FIX.md`, `GNM_INIT_SEQUENCE.md`.

## 5. Key numbers (13.60, all measured previously)

`VMSPACE_VM_VMID = 0x1FC` · `DATA_BASE_GVMSPACE = 0x2EEA570` · `SIZEOF_GVMSPACE = 0x100` ·
`gvmspace.page_dir_va = 0x38` · process vmid `= 2` · onion GPU VA base `= 0xc80000000` ·
5-level walk, 8 KB leaves (TF bit 56) · leaf PA mask `0xFFFFFFFFE000` (8 KB) /
`0xFFFFFFE00000` (2 MB) · `DMA_DATA` header `0x8C00C000` · `OFFSET_KERNEL_PMAP_STORE = 0x28c84a8`.
