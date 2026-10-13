# GNM driver init sequence for a payload process (PS5)

**Status:** research only — nothing deployed. Resolves the elfldr GNM failure
(`"Failed to get trap handler code"`, `sceGnmSubmitDone` = `0x80D4FFFF`).

## TL;DR

- The **"trap handler code"** is the GPU *trap handler* — the small piece of
  GPU code that runs on a GPU exception / protection fault (the AMD **TBA/TMA**
  trap handler: Trap Base Address / Trap Memory Address). The GNM driver
  installs it during **module init**, not through any exported `sceGnm*` call.
- **No `sceGnm*` call installs the trap handler.** There is no
  `sceGnmInitialize` / `sceGnmInit` / trap-handler export. It is fetched and
  installed automatically when `libSceGnmDriver[ForNeoMode].sprx` is *loaded*
  (its `module_start` runs at `dlopen` time).
- **GNM cannot be initialized in a bare elfldr payload process.** The fetch of
  the trap-handler code requires the graphics/app context (GPU kernel-driver
  per-process setup) that an elfldr process lacks. This is why every working
  reference runs in a *game/app* process, and why payloads that need GPU DMA
  use the raw `/dev/gc` ioctl instead of GNM.

---

## 1. The failing call, decoded

Sequence observed in the elfldr payload (from `GPU_DMA_KDATA_WRITE.md`):

1. Payload links `libSceGnmDriverForNeoMode` (stub) → the ELF loader `dlopen`s
   the real `.sprx`.
2. The sprx's **module init** runs and tries to fetch the trap handler → fails
   → logs **`Failed to get trap handler code`** to klog/TTY.
3. The driver is left **uninitialized**; `sceGnmSubmitCommandBuffers(...)` and
   `sceGnmSubmitDone()` then return `0x80D4FFFF`.

`0x80D4FFFF` is the PS5 GNM-driver generic "not initialized / internal error".
(PS4 GNM errors use `0x80D1xxxx` — see shadPS4 `gnm_error.h`; the `0x80D4`
prefix is the PS5/ForNeoMode error space, `0xFFFF` = generic. No public
authoritative decode of this exact value exists; treat as "driver not
initialized because init failed".)

---

## 2. What "trap handler code" actually is

The GPU, like the CPU, needs a handler for faults: illegal shader instruction,
memory violation, protection fault, divide-by-zero, etc. On AMD hardware this
is the **trap handler**, addressed through the **TBA** (Trap Base Address) and
**TMA** (Trap Memory Address) registers — see AMD's `cwsr_trap_handler` in the
`amdkfd` driver and the LLVM "AMDGPU Trap Handler ABI" docs.

Privilege model is the key fact:

- **gfx8 and below** (PS4 "Liverpool" is GCN ~gfx7): TBA/TMA are **not
  privileged** — userland can set them (via packets).
- **gfx9 and above** (PS5 "Oberon" is RDNA 2, ~gfx10.3): setting TBA/TMA is a
  **privileged, kernel-only** operation.

Therefore on PS5 the trap-handler *code* cannot be statically installed by the
userland GNM driver; it must be **obtained from the kernel GPU driver** at init
time — which is exactly what "get trap handler code" is doing, and exactly what
fails when the process has no graphics context.

(References: AMD amdkfd `cwsr_trap_handler_*`; the "AMDGPU: add support for
user trap handlers" patch — "On GFX9+ [TBA/TMA] are per VMID and privileged,
only the KMD can configure them"; martty "Making an AMDGPU debugger part III —
Trap handler": "On gfx8 and below, setting these are nonprivileged… from gfx9
and above, setting TBA and TMA is a privileged operation and only the kernel
can do it.")

---

## 3. Which sceGnm call installs it — answer: none

Two independent sources list the complete export set of the GNM driver; neither
contains any init or trap-handler function:

- **PS4 RE** (shadPS4 `gnmdriver.cpp`, 254 exports).
- **PS5 3.20 sprx dump** (`DNNDHH/PS5-3.20_Libs/libSceGnmDriverForNeoMode.c`,
  generated from the real sprx).

Init-*adjacent* exports, for clarity:

| Function | What it actually does |
|---|---|
| `sceGnmDispatchInitDefaultHardwareState` | Writes register-reset packets **into a command buffer** (hardware state, not driver init) |
| `sceGnmDrawInitDefaultHardwareState` / `175` / `200` / `350` | Same — firmware-version-specific register-reset sequences into a command buffer |
| `sceGnmDrawInitToDefaultContextState[400]` | Context-state reset packets into a command buffer |
| `sceGnmMapComputeQueue` / `MapComputeQueueWithPriority` / `UnmapComputeQueue` | Map/unmap the GFX/compute ring to the process (this is the *queue* setup) |
| `sceGnmDriverInternalRetrieveGnmInterface[For...]` | Internal driver interface retrieval (validation/replay/debugger) |
| `sceGnmSubmitCommandBuffers` / `SubmitAndFlip…` / `SubmitDone` | Submission + wait-for-idle |

**Conclusion:** the trap handler is installed inside the sprx's `module_start`
(load-time init). There is no `sceGnmInit`/`sceGnmInitialize` to call, and
there is no hidden "install trap handler" call you can invoke directly.

---

## 4. Minimal init + submit sequence

This is the *working* sequence — it requires the driver to already be
initialized (i.e. you are in a process where `libSceGnmDriver[ForNeoMode].sprx`
loaded successfully). It is exactly what flatz's `gpu.lua` does (see §6):

```
/* 0. NO explicit init — driver auto-initialized when the .sprx was loaded.   */

/* 1. Map the GFX/compute queue to this process (flatz skips this because the
 *    game already mapped it).                                                */
uint32_t queueIndex = 0;
sceGnmMapComputeQueue(0 /*pipeId*/, &queueIndex, NULL, NULL, NULL);

/* 2. Allocate MAIN (onion = system-RAM-backed) direct memory, GPU-visible.   */
void*  physOut = 0;
void*  vaOut   = 0;
sceKernelAllocateMainDirectMemory(align, size, /*memType=*/1, &physOut);
sceKernelMapDirectMemory(&vaOut, size,
    PROT_READ|PROT_WRITE|PROT_GPU_READ|PROT_GPU_WRITE,
    MAP_NO_COALESCE, physOut, size);

/* 3. Build a PM4 command buffer (e.g. PACKET3_DMA_DATA, opcode 0x50).        */

/* 4. Submit.                                                                 */
uint64_t dcbGpuAddr[1] = { cmdBufVa };
uint32_t dcbSize[1]    = { cmdBufBytes };
sceGnmSubmitCommandBuffers(1, dcbGpuAddr, dcbSize, /*dummy=*/0, /*flags=*/0);

/* 5. Wait for the submission to drain.                                       */
sceGnmSubmitDone();
```

For the DMA-copy use case the packet is a `PACKET3_DMA_DATA` (opcode `0x50`,
count 6): `[src_lo, src_hi, dst_lo, dst_hi, length]` — identical to what the
Caliper `/dev/gc` probes already encode (see `GPU_DMA_WRITE.md`).

The full `sceGnmSubmitCommandBuffers` → `sceGnmSubmitDone` pair (with
`sceKernelAllocateMainDirectMemory` + `sceKernelMapDirectMemory`) is visible
verbatim in flatz's `gpu.lua` (`submit_dma_data_command`, `alloc_main_dmem`).

---

## 5. Can GNM init in an elfldr payload? — No (in general)

The elfldr process is a minimal payload process spawned by the exploit's ELF
loader. It has **no graphics context**: no video-out, no per-process GPU
kernel-driver context, and — critically — the GPU trap handler is not available
to it. The GNM driver's load-time init fails on the trap-handler fetch, so the
driver never reaches the initialized state and every submission call returns
`0x80D4FFFF`.

Evidence this is a *context* problem, not a "wrong call order" problem:

1. **flatz's `gpu.lua`** (`itsPLK/ps5-lua-autoloader`) never calls any init; it
   just `find_mod_by_name("libSceGnmDriverForNeoMode.sprx")` and `dlsym`s
   `sceGnmSubmitCommandBuffers` + `sceGnmSubmitDone`. It works because it runs
   **inside a PS4-game process on the PS5**, where the driver is already loaded
   *and* initialized.
2. **psdevwiki (Vulnerabilities, "GPU DMA")**: *"Using a game entrypoint, one
   can call `sceGnmSubmitCommandBuffers` and `sceGnmSubmitDone` from
   `libSceGnmDriverForNeoMode.sprx`."* — a **game entrypoint** is the stated
   precondition. The same page notes the GPU-DMA write of kernel `.data` is the
   only route past the 6.00+ hypervisor `.data` write protection.
3. **ps5-linux-loader `gpu.c`** (payload context) does GPU DMA via the raw
   **`/dev/gc` ioctl** (`open("/dev/gc")` + `GPU_SUBMIT_IOCTL`), *not* GNM.
4. **etaHEN** links `libSceGnmDriver.so` + `libSceAgcGnmp.a` +
   `libSceAgcGpuAddress.a` + `libSceSdma.so` (the PS5-native GNM/"Agc" stack)
   and does GPU DMA from its daemon — but its daemons are spawned by the
   bootstrapper after the exploit in a context that retains the graphics stack;
   this is not the elfldr-`dlopen` case. (The public repo no longer ships the
   `gpu_dma` source; the libs are the only surviving trace.)
5. The Caliper elfldr attempt itself: init fails with exactly the trap-handler
   error, then `0x80D4FFFF`.

**Net:** you cannot "just call the right sceGnm sequence" from elfldr. The
driver's own load-time init is what fails, and on RDNA 2 the missing piece
(trap handler) is kernel-privileged, so there is no userland call that can
recreate it from a bare payload.

---

## 6. The alternative: `/dev/gc` raw path (and why it regressed on 13.60)

Payloads that need GPU DMA from a non-game process use the raw `/dev/gc` ioctl
(no GNM driver). The Caliper team already has this working for VRAM
(`GPU_DMA_WRITE_TEST.md`, ioctl `0xC0108102` / `PACKET3_DMA_DATA`).

Why it stopped reaching system RAM on 13.60 (`GPU_DMA_KDATA_WRITE.md`):

- **≤12.40** (where flatz / tcphdr / firmware-spoofer work): `/dev/gc` is bound
  to the **process vmid** and MAIN direct memory is system-RAM-backed at the CPU
  VA → the `/dev/gc` DMA can reach system RAM directly.
- **13.60**: `/dev/gc` opens **vmid 6** (a "dev" vmid) whose mappings are
  **garlic/VRAM-only** (`>16 GiB` physical). The **onion (system-RAM)** mapping
  lives in **vmid 2** (the process vmid) at the garlic GPU VA `0xc80000000`,
  reachable only through GNM submission — which is unavailable in elfldr (§5).

So on 13.60 the two halves are mutually exclusive in a payload: `/dev/gc` =
VRAM-only, GNM = needs a game process.

---

## 7. Paths forward (for the system-RAM write goal)

1. **Get a game/app entrypoint (the established route).** Run the GPU-DMA write
   in a process that already has `libSceGnmDriverForNeoMode` loaded+initialized:
   PS4-game save-data exploit, Lua loader, BD-JB, or Y2JB/YouTube — the exact
   contexts flatz / etaHEN / the firmware-spoofers use. This is how every public
   6.00+ kernel-`.data` GPU write is done.
2. **Chase the `/dev/gc` vmid regression.** Investigate whether 13.60 changed
   which vmid `/dev/gc` binds (kernel offset/flag), or whether a different
   device node / ioctl re-binds it to the process vmid. If `/dev/gc` can be made
   to open vmid 2 again, the existing `/dev/gc` primitive reaches system RAM
   with no GNM dependency.
3. **Do not** attempt to reimplement the trap-handler install from userland: on
   RDNA 2 TBA/TMA are privileged; only the kernel GPU driver can supply them.

---

## Sources

- shadPS4 `src/core/libraries/gnmdriver/gnmdriver.cpp` + `gnm_error.h` +
  `gnmdriver.h` (PS4 GNM export list, error codes):
  <https://github.com/shadps4-emu/shadPS4/tree/main/src/core/libraries/gnmdriver>
- `DNNDHH/PS5-3.20_Libs/libSceGnmDriverForNeoMode.c` (PS5 3.20 sprx export
  list, generated from the real module):
  <https://github.com/DNNDHH/PS5-3.20_Libs/blob/main/libSceGnmDriverForNeoMode.c>
- flatz `gpu.lua` (GNM submission from a game process, no init call):
  <https://github.com/itsPLK/ps5-lua-autoloader> (`savedata/gpu.lua`)
- ps5-linux-loader `gpu.c` (`/dev/gc` raw ioctl from a payload):
  <https://git.etawen.dev/mia/ps5-linux-loader> (`source/gpu.c`)
- psdevwiki PS5 Vulnerabilities — GPU DMA + "game entrypoint" requirement:
  <https://psdevwiki.com/ps5/Vulnerabilities>
- etaHEN (PS5-native GNM/"Agc" link set): <https://github.com/etaHEN/etaHEN>
- SharpProspero graphics-gpu.md (`AgcDevice.Initialize`, `SceAgcDriver`
  submit/queue/flip/wait): <https://github.com/SvenGDK/SharpProspero>
- AMD trap-handler privilege (TBA/TMA): martty "Making an AMDGPU debugger
  part III — Trap handler" <https://martty.github.io/posts/radbg_part_3>; AMD
  amdkfd `cwsr_trap_handler`; LLVM "AMDGPU Trap Handler ABI".

## Local context (Caliper-C0re)

- `kernel/GPU_DMA_KDATA_WRITE.md` — the 13.60 `/dev/gc` vmid-6 VRAM-only finding.
- `kernel/GPU_DMA_WRITE_TEST.md` — the confirmed `/dev/gc` VRAM→VRAM primitive.
- `kernel/HANDOFF.md` — the GNM/vmid-2 path and the `"Failed to get trap handler
  code"` / `0x80D4FFFF` symptom.
