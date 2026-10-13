# GPU-DMA system-RAM (kernel .data) write via the onion/vmid-2 GNM path — 13.60

## Goal
Prove a system-RAM (kernel `.data`) write on 13.60 by retargeting the vmid-2 (process) onion
leaf (`garlic GPU VA 0xc80000000 -> system-RAM phys 0x33400000`) to a safe zeroed kernel
`.data` field's physical, DMA-writing the sentinel `0xDEADBEEFCAFEBABE` through it, and
reading it back via `kernel_copyout` — submitted via **GNM** (`sceGnmSubmitCommandBuffers`),
NOT `/dev/gc`.

## Result: **FAIL — GNM cannot be initialized in the elfldr payload process** (`sysram_write_pass = false`)

The victim-only GNM variant (`probe78/kwrite3.c`) was built and deployed. The vmid-2 onion
leaves ARE all populated (no lazy-population problem for the first four 8KB leaves), the
process vmid is confirmed `2`, and the retarget PTE write lands (read-back confirms it).
But the GNM submission is a **silent no-op**: `sceGnmSubmitCommandBuffers` returns `0`
("success") yet the DMA copy does not execute — even the pure system-RAM→system-RAM
*within-victim* sanity copy (T2) returns `got=0` instead of the sentinel.

Root cause (reverse-engineered from the in-memory image of
`/system/common/lib/libSceGnmDriverForNeoMode.sprx`): the driver's `Gnm::Initialize()`
fails during module load in the bare elfldr process, leaving the driver in an
uninitialized state where every submission is dropped.

## Live run values (13.60, fw `0x13600007`)

| Item | Value |
|---|---|
| TEXT_BASE / DATA_BASE / kdata_base | `0xffffffff8de00000` / `0xffffffff8eac0000` / `0xffffffff8eac0000` |
| target offset / target_kva / target_pa (kernel CR3 walk) | `0x299ad0` / `0xffffffff8ed59ad0` / `0xed59ad0` |
| victim onion cpu_va / bus off | `0x200600000` / `0x2027a00000` |
| process vmid | `2` |
| victim leaves (gva -> phys, 8KB) | `0xc80000000->0x33400000`, `+0x2000->0x33402000`, `+0x4000->0x33404000`, `+0x6000->0x33406000` |
| leaf raw / retargeted raw | `0x0004000033400177` -> `0x000400000ed58177` (8KB, bit 50 set = onion/coherent) |

### kwrite3 run log (authoritative, `/data/kex_gpuwrite.txt`)
```
ERROR: Failed to get trap hanlder code      <- printed during module load, BEFORE main()
**** NEO Mode ****
DATA_BASE=0xffffffff8eac0000 kdata=0xffffffff8eac0000 fw=0x13600007
target_kva=0xffffffff8ed59ad0 target_pa=0xed59ad0 anchor kva=0xffffffff804772b8 dmap=0xffffffff804772b8
anchor cross-check PASS
target zero+stable, self-check PASS
victim cpu_va=0x200600000 off=0x2027a00000
vmid=2
leaves phys0=0x33400000 phys1=0x33402000 phys2=0x33404000 phys3=0x33406000
T2: submit=0 got=0x0000000000000000 expect=0xdeadbeefcafebabe
T2 FAIL
T3: target_base=0xed58000 off=0x1ad0 new=0x000400000ed58177
T3 setlong readback=0x000400000ed58177
T3: submit=0 after(kernel_copyout)=0x0000000000000000 after(dmap)=0x0000000000000000 expect=0xdeadbeefcafebabe
PTE restored=0x0004000033400177
T3 FAIL
RESULT: KDATA_WRITE_FAIL
```

## The GNM-driver-init blocker (reverse-engineered, definitive)

The string `"ERROR: Failed to get trap hanlder code"` (Sony's typo) is printed by the
`libSceGnmDriverForNeoMode.sprx` module constructor **before `main()`**. It is emitted by
a trap-handler-setup routine (`.text` offset `0x83e0`; the print site is at `0x847f`) that
does a **table lookup** indexed by the GPU "mode":

```
mode = get_gpu_mode();            // call @0x8408 -> 0x82af38920
if (mode >= 4)  error("No trap hanlder for mode %d");
desc = trap_handler_table[mode];  // table @ module .data offset 0x14060
if (!desc->code || !desc->data)   // ->0x843b / 0x8447 are NULL
    error("Failed to get trap hanlder code");   // <- 0x847f, the observed print
```

`desc->code`/`desc->data` are the **CWSR trap-handler microcode + context** (the AMD
"compute wave save/restore" handler; resource names `SceGnmTrapCode` / `SceGnmTrapData` /
`SceGnmCwsr`). Those pointers are populated by `Gnm::Initialize()` (`.text` offset
`0x53e0`), which allocates a long list of GPU resources through an imported allocator
(`call 0x82af388f0`) at **fixed garlic VAs** — `SceGnmTrapCode`/`SceGnmTrapData` at
`0xf00000000`, CWSR at `0xc80008000` (22 MB `0x1600000`), `SceGnmDdid`, `SceGnmEopFifo`,
`SceGnmShadowRegInfo`, `SceGnmACQRB`, `SceGnmMisc`.

In the elfldr process `Gnm::Initialize()` fails at its first KMD-coupled steps and sets the
driver-wide error state to `0x8eee00ff`:

```
call <init-step>            // @0x38b5, result must be 1
if (result != 1) { print("Gnm Initialize() error:%d"); state = 0x8eee00ff; }  // @0x3936/0x3946
...
call get_cu_mask()          // @0x3b69 -> 0x82af35e90
if (ret != 1)   { print("sce::Gnm::Initialize Error: Get CU Mask Fails (%d)"); state = 0x8eee00ff; }  // @0x3b7c
call init_embedded_shader() // @0x3b1f
if (ret)        { print("Initialize Embedded Shader Fails"); state = 0x8eee00ff; }  // @0x3b31
```

`0x8eee00ff` is the driver's "not initialized" code. Once set, every GNM entry point fails:

| call (this run) | return |
|---|---|
| `sceGnmRegisterOwnerForSystem()` | `0x8eee00ff` |
| `sceGnmRegisterOwner(NULL,…)` | `0x8eee00ff` |
| `sceGnmCreateWorkloadStream(0,…)` | `0x3` |
| `sceGnmMapComputeQueue(0,0,…,0x400)` | `1` (vqid, but no-op) |
| `sceGnmSubmitCommandBuffers(1,…)` | `0` (**silent no-op** — no queue ring was ever set up) |
| `sceGnmSubmitDone()` | `0x80d110ff` (submit path aborts at `.text @0x858` / `0x809` "Internal submit error") |

`RegisterOwner*` is additionally hard-stubbed in this sprx build: its body is literally
`mov eax, 0x8eee00ff; ret` (`.text @0x4000`–`0x5000`), so owner registration cannot be
performed by the payload to complete the init.

## Why the reference implementations work but this doesn't

Every public GPU-DMA kernel-RW implementation runs in a context where **GNM was already
initialized by the app framework**, so no explicit init is needed:

- **flatz BD-JB (Java, 2025-01-05):** calls `sun.awt.GnmUtils.copyPlanesBackgroundToPrimary`.
  The BD-J JVM/AWT initialized GNM (owner + trap handler + queues) at startup; the method
  only *uses* the pre-initialized driver. This is Java-only — not callable from an elfldr
  payload, and its native form would still require the pre-initialized driver.
- **Znullptr Lua / flatz `gpu.lua` (game save-data):** `find_mod_by_name("libSceGnmDriverForNeoMode.sprx")`
  then `dlsym` `sceGnmSubmitCommandBuffers`/`sceGnmSubmitDone` and call them directly. This
  works only because the game process already loaded **and initialized** the module
  (psdevwiki "Vulnerabilities" §10.1: "With a game entrypoint, one can call
  sceGnmSubmitCommandBuffers and sceGnmSubmitDone").
- **cragson ps5-hen / ps5-linux-loader `gpu_dma.cpp`:** same — runs inside a HEN/game process.

The elfldr payload is a bare `elfldr`-spawned process: `dlopen` succeeds and the constructor
runs, but `Gnm::Initialize()` cannot complete because the process is not a registered GPU
client (no CU-mask grant, no KMD resource registration), so the driver is left broken.

## What a working GNM init would need (for the record)

To make `sceGnmSubmitCommandBuffers` actually queue work in a fresh process, the following
must succeed, in order, against the PS5 kernel GPU driver (KMD):

1. A KMD "register as GPU client" step (the first `call @0x38b5` whose result must be 1 —
   this is the step that fails first; it is what the app-launch framework does on process
   start and is not reproducible from a bare payload without reversing the KMD IPC/syscall).
2. `Get CU Mask` — a syscall/IPC returning the process's enabled compute-unit mask.
3. Embedded-shader init.
4. Resource allocation of `SceGnmTrapCode`/`SceGnmTrapData`/`SceGnmCwsr`/… at fixed garlic
   VAs (the CWSR microcode is ~22 MB and lives in VRAM at `0xc80008000`).
5. Queue mapping (`sceGnmMapComputeQueue`) + `sceGnmSubmitDone` fence.

Steps 1–3 are the blockers; they are KMD-gated and not exposed through any SDK stub the
payload can call (and `RegisterOwner*` is stubbed to `0x8eee00ff`).

## Files

- `probe78/kwrite3.c` / `kwrite3.elf` — victim-only GNM variant (built + deployed this run).
- `probe78/gnm_init.c` / `gnm_init.elf` — probes RegisterOwner/Workload/MapComputeQueue/Submit/SubmitDone.
- `probe78/gnmdump4.c` / `gnmdump4.elf` — reliable in-memory dump of `libSceGnmDriverForNeoMode.sprx`
  (CPU page-walk + `kernel_copyout`, reads execute-only `.text`); pulled to
  `scratch/ps5/gnm_neo4.bin`.
- `scratch/ps5/gnm_disasm.txt` — full disassembly of the captured `.text`.

## Conclusion

`sysram_write_pass = false`. The `/dev/gc` (vmid 6) DMA is VRAM-only (prior work), and the
onion/vmid-2 GNM path is blocked because **GNM cannot be initialized in the bare elfldr
payload process** — `Gnm::Initialize()` fails at KMD-gated steps (client registration,
Get-CU-Mask, CWSR trap-handler resource allocation at fixed garlic VAs), so
`sceGnmSubmitCommandBuffers` silently no-ops and `sceGnmSubmitDone` returns `0x80d110ff`.
The primitive is only usable inside a GNM-initialized process (BD-J JVM, game, or etaHEN),
which is exactly where the public flatz/znullptr implementations run.
