# FLATZ GPU-DMA kernel .data write — 13.60 Lua port for Luac0re/mast1c0re (PS2EMU)

**Artifacts:** `gpu1360.lua` (the adapted script) + this note.
**Status:** OFFLINE code + research only. NOT deployed, NOT run on-console. Own console, nothing published.
**Provenance:** flatz `gpu.lua` (itsPLK/ps5-lua-autoloader / shahrilnet/remote_lua_loader mirror, "credit to flatz and shadPS4"), cragson/ps5-hen `gpu_dma.cpp/.h`, flatz `GpuMemoryUtil.java` (gist d6fbf7ef), and `probe79/flatcopy.elf` (the buildable 13.60 flatz port in `Caliper-C0re`). All five fetched/read; sources stashed in `kernel/gpudma_src/`.

---

## 1. What this primitive is (one paragraph)

flatz's GPU-DMA copy bypasses the HV/firmware write-protect on kernel `.data` by driving
the copy through the **GPU's own GPUVM page tables** (kernel-managed, guest-controllable)
instead of the CPU NPT. The recipe is: allocate **MAIN (onion, `mem_type=1`)** direct
memory, walk the **process vmid (2)** GPU page tree to find the victim leaf, **retarget the
leaf PTE's physical field** to a kernel `.data` physical, then submit a
`PACKET3_DMA_DATA` (opcode `0x50`) via **GNM** (`sceGnmSubmitCommandBuffers` +
`sceGnmSubmitDone`). The GPU writes the sentinel through the retargeted leaf, landing in
system RAM, bypassing the CPU-side write guard. This is the etaHEN/flatz path — **not** the
`/dev/gc` ioctl path, which on 13.60 is VRAM-only (vmid 6) and cannot reach system RAM
(`GPU_DMA_KDATA_WRITE.md`).

---

## 2. The two Lua contexts are NOT the same — this is the whole port

`flatz gpu.lua` is written for **remote_lua_loader** (itsPLK/ps5-lua-autoloader), which
ships a rich kernel-access layer. Luac0re is a **different loader** running the Lua 5.3
interpreter *embedded in the PS2-emulator's `eboot.bin`*. The port is therefore not a
recompile — it is a re-binding of every flatz helper onto Luac0re's actual API, plus the
13.60 layout changes.

### 2.1 What Luac0re DOES provide (verified from source)

| Luac0re API | File | What it is |
|---|---|---|
| `read64/read32/read16/read8(addr)` | `lua/memory.lua` | **userland** read via ROP gadget `MOV_RAX_DEREF_RAX_RET` |
| `write64/write32/write16/write8(addr,v)` | `lua/memory.lua` | **userland** write via `MOV_DEREF_RDI_RAX_RET` |
| `read_buffer/write_buffer(addr,len)` | `lua/memory.lua` | userland memcpy-based read/write |
| `malloc(size)` / `free` | `lua/memory.lua`, `lua/func.lua` | `malloc == calloc(size,1)` |
| `func_wrap(addr)` | `lua/func.lua` | wrap a native address as a Lua-callable fn (≤6 args, via `call_rop`) |
| `call_rop(addr, rax, a1..a6)` | `lua/rop.lua` | raw ROP call; **string args auto-passed as `addrof(s)+0x20`** |
| `dlsym(handle, sym)` | `lua/func.lua` | via `sceKernelDlsym` (`init_dlsym()`); returns the address |
| `sceKernelLoadStartModule` | `lua/func.lua` (`dlsym_test`) | module handle idiom (see §2.2) |
| `syscall.*` wrappers | `lua/syscall.lua`, `lua/global.lua` | `syscall.mprotect`, `syscall.sysctl`, etc. |
| `memcpy`/`memset` | `lua/func.lua` | `func_wrap`'d libc |
| constants | `lua/global.lua` | `PROT_READ/WRITE`, `GPU_READ=0x10`, `GPU_WRITE=0x20`, `MAP_NO_COALESCE=0x400000`, `LIBKERNEL_HANDLE=0x2001` |
| `to_hex/hex_to_binary/bin_to_hex/find_pattern` | `lua/misc.lua` | 64-bit-safe helpers |
| `send_notification/show_dialog/microsleep/file_*` | `lua/misc.lua` | logging / UI |
| JIT native exec (v2.0+) | `lua/jit/*` | arbitrary native code + socket-restriction bypass |
| **Lua 5.3 integers** | interpreter | native `& | ~ << >> //` on 64-bit ints — **no `bit64`/`bit32` lib needed** |

### 2.2 What Luac0re does NOT provide, and the substitution

| flatz gpu.lua uses | Luac0re substitute | Notes |
|---|---|---|
| `find_mod_by_name(name)` | `sceKernelLoadStartModule(name,0,0,0,0,0)` | returns the module handle (existing handle if already loaded) |
| `fcall(fn)` | `func_wrap(fn)` | |
| `bit64.*` / `bit32.*` | Lua 5.3 operators `& | ~ << >> //` | Luac0re runs Lua **5.3**, so integers are native 64-bit |
| `memory.alloc(n)` | `malloc(n)` | |
| `memory.read_qword/write_qword/...` | `read64/write64/...` | **userland only** |
| `syscall.mprotect` | `syscall.mprotect` | present, but **dropped** on 13.60 (see §4) |
| `kernel.read_qword / write_qword` | **NOT PROVIDED — the wiring seam** | see §5 |
| `phys_to_dmap(pa)` | `kernel.dmap + pa` | DMAP base from the JB chain |
| `virt_to_phys(va, cr3)` / `get_proc_cr3` | reimplemented (`cpu_va_to_pa`, `derive_kernel_cr3`) | 4-level x86 walk on `kernel.read_phys` |
| `kernel.addr.curproc / data_base / kernel_cr3` | `kernel.kdata_base / kernel.kernel_cr3` (JB chain) | |
| `PROT_READ|PROT_WRITE|GPU_READ|GPU_WRITE` | `DMEM_PROT_RW = 0x33` | constants already in `global.lua` |

**The one hard dependency:** Luac0re's `read64/write64` are **userland** (ROP-gadget
loads/stores) — they **cannot** read kernel VAs. The flatz primitive walks the GPU page
tree at kernel DMAP VAs (`0xffffff80…`) and retargets a leaf PTE with a **kernel write**.
That kernel R/W must come from the **JB chain** (Relapse/etaHEN on 13.60) — see §5.

---

## 3. flatz gpu.lua helper-by-helper adaptation (exact diff)

| flatz gpu.lua | gpu1360.lua | Change |
|---|---|---|
| `gpu.setup()` allocs 3 × 2 MiB (victim+transfer+cmd) | **1 × 2 MiB** victim, leaves 0–3 used as retarget/sentinel/packet/T2 | 13.60 onion leaves are lazily populated; 4 leaves of one buffer are enough (mirrors `probe79`) |
| `get_ptb_entry_of_relative_va(victim_va)` + `rel_va = va - start_va` | `gpu_walk_leaf(vmid, LEAF0_GVA)` with **fixed garlic GPU VA `0xc80000000`** | 13.60 `gvmspace.start_va = 0x0`, so `rel_va = cpu_va` is **wrong**; the onion buffer is at the fixed garlic VA base, not the CPU VA |
| `get_curproc_vmid()` via `kernel_offset.VMSPACE_VM_VMID` | **`PROC_VMID_KNOWN = 2`** | vmid=2 is the measured process vmid on 13.60 (`VMSPACE_VM_VMID = 0x1FC`, not 0x1EC/0x1E4) |
| `victim_real_pa = virt_to_phys(victim_va, curproc_cr3)` | **recovered from the leaf PTE** (`leaf & 0x0000FFFFFFFFE000`) | `cpu_va_to_pa(victim_va)` and `off` are BOTH fake for the direct-memory VA on 13.60 |
| `page_size ~= dmem_size → error()` (requires a single 2 MB leaf) | **accepts 8 KB leaves**, uses `phys_mask_for(page_size)` | 13.60 tree is 5-level with **8 KB leaves** (TF bit56); no 2 MB leaf |
| `mprotect(RO)` → write PTE → `mprotect(RW)` dance | **no mprotect** — direct `kernel.kwrite64(dmap+pte, new)` | the GPU VA is re-translated fresh on submit; the mprotect dance is unnecessary (probe76 verified) |
| `cleared_ptbe = initial & ~victim_real_pa` | `new = (raw & ~phys_mask) \| (target_base & phys_mask)` | 13.60 masks: 8 KB `0x0000FFFFFFFFE000`, 2 MB `0x0000FFFFFFE00000` |
| `pkt[1] = 0xA3006000` (per FLATZ_GNM_COPY.md) | **`0x8C00C000`** | **doc error** — flatz gpu.lua, cragson gpu_dma.cpp, and the on-console-verified probe76 all emit `(1<<31)|(2<<25)|(1<<27)|(2<<13)|(1<<15)` = `0x8C00C000` |
| `sceGnmSubmitCommandBuffers(dcb_count, dcb_gpu_addr, dcb_sizes, 0, 0)` | identical | `dcb_gpu_addr`/`dcb_sizes` are heap buffers holding `{cmd_gva}`/`{size}` |

---

## 4. 13.60 offsets (all measured, see the cited local docs)

| Symbol | 13.60 value | Source |
|---|---|---|
| `VMSPACE_VM_VMID` | `0x1FC` | live vmspace dump (u32 = 2) |
| `DATA_BASE_GVMSPACE` | `0x2EEA570` | IDT anchor (`idt − 0x9D90`), verified across 11.60/12.70/13.60 |
| `SIZEOF_GVMSPACE` / `page_dir_va` / `start_va` / `size` | `0x100` / `0x38` / `0x08` / `0x10` | gvmspace entry layout |
| process vmid | `2` | measured; gvmspace[2].page_dir_va = `0xFFFFFF80A0C98000` |
| onion GPU VA base | `0xc80000000` | PDPT index 50; first alloc → `0xc80000000` |
| leaf physical field | bits **13–47** (8 KB) / 21–47 (2 MB) | leaf PTE, not `off`/`cpu_va_to_pa` |
| `OFFSET_KERNEL_PMAP_STORE` | `0x28c84a8` | kernel CR3 walk anchor (invariant `pml4_kva − DMAP == CR3`) |
| `KDATA_TARGET_OFF` | `0x299AD0` | verified-zeroed 8-byte `.data` field |

**Walk (13.60, 5 levels for 8 KB leaves):**
`PDB2/PML4 (page_dir_va, kernel VA) → PDB1/PDPT → PDB0/PD (frag=4) → PTB 64 KB → 8 KB
leaf sub-table (TF bit56)`; `IS_PTE` bit54 = 2 MB leaf (fallback for other FW). Leaf
physical recovered from the **leaf PTE** with `& 0x0000FFFFFFFFE000`. Retarget masks:
`0x0000FFFFFFFFE000` (8 KB) / `0x0000FFFFFFE00000` (2 MB) — **never** the 80-bit literal
`0x0000FFFFFFFFFFE00000` (truncates to 64 bits, clears `IS_PTE` bit54 → panic).

---

## 5. The kernel R/W wiring seam (the one thing Luac0re can't give you)

`gpu1360.lua` defines a `kernel` table (`kernel.kread64/kwrite64/read_phys/dmap/
kdata_base/kernel_cr3`) that is the **only** externally-supplied piece. Three realistic
wirings on a jailbroken 13.60:

1. **Native stub via `func_wrap` (cleanest).** Compile a tiny stub (ps5-payload-sdk,
   `kernel_copyout`/`kernel_copyin`/`kernel_setlong` already exported) or reuse the
   Relapse/etaHEN kread/kwrite, expose it as a function, `func_wrap` it, and back
   `kernel.kread64/kwrite64` with it. `kernel.dmap` = `KERNEL_ADDRESS_DMAP_BASE`;
   `kernel.kdata_base` = `payload_get_args()->kdata_base_addr` (runtime, KASLR-slid).
2. **JB-daemon socket.** Relapse/etaHEN expose kread/kwrite over a socket — wrap the
   send/recv in `kernel.kread64/kwrite64`.
3. **elfldr route (already written).** `probe79/flatcopy.elf` is the *same* primitive as
   a C payload — if the goal is a kernel-.data write (not specifically "in Lua"), run it
   instead of porting.

`kernel.kdata_base` and `kernel.dmap` are **per-boot** (KASLR) — never SDK-hardcode them.
`derive_kernel_cr3()` self-checks the `kernel_pmap_store` invariant before any write.

---

## 6. Known blockers / assumptions (flag before betting the write on it)

1. **GNM must already be loaded + initialized in the PS2EMU process.** The flatz/psdevwiki
   precondition is "a game entrypoint". `sceGnmSubmitCommandBuffers`/`sceGnmSubmitDone`
   are resolved from `libSceGnmDriverForNeoMode.sprx`; if the PS2-emulator process uses the
   native PS5 AGC graphics stack (SceAgcGnmp) rather than the PS4-compat GNM driver, the
   GNM submit path may **not** be the right submission channel there — the `sceKernelLoadStartModule`
   call in §(a) is the probe for that (it returns `>=0x80000000` on failure). On the
   references that work, GNM init has already succeeded at module load.
2. **Kernel R/W is external.** Luac0re alone is userland. Without a wired `kernel` table the
   script `error()`s at the seam, never panics.
3. **Lazy onion-leaf population.** 13.60 populates 8 KB GPU leaves on GPU demand (~280 KB of
   the 2 MiB victim was seen). The script uses only the **first four 8 KB leaves** (which are
   present) and errors cleanly if any is missing; full-range population is
   `GPUVM_POPULATION.md` §3 if a larger copy is ever needed.
4. **The retarget PTE write is a kernel write** (`dmap + leaf_pte_pa`); a wrong address
   there **panics** (no EFAULT). The script writes only the validated `pte0` and restores
   `raw0` on every path.

---

## 7. Verification status

- **NOT run.** Offline code + research only; console in use elsewhere. Everything above is
  either fetched source, a local measured offset, or a 1:1 port of `probe79/flatcopy.elf`
  (which itself was **build-verified** but not deployed).
- The only correction vs. the existing local notes is the **DMA_DATA header constant**
  `0xA3006000 → 0x8C00C000` (FLATZ_GNM_COPY.md §(c) is wrong; the code and the
  on-console-verified probe76 agree on `0x8C00C000`).
- Unverified-by-me, flagged above: `KERNEL_OFFSET_PROC_P_VMSPACE` (header-derived `0x1F0` —
  not used by the script, which hardcodes vmid=2; listed for the optional self-check only).
