# Luac0re 13.60 Port — Firmware-Specific Constants Analysis

Target: `Luac0re 2.4b` (Gezine) — mast1c0re-based PS2-emulator save-data Lua loader
(SW Racer Revenge / ps2emu eboot, Lua 5.3 embedded), to run on **PS5 13.60**.

Analysis date: 2026-10-06. Sources cross-checked: local `kernel/gpudma_src/` (2.4b Lua),
`Gezine/Luac0re` git history (init commit `8af25f4` → `2.4b`), `Gezine/Luac0re` tag `2.2d`
(`lua/offsets.lua`), `ps5-payload-dev/sdk` `crt/kernel.c` (13.60 case), `X1NONs/X1NON-PSJB`
(`offsets/13.XX/13.60`), and the local Relapse-JB `kernel/offsets_13.60.js`.

---

## 0. Headline finding (corrects the task premise)

**The Luac0re *userland Lua loader* is already firmware-independent on PS5. It does not
need new ROP gadget addresses or syscall numbers for 13.60.** The memory primitives'
gadgets live in the **EBOOT** (the SW Racer Revenge ps2emu binary — a game disc, never
rebuilt by Sony), not in libkernel. What is genuinely firmware-specific in Luac0re is:

1. the **kernel jailbreak offsets** (ALLPROC / SECURITY_FLAGS / ROOTVNODE / pmap / gvmspace)
   — these are the "PS5 firmware specific offsets" that stop at 13.20 and were
   **deprecated out of Lua into the kexp C shellcode in v2.3**; and
2. one userland constant, the **sceKernelDlsym delta** (`-0x450`), which is hardcoded
   and "tested until 13.20" and therefore needs a 13.60 check.

Every other "firmware-specific-looking" constant in the Lua is either EBOOT-relative
(constant) or a `libSceLibcInternal.sprx` / `libSceFios2.sprx` offset that has **never
changed across the whole Luac0re git history** and is stable 9.xx→13.20.

---

## 1. Inventory of every firmware-sensitive constant

### 1.1 Userland ROP gadgets — EBOOT (FIRMWARE-INDEPENDENT, no change)

All in `lua/global.lua`. `EBOOT_BASE` is leaked by the mast1c0re PS2 shellcode from the
ps2emu process; the ps2emu binary is the game's own and never changes with firmware.

| Name | Definition | Bytes | Role |
|---|---|---|---|
| `MOV_RAX_DEREF_RAX_RET` | `EBOOT_BASE + 0x23ac20` | `48 8B 00 C3` (mov rax,[rax];ret) | **read64** |
| `MOV_DEREF_RDI_RAX_RET` | `EBOOT_BASE + 0x75b6c` | `48 89 07 C3` (mov [rdi],rax;ret) | **write64** |
| `RET` | `EBOOT_BASE + 0x72` | `C3` | |
| `POP_RAX_RET` | `EBOOT_BASE + 0xb50a0` | | |
| `POP_RBX_RET` | `EBOOT_BASE + 0xc234` | | |
| `POP_RCX_RET` | `EBOOT_BASE + 0x96059` | | |
| `POP_RDI_RET` | `EBOOT_BASE + 0x1429` | | |
| `POP_RSI_RET` | `EBOOT_BASE + 0xbf2b0` | | |
| `POP_RDX_RET` | `EBOOT_BASE + 0xbf5b7` | | |
| `POP_RBP_RET` | `EBOOT_BASE + 0x8f` | | |
| `POP_RSP_RET` | `EBOOT_BASE + 0x61a70` | | |
| `POP_R13/R14/R15_RET` | `EBOOT_BASE + 0xbf35d/0x11d0e2/0x1428` | | |
| `XCHG_RAX_RBP` | `EBOOT_BASE + 0x7ea4` | | RBP save/restore in `call_rop` |
| `SUB_RAX_RDX_RET` | `EBOOT_BASE + 0x41a2` | | |
| `LUA_PIVOT1/2` | `EBOOT_BASE + 0x129039/0x94d26` | | stack pivot |

**13.60 status: no change required.** The byte patterns `48 8B 00 C3` / `48 89 07 C3`
mentioned in the task are *these* EBOOT gadgets — they are findable in the ps2emu eboot,
**not** in a 13.60 libkernel dump.

### 1.2 Two non-EBOOT gadgets used inside `call_rop` (libc / fios2 — STABLE)

| Name | Definition | Module | Bytes | Role |
|---|---|---|---|---|
| `POP_R8_RET` | `LIBC_BASE + 0x1345a` | libSceLibcInternal.sprx | `41 58 31 C0 66 89 0B 5B 41 5E 5D C3` | set r8 |
| `MOV_R9_RET` | `FIOS_BASE + 0x4009c` | libSceFios2.sprx | `4C 8B 4D B0 48 8B 5D C0 B8 FC FF FF FF BE FD FF FF FF BF 01 00 00 00 49 01 C1 FF E1` | set r9 |

These are the only two `call_rop` gadgets that come from a system `.sprx` rather than the
eboot. Both offsets are **identical in every Luac0re commit from the initial release through
2.4b** (verified with `git log -p -- lua/global.lua`), i.e. stable across PS5 9.xx→13.20.

**13.60 status: expected unchanged. Re-derive only if a 13.60 libc/fios dump shows
otherwise** (see §4 for the exact scan).

### 1.3 `LIBC_OFFSETS` — libSceLibcInternal.sprx (STABLE)

`lua/global.lua` `LIBC_OFFSETS = { ... }`, all `LIBC_BASE + ...`:

| Key | Offset | Used for |
|---|---|---|
| `malloc_heap_override_enabled` | `0xCEED0` | `patch_malloc()` |
| `malloc_heap_size_limit` | `0xCEEC8` | `patch_malloc()` |
| `malloc_heap_page_align` | `0xCEEAA` | `patch_malloc()` |
| `malloc_heap_premapped_base` | `0xCEED8` | `patch_malloc()` |
| `sceKernelGetModuleInfoFromAddr` | `0xCBDA8` | module info / dlsym anchor |
| `gettimeofday` | `0xCBC50` | syscall trampoline (`+7`) |
| `libc_strerror` | `0xADE0` | error strings |
| `libc_error` | `0xCBC58` | errno |

Unchanged across all Luac0re releases. These bootstrap everything (module-info, dlsym,
syscalls); they demonstrably work on 13.20 and are the same offsets mast1c0re has used
across many PS5 firmware families. **13.60 status: expected unchanged.**

### 1.4 Syscall numbers — `SYSCALL_TABLE` (FreeBSD numbers, STABLE)

`lua/global.lua` `SYSCALL_TABLE`: FreeBSD-derived numbers (`read=0x3, write=0x4,
open=0x5, ... mprotect=0x4a, socket=0x61, ... sysctl=0xca, ... dlsym=0x24f,
jitshm_create=0x215, ...`). On PS5 these are dispatched through the libc `gettimeofday+7`
`syscall` trampoline with the number in RAX (`syscall.resolve` PS5 branch) — no per-firmware
syscall-wrapper addresses are used.

Cross-check: `X1NONs/X1NON-PSJB offsets/13.XX/13.60` and the local `offsets_13.60.js`
carry a `syscall_map` (libkernel C-stub offset per syscall number) that is **byte-identical
across 13.00→13.60**, and its keys match Luac0re's `SYSCALL_TABLE` numbering (e.g. `0x3→…`,
`0x24F→0x1B5A0`). This confirms the FreeBSD syscall numbering Luac0re relies on is unchanged
on 13.60. **13.60 status: no change required.**

### 1.5 sceKernelDlsym delta — the ONE loader constant to verify (TODO)

`lua/func.lua` `init_dlsym()`, PS5 branch:

```lua
-- PS5: For firmware > 10.01, calculate offset dynamically
-- Was tested until 13.20
if major > 10 or major == 10 then
    SCE_KERNEL_DLSYM = read64(LIBC_OFFSETS.sceKernelGetModuleInfoFromAddr) - 0x450
else
    SCE_KERNEL_DLSYM = read64(LIBC_OFFSETS.sceKernelGetModuleInfoFromAddr) - 0x480
end
```

`sceKernelDlsym` and `sceKernelGetModuleInfoFromAddr` are both `libkernel.sprx` exports;
`-0x450` is the fixed distance between them on every PS5 ≥ 10.01 tested through 13.20.
This is the only userland constant whose 13.60 value I could not confirm from a public
export list. **13.60 status: TODO — verify the delta; expected unchanged `-0x450`.**

### 1.6 Kernel jailbreak offsets — the actual "13.60 not implemented" part

Luac0re ≤ 2.2d kept these in `lua/offsets.lua` as a per-firmware table `fw_offsets`
(4.00 … 13.20; 13.20 aliased to 13.00's values). **v2.3 deprecated them out of Lua** —
p2jb/poops now carry their kernel offsets inside the kexp C shellcode
(`jit_shellcode/`, `lua/elf_jb/kexp_2026_05_25.bin`), and `payloads/p2jb.lua` gates the
jailbreak at `FW_VERSION > 12.70 → unsupported`.

The 2.2d schema was: `ALLPROC, SECURITY_FLAGS, ROOTVNODE, KERNEL_PMAP_STORE, GVMSPACE`.
13.60 values, resolved and cross-validated this session:

| Field | 13.60 value (DATA_BASE-relative) | absolute (DATA_BASE=0xCC0000) | source |
|---|---|---|---|
| `ALLPROC` | `+0x28C9E80` | `0x03589E80` | ps5-payload-dev `case 0x13600000`; = `offsets_13.60.js` |
| `SECURITY_FLAGS` | `+0x0D9C064` | `0x01A5C064` | ps5-payload-dev; = `offsets_13.60.js` |
| `ROOTVNODE` | `+0x314B510` | `0x03E0B510` | ps5-payload-dev; = `offsets_13.60.js` |
| `KERNEL_PMAP_STORE` | **TODO** | — | poops-specific; not in offsets_13.60.js |
| `GVMSPACE` | **TODO** | — | poops-specific; not in offsets_13.60.js |

Notes: 13.60 kernel `DATA_BASE` moved `0xCB0000 (13.40) → 0xCC0000 (13.60)`; `ALLPROC` is
unchanged from 13.40; `SECURITY_FLAGS` and `ROOTVNODE` shifted.

---

## 2. Does `offsets_13.60.js` (Relapse JB) supply Luac0re's 13.60 needs?

| Luac0re need | Supplied by `offsets_13.60.js`? | Detail |
|---|---|---|
| read64/write64 gadget addresses | **No — not needed.** | Gadgets are EBOOT-relative (§1.1), not libkernel. |
| libc gadget `POP_R8_RET` / fios `MOV_R9_RET` | No. | It lists `libc` offsets for a *different* module/base (`memset=0x14700`, `vsnprintf=0x5F6A0` …) that do not include Luac0re's `0x1345a`/`0x4009c`/`0xCBDA8`/`0xCBC50` family. |
| Luac0re `LIBC_OFFSETS` | No (different base). | Not needed anyway — stable (§1.3). |
| Syscall numbers | **Indirectly yes.** | Its `syscall_map` keys confirm FreeBSD numbering unchanged on 13.60 (§1.4). |
| Kernel jailbreak offsets | **Yes, partial.** | `ALLPROC/SECURITY_FLAGS/ROOTVNODE` match the cross-validated 13.60 values (§1.6). `KERNEL_PMAP_STORE`/`GVMSPACE` absent. |

**Verdict:** `offsets_13.60.js` does **not** supply userland loader offsets (and none are
needed — they are EBOOT-relative or stable), but it **does** independently confirm the 13.60
kernel data-base offsets and the stable syscall numbering.

---

## 3. What was actually changed (files under `kernel/gpudma_src/luac0re1360/`)

- **`offsets.lua`** (new): restores the ≤2.2d `fw_offsets` firmware table and adds the
  `13.60` entry with the cross-validated values (§1.6); `KERNEL_PMAP_STORE`/`GVMSPACE`
  left `nil` (TODO) for the poops/GPU path.
- **`func.lua`** (patched): converts the hardcoded dlsym delta to a data-driven
  `DLSYM_DELTAS` table with an explicit `13.60 = 0x450` entry and an on-console
  self-check, replacing the `major>=10` branch. `-0x450` is the best-known value (TODO
  verify §1.5).
- **`p2jb.lua`** (note, not reproduced): the `FW_VERSION > 12.70` gate is the *kernel
  jailbreak* gate, not the loader gate; raising it to 13.60 is only meaningful together
  with a kexp that has 13.60 kernel offsets (out of scope for the Lua loader). Documented,
  not blindly changed.

Unchanged (firmware-independent, no edits needed): `global.lua` (EBOOT gadgets + stable
libc/fios offsets), `rop.lua`, `memory.lua`, `syscall.lua`, `jit/*`.

---

## 4. Exact dump / scan procedure for the remaining TODO items

### 4.1 Verify the 13.60 sceKernelDlsym delta (the only loader TODO)

Dump 13.60 `libkernel.sprx` (from a 13.60 console or PUP, or read it via Luac0re once
booting), then:

```sh
# readelf (from binutils) or pyelftools on libkernel.sprx
readelf -sW libkernel.sprx | grep -E 'sceKernelDlsym$|sceKernelGetModuleInfoFromAddr$'
```

`delta = rva(sceKernelGetModuleInfoFromAddr) - rva(sceKernelDlsym)`.
Expect `0x450`. If it differs, set the `13.60` entry in `DLSYM_DELTAS` to the measured
value. (On-console self-check is also embedded in the patched `func.lua`.)

### 4.2 Re-derive `POP_R8_RET` / `MOV_R9_RET` (only if a 13.60 dump shows drift)

Scan the 13.60 `libSceLibcInternal.sprx` and `libSceFios2.sprx` for the exact byte patterns:

```sh
# POP_R8_RET (libc): pop r8; xor eax,eax; mov [rbx],cx; pop rbx; pop r14; pop rbp; ret
grep -obaP '\x41\x58\x31\xc0\x66\x89\x0b\x5b\x41\x5e\x5d\xc3' libSceLibcInternal.sprx

# MOV_R9_RET (fios2): mov r9,[rbp-0x50]; mov rbx,[rbp-0x40]; mov eax,-4; mov esi,-3;
#                      mov edi,1; add rcx,r8; jmp rcx
grep -obaP '\x4c\x8b\x4d\xb0\x48\x8b\x5d\xc0\xb8\xfc\xff\xff\xff\xbe\xfd\xff\xff\xff\xbf\x01\x00\x00\x00\x49\x01\xc1\xff\xe1' libSceFios2.sprx
```

New offset = matched file offset minus the module's image base for `.text` (subtract the
ELF segment p_vaddr, i.e. use RVA = file_offset - p_offset_of_text).

### 4.3 `KERNEL_PMAP_STORE` / `GVMSPACE` (kernel jailbreak, poops path)

Not derivable from a libkernel/libc dump — these are kernel data-segment symbols. Take them
from a 13.60 kernel offset dump (e.g. `ps5-payload-dev/sdk` or a poops/kexp 13.60 offset
profile) once one exists; they are not required for the userland Lua loader itself.

---

## 5. Bottom line

- **Userland Lua loader → no 13.60 offset changes required.** EBOOT gadgets are constant,
  libc/fios offsets and syscall numbers are stable (9.xx→13.20), and there is no
  firmware-version gate in the loader path.
- **One verification item:** the `sceKernelDlsym` delta `-0x450` (§1.5) — expected
  unchanged on 13.60, self-check + dump procedure provided.
- **The real "13.60 not implemented" gap is the kernel jailbreak (p2jb/poops/kexp), not
  the loader.** Its 13.60 `ALLPROC/SECURITY_FLAGS/ROOTVNODE` are resolved and cross-validated
  here (§1.6); pmap/gvmspace and the kexp itself remain TODO.
- **Caveat (out of scope):** whether the mast1c0re ps2emu save-data entry still fires on
  13.60 is a separate question from the Lua offsets and was not evaluated here.
