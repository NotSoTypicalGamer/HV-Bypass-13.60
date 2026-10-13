# Luac0re 13.60 drop-in notes

The userland Lua loader is firmware-independent (see LUACORE_1360_PORT.md). Two files are
patched / added here; everything else from the 2.4b release is used unchanged.

## Patched / new files in this directory

| File | Action | Why |
|---|---|---|
| `func.lua` | patched | `init_dlsym()` dlsym delta is now data-driven (`DLSYM_DELTAS`) with an explicit `13.60 = 0x450` entry + on-console self-check. Functional behaviour unchanged. |
| `offsets.lua` | new | Restores the <=2.2d `fw_offsets` KERNEL table and adds 13.60 (ALLPROC/SECURITY_FLAGS/ROOTVNODE cross-validated; PMAP_STORE/GVMSPACE = nil TODO). Only used by the p2jb/poops jailbreak path, not the loader. |

## Unchanged (drop 2.4b originals in as-is)

`global.lua` (EBOOT gadgets + stable libc/fios offsets), `rop.lua`, `memory.lua`,
`syscall.lua`, `misc.lua`, `remotelualoader.lua`, `init.lua`, `main.lua`, `jit/*`,
`elf_jb/*`.

## Remaining TODO (require a 13.60 console / dump)

1. `sceKernelDlsym` delta `-0x450` — expected unchanged; verify via §4.1 of the port doc.
2. `KERNEL_PMAP_STORE` / `GVMSPACE` (kernel jailbreak, poops path) — not derivable offline.
3. Whether the mast1c0re ps2emu save-data entry still fires on 13.60 (separate from offsets).
