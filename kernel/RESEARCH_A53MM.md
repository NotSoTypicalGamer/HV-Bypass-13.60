# a53mm — PS5 GPU/PSP MMU module (future KEX target)

Source: static string analysis of `kernel_data.bin` (48 MB), file offsets → VA = +0xffffffffc9570000
(this boot). Module source paths all under `W:\Build\J01736804\sys\mp4\x86\kernel\modules\a53mm\`.

## What it is
a53mm = the AMD **Oberon** (PS5 APU) secure co-processor (PSP) + GPU MMU manager. It owns:
- **VMID** allocation for game/vdec/vsh (per-process GPU+CPU virtual machines).
- **CPU + GPU page tables** (`a53mm_page_table.c`: pml4e/pdpe/pde/pte walks, `A53MM_CPU_ATTR_*`,
  `A53MM_GPU_PTE_ATTR_BASE_ADDR_MASK`, 2MB page checks `a53mm_pg_is_2mpage`).
- **Privilege mode** (`a53mm_privilege_mode.c`): app↔system privilege transitions, `a53mm_lock_region_with_pid`,
  `a53mm_acquire_privileged_lock`, `MODIFY_PRIV` state.
- **Page migration** (`a53mm_page_migration.c`): move pages between VMIDs.
- **PSP mailbox** (`psp_mbox_send_sysmail`, `psp_mbox_encode_kernel_text`, `psp_mbox_map_tmr`):
  secure-world IPC; `encode_kernel_text` is the **XOM/encryption path**.
- **Input rings** (`a53mm_input_ring.c`): command rings (admin + per-app), `mmap_from_io_ring`.

## Reachability
- Char device: **`a53mmsys`** ("failed to create a53mmsys dev" @ a53mm.c:306) → ioctl surface.
- PSP private-data export: `sceSblPspPrivateDataExport` / `SecReg(export PSP Private Data)`.
- Sysctl-ish tunables: `a53mmthreshold`, `a53mminitcxt`, `a53mmresettq`, `a53mmmigration`,
  `a53mmmp4resume`, `a53mmfuture` (future/callback state machine `A53MM_CBFUTURE_STATE_*`).

## Security-relevant seams (assertion strings = invariants worth attacking)
- `PSP private region violation`
- `(pml4e & A53MM_CPU_ATTR_PS) == 0`, `(pdpe & A53MM_CPU_ATTR_PS) == 0`
- `(pte_all->cpu_pte[N] & A53MM_CPU_ATTR_FRAME) == 0` (page-table frame checks)
- `is_mapper_pt_pa(sc, ...)` — mapper page-table PA validation
- `a53mm_acquire_privileged_lock` / `curproc->p_pid == a53mm_context.current_owner` (owner checks)
- `(counter_offset + sizeof(SceAmprCounter)) <= a53mm_context.mem_mm_private.size` (bounds check)

## Why it matters for KEX
a53mm builds the **GPU's** page tables and switches privilege state. A bug in a53mm's
map/unmap/migrate path (or a craftable GPU command via the input rings) that lets a game-VMID
page-table entry alias physical memory outside its allowance = GPU-side arbitrary physical
read/write → escalate to kernel. This is Sony-original code (invisible to FreeBSD-diff hunts),
and it is the single largest Sony kernel module (1241 string hits).

## Next steps (non-destructive, offline)
1. Map the `/dev/a53mmsys` ioctl/cmd numbers (find the ioctl dispatch table in the data segment
   near the `a53mmsys` cdevsw entry).
2. Cross-reference the `a53mm_command.c` opcode set (the `[A53MM] opCode : %#x` dump) to the
   input-ring command format.
3. Look for a map/unmap/migrate path that trusts a caller-supplied PA without `is_mapper_pt_pa`
   validation.
