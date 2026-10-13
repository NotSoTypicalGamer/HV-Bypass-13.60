# WAK1360-Relapse (arg0WAK) — 13.60 Relapse port

Public exploit host (WebKit + Relapse aio_multi_wait UAF) covering fw 7.00-13.60. Gives
kernel R/W + a ROP kcall (`worker_rop.fcall(rip, rdi, rsi, rdx, rcx, r8, r9)`).

Key 13.60 offsets (offsets/13.60.js):
- `OFFSET_KERNEL_DATA = 0x00CC0000`  -> .data base = text base + 0xCC0000 (NOT 0x82000000;
  earlier offset-hunt conclusion was wrong).
- `OFFSET_KERNEL_ALLPROC = 0x03589E80`, `OFFSET_KERNEL_SECURITY_FLAGS = 0x01A5C064`,
  `QA_FLAGS = +0x24`, `UTOKEN_FLAGS = +0x8C`, `ROOTVNODE = 0x03E0B510`.
- aio: `waiterSize=0x38`, `requestSize=0x28`, group `{num:0x00, state:0x08, waiters:0x50}`,
  idTable `{pages:0x220, slotStride:0x30, entryType:0x160}`.
- KASLR defeat: `rtmsg2`, `retStatic=0x00AE2DA0`.
- proc `{pid:0xbc, ucred:0x40, fd:0x48, aioInfo:0xc48}`, ucred `{uid:0x04, ...}`.

This is the **Relapse half of the S3 AP-launch chain** — kernel R/W + kcall already solved
with exact offsets. Still NOT in here (still to find): `acpi_sleep_machdep`, `ACPIGBL_FACS`,
`IDT`, `COMMON_TSS`, and the inner-HV `pcpus[]`.
