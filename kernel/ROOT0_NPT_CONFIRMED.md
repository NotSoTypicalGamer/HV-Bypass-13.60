# ROOT-0 NPT — CONFIRMED on 13.60 (2026-10-06)

## The breakthrough

The Sonic-Iso "root-0 NPT maps the hypervisor's own physical memory" technique is
**CONFIRMED live on 13.60** — it is DETERMINISTIC (not the "lucky boot" coin-flip the
earlier work wrongly framed it as). It reaches 14.00 and was patched in 14.10, so 13.60
is squarely inside its working window.

## Live result (probe93/root0.elf)

`kernel_copyout(dmap + host_PA)` over the HV's host-PA range:

```
READ 0x0          ret=0  val=0x0000000000000000   (guest DRAM, zeros)
READ 0x60000000   ret=-1                            (carve-out: not-present)
READ 0x100000000  ret=0  val=0xeaa70e27e97f8dd2   (guest DRAM @4GB)
READ 0x800000000  ret=0  val=0xffffffffffffffff   (HV memory! readable)
READ 0x810000000  ret=0  val=0xffffffffffffffff
READ 0x820000000  ret=0  val=0xffffffffffffffff
... (32–34 GB all readable, all-ones) ...
```

Key facts:
- host-PA **0x800000000–0x880000000 (32–34 GB) reads `ret=0`** — present + readable,
  NO panic. This is the root-0 NPT mapping the HV's own physical memory.
- `0xffffffffffffffff` = all CR/DR intercept bits set, i.e. a VMCB's first 8 bytes
  (cr_read/cr_write/dr_read/dr_write all 0xffff). Consistent with the VMCB region.
- The earlier "lucky boot" read the WRONG address (`0x60000000` carve-out = -1); the
  correct lever is host-PA 32–40 GB.
- The scan PANICKED past ~34 GB (the root-0 mapping does not extend into 34–64 GB —
  hidden/permission-stripped pages there). Stay within 32–40 GB.

## Next steps

1. Re-JB, then FINER scan of 0x800000000–0x900000000 (32–36 GB) at 2 MB / 4 KB steps,
   hunting non-`0xffffffffffffffff` values (the actual VMCB / VCPU array / NPT pages).
2. Identify the VMCB (predicate: np_enable@0x90 bit0=1, n_cr3@0xB0 4KB-aligned,
   asid@0x58 1..16, intercepts@0x0 nonzero).
3. Clear `VMCB+0x90` bit0 (NP_ENABLE) via the CPU (kernel_setlong / kernel_copyin on the
   DMAP), disabling nested paging — then HV memory is freely readable/writable.

## Files

- `scratch/ps5/probe93/root0.c` / `root0.elf` — the host-PA read probe (log
  `/data/kex_root0.txt`, logs BEFORE each read so a panic leaves its address).
