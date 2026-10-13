# probe99 — S3-resume AP-launch (HCALL 0x0f) port attempt

Deterministic root-0 VMCB write via the `khv_startup_mp` S3-resume bug (see
`kernel/s3-resume-startup_mp-ap-launch.md` and `kernel/S3_AP_LAUNCH_PORT.md`).

- `ap_launch.S` — the 4 KiB root-0 AP payload. Per the write-up it **walks `pcpus[]`**
  (`pcpu[core].m_vmcb` at `+0xa8`) and computes `VMCB phys = m_vmcb - hv_heap_offset`,
  then validates each VMCB (`NESTED_CTRL==9 @+0x90`, `Control2==1 @+0xb8`, aligned
  `NESTED_CR3 @+0xb0`) and writes `NESTED_CTRL=0x8`. Position-independent, no relocations.
- `trigger.c` — stages the AP payload at `0x3ffff000` and, in the S3-resume window, fires
  `HCALL 0x0f(core=15, RIP=0x3ffff000, CR3=0x68000)`.

## Still open (blocking a real deploy)
1. **`pcpus[]` base + `sizeof(pcpus_t)` stride** — the 13.60 inner-HV globals. The write-up
   gives the *strides* (`m_vmcb+0xa8`, `core_id+0x138`) but not the *base*; needs the 13.60
   HV binary (a lucky boot).
2. **`acpi_sleep_machdep` offset** — the `#DB` breakpoint (`+0x18e` on 10.00) is the timing
   + the ROP execution path for the VMMCALL. 13.60 offset unknown; kernel text is XOM.
3. **`hv_heap_offset = 0x2a028`** — known (the one offset the write-up publishes).

None of 1/2 are recoverable from current dumps (ktext XOM-scrambled, hv_dump ciphertext,
`.data` has no `acpi_sleep_machdep` pointer).
