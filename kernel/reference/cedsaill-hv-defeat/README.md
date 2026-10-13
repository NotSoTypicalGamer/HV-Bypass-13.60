# cedsaill3/ps5-hv-defeat (FW 9.60) — working deterministic HV defeat

Public complete implementation (RING0_OK + JAILBREAK_OK confirmed on 9.60). Same technique
family we've been on, but a working reference:

1. GPU-DMA physical WRITE (main direct memory, not garlic) — the GPU RDNA2 IOMMU does not
   respect the CPU NPT, so it writes kernel .data despite W=0. (`hv-unlock.c gpu_write_pa`)
2. Hook `sysent[661]` (unused syscall slot) for ring-0 entry.
3. `wrmsr(MSR_APICBASE, hv_stack|0x900)` -> VMEXIT; the HV MSR dispatch entry for APICBASE
   is NULL -> CPU jumps VA 0 -> PA 0 -> staged shellcode (in HV context).
4. Shellcode scans [0x62800000..0x64800000] for VMCBs (NESTED_CTRL@+0x90 NP_ENABLE set),
   clears NP_ENABLE on each, restores APICBASE, re-enters via vmload+vmrun.

NOTE vs our 13.60 findings:
- Our GPU-DMA write is DEAD on 13.60 (garlic vmid6 = VRAM-only; onion vmid2 GNM =
  driver-init fails). cedsaill uses MAIN direct memory, a path we did not fully test.
- Our WRMSR analysis says the #SX (BSP bit) path is patched since 8.00, but the "null
  dispatch -> VA 0" framing here is different and NOT yet ruled out on 13.60.
- NEW IDEA: swap the GPU-DMA write for the Relapse DMAP write (`kernel_copyin(dmap+0, ...)`)
  to stage the shellcode at PA 0 — if the null-dispatch trigger is live, the chain ports.
