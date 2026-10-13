# REST_RESUME_DUMP.md — rest-mode resume → dump the HV (root-0 NPT bug)

**Goal:** on resume from rest mode, the HV may re-run NPT construction WITHOUT
re-applying the own-pages carve-out (the Byepervisor bug-2 asymmetry) — leaving the
HV's own memory (carve-out `0x60000000–0x70000000`) guest-readable. If we read it, we
bugged root-0 NPT and can dump the HV.

**Target:** 13.60 @ `10.0.0.x` (elfldr 9021, FTP 2121).

## Tools (built, in `scratch/ps5/`)

| probe | what it does |
|---|---|
| `probe87/carveout.elf` | samples 8 B every 8 MB across `0x60000000–0x80000000` via DMAP; logs `READ val=` (lucky) vs `rc=-1` (not-present). Safe on unlucky boot (−1). Log `/data/kex_carveout.txt`. |
| `probe83/hvscan4.elf` | fixed SVM scanner (≥2 SVM ops in ≤64 B at valid decode boundaries, rejects stride-2 tables); dump-on-sight 4 KB pages to `/data/hvcluster4_<off>.bin`, O_SYNC log `/data/kex_hvscan4.txt` before any later page faults. Config `/data/hvscan_cfg.txt` "start end". |
| `probe54/hvdump.elf` | configurable full-range dump (`/data/hvdump.txt` "base size") → `/data/hvdump.bin`, 1 MB chunks. Use ONLY on a known-readable range (panics on a trapped page). |
| `probe65/liveness.elf` | maps the readable DMAP band (4 KB @ 512 MB boundaries 2–16 GB). |

## Sequence

1. **Baseline (pre-rest):** deploy `carveout.elf`, confirm `rc=-1` everywhere (unlucky).
2. **Rest mode:** operator holds PS button → Enter Rest Mode.
3. **Resume:** operator wakes the console; wait ~15 s for network, then verify `9021`/`2121` up.
4. **Trigger check:** re-deploy `carveout.elf`.
   - All `rc=-1` → not triggered → repeat rest/resume (up to 3–5 cycles).
   - Any `READ val=` in `0x60000000–0x70000000` → **LUCKY — proceed to dump.**
5. **Dump the HV:** STOR `/data/hvscan_cfg.txt` = `60000000 70000000`, deploy `hvscan4.elf`
   (dump-on-sight of the SVM-dense code pages). FTP-pull `/data/hvcluster4_*.bin` + the log.
6. **Whole-band (if the boot is fully readable, no panic):** STOR `/data/hvdump.txt` =
   `60000000 10000000`, deploy `hvdump.elf`, FTP-pull `/data/hvdump.bin` — captures the
   zero-SVM NPT constructor that the density filter would miss.

## Success = we can read plaintext HV code out of the carve-out.

If any step panics: the O_SYNC dumps/logs already written survive — cold-boot, re-JB,
then FTP-pull them before re-deploying.
