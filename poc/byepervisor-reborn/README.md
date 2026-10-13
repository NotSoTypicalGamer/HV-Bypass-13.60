# Byepervisor-Reborn PoC — HV Bypass "Hello World"

Working 13.60 hypervisor-defeat payload, with the success toast changed to
**"HV Bypass Hello World"** to demonstrate the bypass.

## Build

Requires `ps5-payload-sdk` (LLVM 23).

```sh
export PS5_PAYLOAD_SDK=/path/to/ps5-payload-sdk
sh break_hv_payload/build.sh   # builds the break_hv flat AP blob + header
make                           # builds byepervisor_reborn.elf
```

If `build.sh`'s `xxd -i -n break_hv` fails on your distro (some `xxd` builds reject the
combined flags), replace it with:

```sh
xxd -i break_hv_payload/break_hv.bin | sed s/break_hv_bin/break_hv/g > break_hv_payload/break_hv.h
```

## Run

1. Deploy `byepervisor_reborn.elf` through elfldr (port 9021).
2. Enter rest mode, then resume.
3. On resume the AP payload clears `NP_ENABLE` on all 16 VMCBs and the
   **"HV Bypass Hello World"** toast fires (with firmware + cookie).

## Attribution

Mechanism (khook + `break_hv`) from [PS5Dev/Byepervisor-Reborn](https://github.com/PS5Dev/Byepervisor-Reborn);
only the toast text was changed for this PoC.
