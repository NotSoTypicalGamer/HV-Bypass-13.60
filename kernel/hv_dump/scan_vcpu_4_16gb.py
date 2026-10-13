#!/usr/bin/env python3
# Scan the 4-16GB guest-physical dumps (hvcluster_*.bin, base >= 0x100000000)
# for the hypervisor VCPU/VMCB-pointer array.
# Offline, numpy-accelerated.
import os, re, json
import numpy as np

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"

def base_of(f):
    return int(re.match(r'hvcluster_([0-9a-f]+)\.bin', f).group(1), 16)

files = sorted((f for f in os.listdir(D)
                if f.startswith("hvcluster_") and f.endswith(".bin")
                and base_of(f) >= 0x100000000),
               key=base_of)
print(f"files: {len(files)}")

HOST_LO = 0x10000000          # 256 MB
HOST_HI = 0x1000000000        # 64 GB  (generous upper bound)

# ---- value landscape + candidate collection ----
results = []                  # candidate arrays
hist_buckets = {}
total_qwords = 0

for f in files:
    b = base_of(f)
    path = os.path.join(D, f)
    arr = np.fromfile(path, dtype='<u8')
    N = len(arr)
    total_qwords += N

    # value landscape (buckets by top nibble-ish)
    al = (arr & 0xFFF) == 0
    nz = arr != 0
    aligned_nz = al & nz

    for v in arr[aligned_nz]:
        if v == 0:
            continue
        # bucket by highest set region
        if v < 0x100000000:
            key = '0x0_1GB'
        elif v < 0x200000000:
            key = '0x1_2GB'
        elif v < 0x400000000:
            key = '0x2_4GB'
        elif v < 0x800000000:
            key = '0x4_8GB'
        elif v < 0x1000000000:
            key = '0x8_16GB'
        elif v < 0x4000000000:
            key = '0x10_64GB'
        else:
            key = '>=64GB'
        hist_buckets[key] = hist_buckets.get(key, 0) + 1

    # ---- Scan A: constant positive small stride runs (VMCB signature) ----
    d = np.zeros(N, dtype=np.int64)
    if N > 1:
        # careful with unsigned wrap: do signed diff
        d[1:] = arr[1:].astype(np.int64) - arr[:-1].astype(np.int64)

    for L in (16, 8):
        k = L - 2                     # consecutive equalities needed
        if N < L:
            continue
        eq = d[1:N-1] == d[2:N]       # eq[j] ~ d[j+1]==d[j+2]; len N-2
        if len(eq) < k:
            continue
        conv = np.convolve(eq.astype(np.int8), np.ones(k, dtype=np.int8), mode='valid')
        starts = np.nonzero(conv == k)[0]   # arr[start .. start+L-1] constant stride
        for i in starts:
            stride = int(d[i+1])
            if stride <= 0:
                continue
            if stride > 0x10000:
                continue
            vals = arr[i:i+L].astype(np.int64)
            # all aligned & nonzero
            if not np.all((vals & 0xFFF) == 0):
                continue
            if np.any(vals == 0):
                continue
            if np.any(vals < HOST_LO) or np.any(vals >= HOST_HI):
                continue
            results.append({
                'kind': f'const_stride_{L}',
                'guest_pa': b + i*8,
                'file': f,
                'stride': stride,
                'vals': [hex(int(v)) for v in vals],
            })

print(f"total qwords scanned: {total_qwords}")
print("\n=== value landscape (4KB-aligned nonzero) ===")
for k in sorted(hist_buckets):
    print(f"  {k}: {hist_buckets[k]}")

print(f"\n=== candidate const-stride arrays: {len(results)} ===")
for r in results:
    print(f"  {r['kind']} @0x{r['guest_pa']:x} (file {r['file']}) stride=0x{r['stride']:x}")
    print(f"      vals={r['vals']}")

json.dump(results, open(os.path.join(D, 'vcpu_4_16gb_conststride.json'), 'w'), indent=1)
print("\nwrote vcpu_4_16gb_conststride.json")
