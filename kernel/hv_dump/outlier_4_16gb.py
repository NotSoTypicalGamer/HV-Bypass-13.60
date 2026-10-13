import os, re, math
import numpy as np

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"

def base_of(f):
    return int(re.match(r'hvcluster_([0-9a-f]+)\.bin', f).group(1), 16)

files = sorted((f for f in os.listdir(D)
                if f.startswith("hvcluster_") and f.endswith(".bin")
                and base_of(f) >= 0x100000000), key=base_of)

# per-file zero-ratio & entropy, flag any outliers (plaintext would show low entropy)
outliers = []
for f in files:
    raw = open(os.path.join(D, f), 'rb').read()
    z = raw.count(0) / len(raw)
    # quick entropy on 4KB sample
    from collections import Counter
    c = Counter(raw[:65536])
    ent = -sum((n/65536)*math.log2(n/65536) for n in c.values())
    if z > 0.05 or ent < 7.0:
        outliers.append((f, z, ent))

print(f"files: {len(files)}")
print(f"outliers (zero>5% OR entropy<7.0): {len(outliers)}")
for f, z, ent in outliers:
    print(f"  {f} zero={100*z:.2f}% entropy={ent:.3f}")

# also: check the 3974 aligned values - any plausible VMCB anchor / host-PA?
aligned_vals = []
for f in files:
    b = base_of(f)
    arr = np.fromfile(os.path.join(D, f), dtype='<u8')
    idx = np.nonzero((arr & 0xFFF) == 0)[0]
    for i in idx:
        aligned_vals.append((b + i*8, int(arr[i])))
print(f"\naligned nonzero u64 total: {len(aligned_vals)}")

# old anchors and plausible VMCB PA range 0x60000000-0x70000000, and 0x2xxxx/0x8xxxx
anchors = [0x6290B000, 0x62A05000, 0x6290E000]
print("matches to old anchors / 0x62xxxxxx / 0x2xxxxxxx / 0x8xxxxxxx aligned values:")
interesting = []
for gpa, v in aligned_vals:
    if v in anchors:
        print(f"  EXACT OLD ANCHOR 0x{v:x} at guest_pa 0x{gpa:x}")
    if 0x60000000 <= v < 0x70000000:
        interesting.append((gpa, v, '0x6xxxxxxx'))
    elif 0x200000000 <= v < 0x300000000:
        interesting.append((gpa, v, '0x2xxxxxxx'))
    elif 0x800000000 <= v < 0x900000000:
        interesting.append((gpa, v, '0x8xxxxxxx'))
    elif 0x10000000 <= v < 0x400000000:
        interesting.append((gpa, v, 'host-low'))
print(f"interesting aligned values: {len(interesting)}")
for gpa, v, kind in interesting[:40]:
    print(f"  gpa=0x{gpa:x} -> 0x{v:x} [{kind}]")
