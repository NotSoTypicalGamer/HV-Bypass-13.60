import os
import numpy as np

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
CONTIG = "hvdump_0x26000000_600MB.bin"
CONTIG_BASE = 0x26000000

def enum16(arr, base_pa, label):
    m = len(arr)
    aligned = ((arr & 0xFFF) == 0) & (arr != 0)
    am = aligned.astype(np.int8)
    d = np.diff(np.concatenate(([0], am, [0])))
    starts = np.where(d == 1)[0]
    ends = np.where(d == -1)[0]
    out = []
    for s, e in zip(starts, ends):
        L = e - s
        if L == 16:
            vals = [int(v) for v in arr[s:e]]
            host = all(0x10000000 <= v < 0x400000000 for v in vals)
            out.append((base_pa + s*8, vals, host))
    return out

all16 = []
data = np.fromfile(os.path.join(D, CONTIG), dtype='<u8')
all16 += enum16(data, CONTIG_BASE, CONTIG)
del data
for f in sorted(x for x in os.listdir(D) if x.startswith('hvcluster_') and x.endswith('.bin')):
    base = int(f[len('hvcluster_'):-4], 16)
    a = np.fromfile(os.path.join(D, f), dtype='<u8')
    all16 += enum16(a, base, f)
    del a

print(f"total exact-16 aligned non-zero arrays: {len(all16)}")
print("\n=== all exact-16 arrays ===")
for gpa, vals, host in all16:
    tag = "HOST-RANGE" if host else ""
    print(f"  guest_pa=0x{gpa:x} {tag}")
    print(f"    {[hex(v) for v in vals]}")
