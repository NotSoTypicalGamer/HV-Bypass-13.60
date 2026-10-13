import glob, os
from collections import Counter

files = sorted(glob.glob('hvcluster_*.bin'), key=lambda f:int(os.path.basename(f)[10:-4],16))

# Scan for 8-byte little-endian values in plausible host-PA ranges, ANY alignment
ranges = {
    'old_carveout_628-62b': (0x62800000, 0x62B00000),
    'carveout_600-700':    (0x60000000, 0x70000000),
    'carveout_600-680':    (0x60000000, 0x68000000),
    'phys_0-16GB_4kalign': (0x1000000, 0x400000000),
}
found = {k: Counter() for k in ranges}
# also: 4KB-aligned u64 anywhere in 0x60000000..0x70000000

for f in files:
    gpa = int(os.path.basename(f)[10:-4],16)
    d = open(f,'rb').read()
    for i in range(len(d)-7):
        v = int.from_bytes(d[i:i+8],'little')
        for k,(lo,hi) in ranges.items():
            if lo <= v < hi:
                found[k][v]+=1

for k in ranges:
    print("=== 8-byte LE values in %s : %d distinct, %d total ===" % (k, len(found[k]), sum(found[k].values())))
    for v,c in sorted(found[k].items())[:30]:
        print("   0x%08x  x%d" % (v,c))
    print()
