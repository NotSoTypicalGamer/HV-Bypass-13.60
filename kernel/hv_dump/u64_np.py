import glob, os
import numpy as np
from collections import Counter

files = sorted(glob.glob('hvcluster_*.bin'), key=lambda f:int(os.path.basename(f)[10:-4],16))

all64 = None
parts = []
for f in files:
    d = np.frombuffer(open(f,'rb').read(), dtype='<u8')
    parts.append(d)

all64 = np.concatenate(parts)
print("total u64 words:", all64.shape[0])

# ranges to search (as u64)
def mask(lo, hi):
    return (all64 >= lo) & (all64 < hi)

for label, lo, hi in [
    ('old 0x62800000-0x62B00000', 0x62800000, 0x62B00000),
    ('0x60000000-0x70000000', 0x60000000, 0x70000000),
    ('0x60000000-0x68000000', 0x60000000, 0x68000000),
    ('0x68000000-0x70000000', 0x68000000, 0x70000000),
]:
    m = mask(lo, hi)
    n = int(m.sum())
    vals = all64[m]
    print("=== %s : %d hits ===" % (label, n))
    if n:
        uniq, cnt = np.unique(vals, return_counts=True)
        for v,c in zip(uniq, cnt):
            print("   0x%08x  x%d" % (int(v), int(c)))
    print()

# Also: 4KB-aligned u64 in 0x60000000..0x70000000
m = mask(0x60000000, 0x70000000) & ((all64 & 0xfff) == 0)
print("4KB-aligned u64 in 0x60000000-0x70000000:", int(m.sum()))

# Also 32-bit scan (4-byte values) in 0x60000000-0x70000000
all32 = all64.astype('<u4')  # low 32 bits of each word
# full 32-bit scan: reinterpret every 4-byte window
raw = np.concatenate([np.frombuffer(open(f,'rb').read(), dtype='<u4') for f in files])
m32 = (raw >= 0x60000000) & (raw < 0x70000000)
print("=== 4-byte LE values in 0x60000000-0x70000000: %d hits ===" % int(m32.sum()))
if m32.sum():
    uniq, cnt = np.unique(raw[m32], return_counts=True)
    for v,c in zip(uniq, cnt)[:50]:
        print("   0x%08x  x%d" % (int(v), int(c)))
