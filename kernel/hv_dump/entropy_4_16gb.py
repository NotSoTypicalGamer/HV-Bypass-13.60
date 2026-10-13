import os, re
import numpy as np

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"

def base_of(f):
    return int(re.match(r'hvcluster_([0-9a-f]+)\.bin', f).group(1), 16)

files = sorted((f for f in os.listdir(D)
                if f.startswith("hvcluster_") and f.endswith(".bin")
                and base_of(f) >= 0x100000000), key=base_of)

# Read ALL bytes and compute global byte histogram + entropy
from collections import Counter
bytecount = Counter()
total_bytes = 0
zero_bytes = 0
for f in files:
    raw = open(os.path.join(D, f), 'rb').read()
    total_bytes += len(raw)
    for i in range(0, len(raw), 4096):  # sample every 4KB block, count zeros quickly
        pass
    # count zeros via bytes.count
    zero_bytes += raw.count(0)
    # update histogram (this is 126MB total, fine)
    bytecount.update(raw)

print(f"total bytes={total_bytes} zero_bytes={zero_bytes} ({100.0*zero_bytes/total_bytes:.3f}%)")

# entropy
import math
ent = 0.0
for b in range(256):
    c = bytecount.get(b, 0)
    if c:
        p = c / total_bytes
        ent -= p * math.log2(p)
print(f"byte entropy = {ent:.4f} bits/byte (8.0 = uniform random)")

# printable ASCII runs? count printable bytes
printable = sum(bytecount.get(b,0) for b in range(0x20,0x7f))
print(f"printable-ascii bytes = {100.0*printable/total_bytes:.3f}%")

# top 10 byte values
top = bytecount.most_common(10)
print("top bytes:", [(hex(b), c) for b,c in top])

# 16-byte block: check for repeated 0x00/0xFF patterns (encryption vs plaintext)
# distribution of u64 high nibble across ALL values
allvals = np.concatenate([np.fromfile(os.path.join(D,f), dtype='<u8') for f in files])
print("\nu64 high-nibble distribution (all values):")
for nib in range(16):
    mask = (allvals >> 60) & 0xF
    c = int(np.count_nonzero(mask == nib))
    if c:
        print(f"  high nibble 0x{nib:x}: {c} ({100.0*c/len(allvals):.2f}%)")
