import os, math
from collections import Counter

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
FN = os.path.join(D, "hvdump_0x26000000_600MB.bin")

fsize = os.path.getsize(FN)
print("file size:", fsize, "= 0x%x" % fsize)

MB = 1 << 20

def entropy(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((v/n) * math.log2(v/n) for v in c.values())

prologue = b"\x55\x48\x89\xe5"

# scan in 1 MB blocks
blocks = []
with open(FN, "rb") as f:
    idx = 0
    while True:
        b = f.read(MB)
        if not b:
            break
        pro = b.count(prologue)
        r48 = b.count(b"\x48")
        e = entropy(b)
        z = b.count(b"\x00") / len(b)
        blocks.append((idx, len(b), pro, r48/len(b), e, z))
        idx += 1
        if idx >= fsize // MB + 2:
            break

print("\nper-1MB blocks:  idx(off_MB)  size  prologues  rex48_density  entropy  zero_frac")
# print blocks sorted by prologue count (code candidates) + all blocks summary
print("\n=== top 40 blocks by prologue count ===")
for idx, sz, pro, r48, e, z in sorted(blocks, key=lambda x: -x[2])[:40]:
    print("  off=0x%08x  pro=%d  r48=%.3f  ent=%.3f  zero=%.3f" % (idx*MB, pro, r48, e, z))

print("\n=== blocks with prologue count == 0 (non-code) count:", sum(1 for b in blocks if b[2]==0), "of", len(blocks))
