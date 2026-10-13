import os, re, hashlib
from collections import defaultdict

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
files = sorted(f for f in os.listdir(D) if f.startswith("hvcluster_") and f.endswith(".bin"))

def chunk_base(fn):
    m = re.search(r'hvcluster_([0-9a-fA-F]+)\.bin', fn)
    return int(m.group(1), 16)

# full-chunk hash
h = {}
for fn in files:
    with open(os.path.join(D, fn), "rb") as f:
        data = f.read()
    h[chunk_base(fn)] = hashlib.md5(data).hexdigest()

# group identical
groups = defaultdict(list)
for base, hh in h.items():
    groups[hh].append(base)

print("total chunks:", len(h))
print("unique contents:", len(groups))
print("\ngroups with >1 member (byte-identical chunks):")
for hh, bases in sorted(groups.items(), key=lambda kv: -len(kv[1])):
    if len(bases) > 1:
        print("  %s: %s" % (len(bases), ["0x%08x" % b for b in sorted(bases)]))

# Also: compute per-1MB how much is non-zero (data vs code heuristic)
print("\nchunk zero-byte fraction (low = mostly full; some HV chunks may have large zero tails):")
stats = []
for fn in files:
    with open(os.path.join(D, fn), "rb") as f:
        data = f.read()
    nz = sum(1 for b in data if b != 0)
    stats.append((chunk_base(fn), nz / len(data)))
stats.sort()
print("  most-zero chunks:")
for b, f in stats[:15]:
    print("    0x%08x  nonzero=%.1f%%" % (b, f*100))
