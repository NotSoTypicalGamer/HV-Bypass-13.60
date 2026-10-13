import os, sys, json
from collections import Counter, defaultdict

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
CONTIG = "hvdump_0x26000000_600MB.bin"
CONTIG_BASE = 0x26000000

def u64(v):
    return v & 0xFFFFFFFFFFFFFFFF

def analyze(data, label):
    n = len(data) & ~0x7
    mv = memoryview(data[:n]).cast('Q')
    m = len(mv)
    band = Counter()          # 256MB band of 4KB-aligned non-zero values
    old_pa_hits = []          # offsets where old fw VMCB PAs appear
    pair_stride = Counter()   # stride between consecutive 4KB-aligned values (any sign, small)
    OLD = {0x6290B000, 0x62A05000}
    prev = None
    prev_off = None
    for i in range(m):
        v = u64(mv[i])
        if (v & 0xFFF) == 0 and v != 0:
            band[v >> 28] += 1
            if v in OLD:
                old_pa_hits.append(i*8)
            if prev is not None:
                d = v - prev
                if 0 < d <= 0x10000:
                    pair_stride[d] += 1
            prev = v
            prev_off = i*8
        else:
            prev = None
    return band, old_pa_hits, pair_stride

def main():
    cp = os.path.join(D, CONTIG)
    data = open(cp, 'rb').read()
    band, old_hits, pair = analyze(data, CONTIG)
    del data
    for f in sorted(x for x in os.listdir(D) if x.startswith('hvcluster_') and x.endswith('.bin')):
        d = open(os.path.join(D, f), 'rb').read()
        b2, o2, p2 = analyze(d, f)
        band.update(b2); old_hits += [(f, o) for o in o2]; pair.update(p2)
        del d

    print("=== 4KB-aligned non-zero u64 value bands (256MB) ===")
    total = sum(band.values())
    print(f"total aligned pointers seen: {total}")
    for b in sorted(band):
        lo = b << 28
        hi = lo + 0x0FFFFFFF
        print(f"  0x{lo:09x} - 0x{hi:09x}: {band[b]}")
    print("\n=== old fw VMCB PA hits (0x6290B000 / 0x62A05000) ===")
    print(f"  count={len(old_hits)}")
    for h in old_hits[:40]:
        print("   ", h)
    print("\n=== stride between consecutive aligned values (small strides) ===")
    for d, c in pair.most_common(40):
        print(f"  0x{d:x}: {c}")

if __name__ == '__main__':
    main()
