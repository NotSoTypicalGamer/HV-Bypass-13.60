import os, json
import numpy as np
from collections import Counter, defaultdict

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
CONTIG = "hvdump_0x26000000_600MB.bin"
CONTIG_BASE = 0x26000000

def scan_16aligned(arr, base_pa, label, need=16):
    """Find runs of >=need consecutive non-zero 4KB-aligned u64 (ANY stride)."""
    m = len(arr)
    aligned = ((arr & 0xFFF) == 0) & (arr != 0)
    am = aligned.astype(np.int8)
    d = np.diff(np.concatenate(([0], am, [0])))
    starts = np.where(d == 1)[0]
    ends = np.where(d == -1)[0]
    out = []
    for s, e in zip(starts, ends):
        L = e - s
        if L >= need:
            vals = arr[s:e].astype(np.int64)
            # host-range check
            host = (vals >= 0x10000000) & (vals < 0x400000000)
            special = ((vals >= 0x60000000) & (vals < 0x70000000)) | ((vals >= 0x80000000) & (vals < 0x90000000))
            out.append({
                'label': label, 'file_off': int(s)*8, 'guest_pa': base_pa + int(s)*8,
                'run_len': L,
                'n_host': int(host.sum()), 'n_special': int(special.sum()),
                'vals': [int(v) for v in vals[:20]],
                'vmin': int(vals.min()), 'vmax': int(vals.max()),
            })
    return out

def main():
    res = []
    data = np.fromfile(os.path.join(D, CONTIG), dtype='<u8')
    res += scan_16aligned(data, CONTIG_BASE, CONTIG)
    del data
    for f in sorted(x for x in os.listdir(D) if x.startswith('hvcluster_') and x.endswith('.bin')):
        base = int(f[len('hvcluster_'):-4], 16)
        a = np.fromfile(os.path.join(D, f), dtype='<u8')
        res += scan_16aligned(a, base, f)
        del a
    print(f"total runs of >=16 aligned non-zero u64: {len(res)}")

    # filter: all 16 in host range OR all in special range
    print("\n=== runs where ALL entries are host-RAM (0x10000000-0x400000000) ===")
    c = 0
    for r in res:
        if r['n_host'] >= 16:
            print(f"  guest_pa=0x{r['guest_pa']:x} len={r['run_len']} vals={[hex(v) for v in r['vals'][:16]]}")
            c += 1
    print(f"  count={c}")

    print("\n=== runs where ALL entries are special (0x6/0x8 range) ===")
    c = 0
    for r in res:
        if r['n_special'] >= 16:
            print(f"  guest_pa=0x{r['guest_pa']:x} len={r['run_len']} vals={[hex(v) for v in r['vals'][:16]]}")
            c += 1
    print(f"  count={c}")

    print("\n=== runs with >=8 host entries (mixed) ===")
    c = 0
    for r in res:
        if r['n_host'] >= 8:
            print(f"  guest_pa=0x{r['guest_pa']:x} len={r['run_len']} n_host={r['n_host']} vals={[hex(v) for v in r['vals'][:16]]}")
            c += 1
    print(f"  count={c}")

    print("\n=== top 20 by len (any range) ===")
    for r in sorted(res, key=lambda x: -x['run_len'])[:20]:
        print(f"  guest_pa=0x{r['guest_pa']:x} len={r['run_len']} vmin=0x{r['vmin']:x} vmax=0x{r['vmax']:x}")

if __name__ == '__main__':
    main()
