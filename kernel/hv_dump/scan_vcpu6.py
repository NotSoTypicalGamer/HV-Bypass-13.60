import os, sys, json
import numpy as np
from collections import defaultdict

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
CONTIG = "hvdump_0x26000000_600MB.bin"
CONTIG_BASE = 0x26000000
MIN_RUN = 8
MIN_STRIDE = 0x1000
MAX_STRIDE = 0x10000

def const_stride_subruns(vals, min_run=MIN_RUN):
    """Given 1D int64 array of ALIGNED values, find maximal constant-stride sub-runs."""
    n = len(vals)
    if n < min_run:
        return []
    d = np.diff(vals)
    if len(d) == 0:
        return []
    change = np.concatenate(([True], d[1:] != d[:-1], [True]))
    idx = np.where(change)[0]
    out = []
    for k in range(len(idx) - 1):
        s = idx[k]; e = idx[k + 1]
        L = e - s + 1
        sd = int(d[s])
        if L >= min_run and MIN_STRIDE <= sd <= MAX_STRIDE:
            out.append((int(s), int(L), sd))
    return out

def scan_column(col, arr_ctx, base_pa, label, step, coloff):
    """Find aligned runs in col, then constant-stride sub-runs. Returns dicts."""
    aligned = ((col & 0xFFF) == 0) & (col != 0)
    m = len(col)
    if m < MIN_RUN:
        return []
    am = aligned.astype(np.int8)
    d = np.diff(np.concatenate(([0], am, [0])))
    starts = np.where(d == 1)[0]
    ends = np.where(d == -1)[0]
    out = []
    for s, e in zip(starts, ends):
        L = e - s
        if L < MIN_RUN:
            continue
        vals = col[s:e].astype(np.int64)
        for (ss, LL, sd) in const_stride_subruns(vals):
            abs_idx = (s + ss) * step + coloff
            out.append({
                'label': label, 'period': step * 8, 'col': int(coloff),
                'file_off': int(abs_idx) * 8, 'guest_pa': base_pa + int(abs_idx) * 8,
                'run_len': LL, 'stride': sd,
                'vals': [int(v) for v in vals[ss:ss + LL][:16]],
            })
    return out

def main():
    results = []
    cp = os.path.join(D, CONTIG)
    arr = np.fromfile(cp, dtype='<u8')
    m = len(arr)
    print(f"[*] contiguous {m} u64", flush=True)

    # q=1
    results += scan_column(arr, None, CONTIG_BASE, CONTIG, 1, 0)
    print(f"[*] q=1: {len(results)}", flush=True)

    # q=2..32
    for q in range(2, 33):
        use = m - (m % q)
        a2 = arr[:use].reshape(-1, q)
        for c in range(q):
            col = a2[:, c]
            results += scan_column(col, None, CONTIG_BASE, CONTIG, q, c)
        del a2
        if q % 8 == 0:
            print(f"[*] q={q}: {len(results)} total", flush=True)
    del arr

    # sparse chunks q=1 only
    for f in sorted(x for x in os.listdir(D) if x.startswith('hvcluster_') and x.endswith('.bin')):
        base = int(f[len('hvcluster_'):-4], 16)
        a = np.fromfile(os.path.join(D, f), dtype='<u8')
        results += scan_column(a, None, base, f, 1, 0)
        del a
    print(f"[*] total results: {len(results)}", flush=True)

    with open(os.path.join(D, 'vcpu_periodic.json'), 'w') as fh:
        json.dump(results, fh, indent=1)

    def cls(v):
        if 0x60000000 <= v < 0x70000000: return '0x6xxxxxxx'
        if 0x80000000 <= v < 0x90000000: return '0x8xxxxxxx'
        if 0x10000000 <= v < 0x400000000: return 'host_ram'
        return 'other'

    by = defaultdict(list)
    for r in results:
        by[cls(r['vals'][0])].append(r)
    print("\n=== summary ===")
    for k in sorted(by):
        print(f"  {k}: {len(by[k])}")

    for k in ['0x6xxxxxxx', '0x8xxxxxxx', 'host_ram', 'other']:
        print(f"\n=== {k} ===")
        for r in by[k][:100]:
            print(f"  {r['label']} off=0x{r['file_off']:x} guest_pa=0x{r['guest_pa']:x} "
                  f"period={r['period']} col={r['col']} len={r['run_len']} stride=0x{r['stride']:x}")
            print(f"    vals={[hex(v) for v in r['vals']]}")

if __name__ == '__main__':
    main()
