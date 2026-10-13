import os, sys, json
import numpy as np
from collections import defaultdict, Counter

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
CONTIG = "hvdump_0x26000000_600MB.bin"
CONTIG_BASE = 0x26000000

MIN_STRIDE = 0x1000
MAX_STRIDE = 0x10000
MIN_RUN = 8

def find_constant_stride_runs(arr, base_pa, label, q=1):
    """For an array viewed as rows of q u64s, check each column for runs of
    >=MIN_RUN aligned non-zero values with constant stride in [MIN_STRIDE, MAX_STRIDE].
    Returns list of dicts."""
    m = len(arr)
    results = []
    use = m - (m % q)
    a2 = arr[:use].reshape(-1, q)
    rows, cols = a2.shape
    for c in range(q):
        col = a2[:, c]  # length rows
        aligned = ((col & 0xFFF) == 0) & (col != 0)
        # find runs
        am = aligned.astype(np.int8)
        d = np.diff(np.concatenate(([0], am, [0])))
        starts = np.where(d == 1)[0]
        ends = np.where(d == -1)[0]
        for s, e in zip(starts, ends):
            L = e - s
            if L < MIN_RUN:
                continue
            vals = col[s:e].astype(np.int64)
            diffs = np.diff(vals)
            if len(diffs) == 0:
                continue
            uniq = np.unique(diffs)
            if len(uniq) == 1:
                sd = int(uniq[0])
                if MIN_STRIDE <= sd <= MAX_STRIDE:
                    idx = s * q + c  # absolute u64 index of first value
                    results.append({
                        'label': label,
                        'period': q * 8,
                        'col': c,
                        'file_off': idx * 8,
                        'guest_pa': base_pa + idx * 8,
                        'run_len': L,
                        'stride': sd,
                        'vals': [int(v) for v in vals[:16]],
                        'vmin': int(vals.min()), 'vmax': int(vals.max()),
                    })
    return results

def classify(v):
    if 0x60000000 <= v < 0x70000000: return '0x6xxxxxxx'
    if 0x80000000 <= v < 0x90000000: return '0x8xxxxxxx'
    if 0x10000000 <= v < 0x400000000: return 'host_ram'
    if v < 0x1000000000: return 'low'
    return 'high'

def main():
    results = []
    # contiguous dump
    cp = os.path.join(D, CONTIG)
    data = np.fromfile(cp, dtype='<u8')
    print(f"[*] contiguous {len(data)} u64", flush=True)
    for q in range(1, 65):
        r = find_constant_stride_runs(data, CONTIG_BASE, CONTIG, q=q)
        results.extend(r)
    print(f"[*] contiguous scan done, {len(results)} results so far", flush=True)
    del data

    # sparse chunks
    for f in sorted(x for x in os.listdir(D) if x.startswith('hvcluster_') and x.endswith('.bin')):
        base = int(f[len('hvcluster_'):-4], 16)
        arr = np.fromfile(os.path.join(D, f), dtype='<u8')
        for q in range(1, 65):
            r = find_constant_stride_runs(arr, base, f, q=q)
            results.extend(r)
        del arr
    print(f"[*] total results: {len(results)}", flush=True)

    with open(os.path.join(D, 'vcpu_periodic.json'), 'w') as fh:
        json.dump(results, fh, indent=1)

    # categorize
    by_class = defaultdict(list)
    for r in results:
        v0 = r['vals'][0]
        by_class[classify(v0)].append(r)

    print("\n=== summary by value class ===")
    for k in sorted(by_class):
        print(f"  {k}: {len(by_class[k])}")

    print("\n=== arrays with values in 0x6xxxxxxx / 0x8xxxxxxx ===")
    for r in by_class['0x6xxxxxxx'] + by_class['0x8xxxxxxx']:
        print(f"  {r['label']} off=0x{r['file_off']:x} guest_pa=0x{r['guest_pa']:x} "
              f"period={r['period']} col={r['col']} len={r['run_len']} stride=0x{r['stride']:x}")
        print(f"    vals={[hex(v) for v in r['vals']]}")

    print("\n=== arrays with values in host-RAM 0x10000000-0x400000000 ===")
    for r in by_class['host_ram'][:60]:
        print(f"  {r['label']} off=0x{r['file_off']:x} guest_pa=0x{r['guest_pa']:x} "
              f"period={r['period']} col={r['col']} len={r['run_len']} stride=0x{r['stride']:x}")
        print(f"    vals={[hex(v) for v in r['vals']]}")

if __name__ == '__main__':
    main()
