import os, sys, json
import numpy as np
from collections import defaultdict

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
CONTIG = "hvdump_0x26000000_600MB.bin"
CONTIG_BASE = 0x26000000
MIN_RUN = 8
MIN_STRIDE = 0x1000
MAX_STRIDE = 0x10000

def runs_1d(aligned, arr, base_pa, label, step=1, col=0):
    m = len(aligned)
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
        idx = np.arange(s, e) * step + col
        vals = arr[idx].astype(np.int64)
        diffs = np.diff(vals)
        uniq = np.unique(diffs)
        if len(uniq) == 1:
            sd = int(uniq[0])
            if MIN_STRIDE <= sd <= MAX_STRIDE:
                out.append({
                    'label': label, 'period': step * 8, 'col': col,
                    'file_off': int(idx[0]) * 8, 'guest_pa': base_pa + int(idx[0]) * 8,
                    'run_len': L, 'stride': sd,
                    'vals': [int(v) for v in vals[:16]],
                })
    return out

def main():
    cp = os.path.join(D, CONTIG)
    arr = np.fromfile(cp, dtype='<u8')
    print(f"[*] contiguous {len(arr)} u64", flush=True)
    aligned = ((arr & 0xFFF) == 0) & (arr != 0)
    allres = []

    allres += runs_1d(aligned, arr, CONTIG_BASE, CONTIG, step=1, col=0)
    print(f"[*] q=1 done: {len(allres)}", flush=True)

    m = len(arr)
    for q in range(2, 33):
        use = m - (m % q)
        R = use // q
        b2 = aligned[:use].reshape(R, q).T
        pad = np.zeros((q, 1), dtype=bool)
        flat = np.concatenate((b2, pad), axis=1).ravel()
        am = flat.astype(np.int8)
        d = np.diff(np.concatenate(([0], am, [0])))
        starts = np.where(d == 1)[0]
        ends = np.where(d == -1)[0]
        width = R + 1
        for s, e in zip(starts, ends):
            L = e - s
            if L < MIN_RUN:
                continue
            c = s // width
            s_col = s % width
            if s_col + L > R:
                continue
            idx = np.arange(s_col, s_col + L) * q + c
            vals = arr[idx].astype(np.int64)
            diffs = np.diff(vals)
            uniq = np.unique(diffs)
            if len(uniq) == 1:
                sd = int(uniq[0])
                if MIN_STRIDE <= sd <= MAX_STRIDE:
                    allres.append({
                        'label': CONTIG, 'period': q * 8, 'col': c,
                        'file_off': int(idx[0]) * 8, 'guest_pa': CONTIG_BASE + int(idx[0]) * 8,
                        'run_len': L, 'stride': sd,
                        'vals': [int(v) for v in vals[:16]],
                    })
        if q % 8 == 0:
            print(f"[*] q={q} done: {len(allres)} total", flush=True)

    del arr, aligned
    print(f"[*] contiguous total: {len(allres)}", flush=True)

    for f in sorted(x for x in os.listdir(D) if x.startswith('hvcluster_') and x.endswith('.bin')):
        base = int(f[len('hvcluster_'):-4], 16)
        a = np.fromfile(os.path.join(D, f), dtype='<u8')
        al = ((a & 0xFFF) == 0) & (a != 0)
        allres += runs_1d(al, a, base, f, step=1, col=0)
        del a, al
    print(f"[*] all done, total: {len(allres)}", flush=True)

    with open(os.path.join(D, 'vcpu_periodic.json'), 'w') as fh:
        json.dump(allres, fh, indent=1)

    def cls(v):
        if 0x60000000 <= v < 0x70000000: return '0x6xxxxxxx'
        if 0x80000000 <= v < 0x90000000: return '0x8xxxxxxx'
        if 0x10000000 <= v < 0x400000000: return 'host_ram'
        return 'other'

    by = defaultdict(list)
    for r in allres:
        by[cls(r['vals'][0])].append(r)
    print("\n=== summary ===")
    for k in sorted(by):
        print(f"  {k}: {len(by[k])}")

    for k in ['0x6xxxxxxx', '0x8xxxxxxx', 'host_ram']:
        print(f"\n=== {k} ===")
        for r in by[k][:80]:
            print(f"  {r['label']} off=0x{r['file_off']:x} guest_pa=0x{r['guest_pa']:x} "
                  f"period={r['period']} col={r['col']} len={r['run_len']} stride=0x{r['stride']:x}")
            print(f"    vals={[hex(v) for v in r['vals']]}")

    print("\n=== other ===")
    for r in by['other'][:40]:
        print(f"  {r['label']} off=0x{r['file_off']:x} guest_pa=0x{r['guest_pa']:x} "
              f"period={r['period']} len={r['run_len']} stride=0x{r['stride']:x} vals={[hex(v) for v in r['vals']]}")

if __name__ == '__main__':
    main()
