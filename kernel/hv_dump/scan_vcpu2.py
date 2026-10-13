import os, sys, json, struct
from collections import defaultdict, Counter

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
CONTIG = "hvdump_0x26000000_600MB.bin"
CONTIG_BASE = 0x26000000

def scan_contig_conststride(data, base_pa, label, min_run=8, min_stride=0x1000, max_stride=0x10000):
    """Runs of consecutive u64 where ALL are 4KB-aligned non-zero AND all pairwise
    strides are IDENTICAL, with stride in [min_stride, max_stride]."""
    n = len(data) & ~0x7
    mv = memoryview(data[:n]).cast('Q')
    m = len(mv)
    results = []
    i = 0
    while i < m:
        v = mv[i]
        if (v & 0xFFF) == 0 and v != 0:
            # candidate run start: require constant stride
            j = i + 1
            if j < m:
                s = mv[j] - v  # stride
                # stride must be positive, aligned, in range
                if s > 0 and (s & 0xFFF) == 0 and min_stride <= s <= max_stride:
                    vals = [v, mv[j]]
                    k = j + 1
                    while k < m:
                        nv = mv[k]
                        if (nv & 0xFFF) == 0 and nv != 0 and (nv - vals[-1]) == s:
                            vals.append(nv)
                            k += 1
                        else:
                            break
                    if len(vals) >= min_run:
                        results.append({
                            'label': label, 'file_off': i*8, 'guest_pa': base_pa + i*8,
                            'run_len': len(vals), 'stride': s, 'vals': vals,
                        })
                    i = k
                    continue
            i += 1
        else:
            i += 1
    return results

def scan_periodic(data, base_pa, label, min_run=8, min_stride=0x1000, max_stride=0x10000,
                  max_period=256):
    """Find arrays where a 4KB-aligned host-PA pointer repeats every `period` bytes
    with constant small stride (struct arrays)."""
    n = len(data) & ~0x7
    mv = memoryview(data[:n]).cast('Q')
    m = len(mv)
    results = []
    for period_q in range(1, max_period//8 + 1):  # period in 8-byte units
        period = period_q * 8
        # scan each residue class
        for start in range(min(period_q, m)):
            if start >= m: break
            vals = []
            idx = start
            # try to build a run
            while idx < m:
                v = mv[idx]
                if (v & 0xFFF) == 0 and v != 0:
                    vals.append((idx, v))
                    idx += period_q
                else:
                    break
            # now check constant stride among collected vals
            if len(vals) >= min_run:
                strides = [vals[k+1][1] - vals[k][1] for k in range(len(vals)-1)]
                uniq = set(strides)
                if len(uniq) == 1:
                    s = strides[0]
                    if s > 0 and (s & 0xFFF) == 0 and min_stride <= s <= max_stride:
                        results.append({
                            'label': label, 'file_off': vals[0][0]*8, 'guest_pa': base_pa + vals[0][0]*8,
                            'period': period, 'run_len': len(vals), 'stride': s,
                            'vals': [v for _, v in vals],
                        })
    return results

def main():
    allc = []
    # contiguous
    cp = os.path.join(D, CONTIG)
    data = open(cp, 'rb').read()
    allc.extend(scan_contig_conststride(data, CONTIG_BASE, CONTIG))
    del data
    for f in sorted(x for x in os.listdir(D) if x.startswith('hvcluster_') and x.endswith('.bin')):
        base = int(f[len('hvcluster_'):-4], 16)
        d = open(os.path.join(D, f), 'rb').read()
        allc.extend(scan_contig_conststride(d, base, f))
        del d

    print(f"[*] constant-stride contiguous arrays (len>=8, stride 0x1000-0x10000): {len(allc)}")
    # group by stride
    by_stride = defaultdict(list)
    for r in allc:
        by_stride[r['stride']].append(r)
    print("[*] stride histogram:")
    for s in sorted(by_stride):
        runs = by_stride[s]
        print(f"    0x{s:x}: {len(runs)} runs")

    # print best candidates: prefer len 8 or 16, values in host range
    def hostrange(v):
        return 0x100000 <= v < 0x400000000
    def special(v):
        return 0x60000000 <= v < 0x70000000 or 0x80000000 <= v < 0x90000000

    print("\n=== arrays whose values are in 0x6xxxxxxx or 0x8xxxxxxx ===")
    cnt=0
    for r in allc:
        if all(special(v) for v in r['vals']):
            print(f"  {r['label']} off=0x{r['file_off']:x} guest_pa=0x{r['guest_pa']:x} len={r['run_len']} stride=0x{r['stride']:x}")
            print(f"    vals={[hex(v) for v in r['vals'][:16]]}")
            cnt+=1
    print(f"  (total {cnt})")

    print("\n=== arrays whose values are ALL in host-RAM range [0x100000, 0x400000000) ===")
    cnt=0
    for r in allc:
        if all(hostrange(v) for v in r['vals']):
            print(f"  {r['label']} off=0x{r['file_off']:x} guest_pa=0x{r['guest_pa']:x} len={r['run_len']} stride=0x{r['stride']:x}")
            print(f"    vals={[hex(v) for v in r['vals'][:16]]}")
            cnt+=1
    print(f"  (total {cnt})")

    with open(os.path.join(D, 'vcpu_conststride.json'), 'w') as fh:
        json.dump(allc, fh, indent=1)

if __name__ == '__main__':
    main()
