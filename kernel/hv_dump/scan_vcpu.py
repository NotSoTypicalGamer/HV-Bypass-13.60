import os, sys, json
from collections import defaultdict

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
CONTIG = "hvdump_0x26000000_600MB.bin"
CONTIG_BASE = 0x26000000

def u64(v):
    return v & 0xFFFFFFFFFFFFFFFF

def is_aligned(v):
    return (v & 0xFFF) == 0 and v != 0

def scan_buffer(data, base_pa, label, min_run=4):
    """Find runs of consecutive non-zero 4KB-aligned u64 values."""
    n = len(data) & ~0x7
    mv = memoryview(data[:n]).cast('Q')
    m = len(mv)
    results = []
    i = 0
    while i < m:
        v = mv[i]
        if is_aligned(v):
            j = i
            vals = []
            while j < m and is_aligned(mv[j]):
                vals.append(u64(mv[j]))
                j += 1
            if len(vals) >= min_run:
                # compute strides
                strides = [vals[k+1] - vals[k] for k in range(len(vals)-1)]
                results.append({
                    'label': label,
                    'file_off': i*8,
                    'guest_pa': base_pa + i*8,
                    'run_len': len(vals),
                    'vals': vals,
                    'strides': strides,
                })
            i = j
        else:
            i += 1
    return results

def summarize_run(r):
    vals = r['vals']
    strides = r['strides']
    uni = sorted(set(strides))
    stride_counts = {s: strides.count(s) for s in uni}
    # dominant stride
    dom = max(stride_counts.items(), key=lambda x: x[1]) if stride_counts else (None, 0)
    return dom, uni, stride_counts

def in_host_pa_range(v):
    # PS5 16GB physical: 0x0 - 0x400000000. VMCB PAs old fw ~0x62xxxxxx (1.6GB).
    # allow 256MB..16GB as "plausible host PA", plus anything < 0x100000000 (4GB) as loose
    return 0x10000000 <= v < 0x400000000

def in_special_range(v):
    return 0x60000000 <= v < 0x70000000 or 0x80000000 <= v < 0x90000000

def main():
    all_runs = []

    # 1. contiguous 608MB dump
    cp = os.path.join(D, CONTIG)
    print(f"[*] scanning {CONTIG} ({os.path.getsize(cp)} bytes)", flush=True)
    data = open(cp, 'rb').read()
    runs = scan_buffer(data, CONTIG_BASE, CONTIG)
    print(f"    -> {len(runs)} runs (len>=4)", flush=True)
    all_runs.extend(runs)
    del data

    # 2. sparse chunks
    chunks = sorted(f for f in os.listdir(D) if f.startswith('hvcluster_') and f.endswith('.bin'))
    for f in chunks:
        base = int(f[len('hvcluster_'):-len('.bin')], 16)
        p = os.path.join(D, f)
        data = open(p, 'rb').read()
        runs = scan_buffer(data, base, f)
        all_runs.extend(runs)
    print(f"[*] total runs: {len(all_runs)}", flush=True)

    # categorize
    strong = []   # len>=8, dominant stride in 0x1000..0x10000, all host-pa-range
    medium = []   # len>=8, any stride, host-pa or special range
    special = []  # values in 0x6xxxxxxx / 0x8xxxxxxx
    others = []

    for r in all_runs:
        vals = r['vals']
        dom, uni, sc = summarize_run(r)
        dstride = dom[0]
        n_host = sum(1 for v in vals if in_host_pa_range(v))
        n_special = sum(1 for v in vals if in_special_range(v))
        r['dom_stride'] = dstride
        r['n_host'] = n_host
        r['n_special'] = n_special
        r['uni_strides'] = uni

        if n_special >= max(4, len(vals)//2):
            special.append(r)
        elif len(vals) >= 8 and dstride is not None and 0x1000 <= dstride <= 0x10000 and n_host >= 8:
            strong.append(r)
        elif len(vals) >= 8 and n_host >= 8:
            medium.append(r)
        else:
            others.append(r)

    print(f"[*] strong (len>=8, stride 0x1000-0x10000, host-PA): {len(strong)}", flush=True)
    print(f"[*] medium (len>=8, host-PA, any stride): {len(medium)}", flush=True)
    print(f"[*] special (0x6xxxxxxx/0x8xxxxxxx): {len(special)}", flush=True)
    print(f"[*] others: {len(others)}", flush=True)

    out = {'strong': strong, 'medium': medium, 'special': special, 'others': others}
    with open(os.path.join(D, 'vcpu_scan_results.json'), 'w') as f:
        json.dump(out, f, indent=1)

    # print details
    def pr(r):
        vals = r['vals']
        print(f"  {r['label']} off=0x{r['file_off']:x} guest_pa=0x{r['guest_pa']:x} len={r['run_len']} "
              f"dom_stride=0x{r['dom_stride']:x}" if r['dom_stride'] else f"  {r['label']} off=0x{r['file_off']:x} len={r['run_len']} stride=None")
        print(f"    strides={[hex(s) for s in r['uni_strides']]}")
        print(f"    vals={[hex(v) for v in vals[:16]]}")

    print("\n=== STRONG ===")
    for r in strong[:60]:
        pr(r)
    print("\n=== MEDIUM ===")
    for r in medium[:40]:
        pr(r)
    print("\n=== SPECIAL (0x6/0x8 range) ===")
    for r in special[:40]:
        pr(r)

if __name__ == '__main__':
    main()
