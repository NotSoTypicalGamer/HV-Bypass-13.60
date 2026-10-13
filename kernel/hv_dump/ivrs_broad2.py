import os, re, struct

DUMPDIR = r"C:/Users/USER/Caliper-C0re/kernel/hv_dump"

ranges = []
for f in sorted(os.listdir(DUMPDIR)):
    if not f.endswith('.bin'):
        continue
    path = os.path.join(DUMPDIR, f)
    size = os.path.getsize(path)
    if size == 0:
        continue
    if f.startswith('hvcluster_'):
        base = int(f[len('hvcluster_'):-4], 16)
    elif f.startswith('hvdump_'):
        base = 0x26000000
    else:
        continue
    ranges.append((base, size, path))
ranges.sort()

pat = re.compile(rb'[A-Z][A-Z0-9_ ]{3}')
valid = []
others = []
for base, size, path in ranges:
    with open(path, 'rb') as fh:
        d = fh.read()
    n = len(d)
    for m in pat.finditer(d):
        i = m.start()
        if i + 36 > n:
            continue
        length = d[i+4] | (d[i+5] << 8) | (d[i+6] << 16) | (d[i+7] << 24)
        rev = d[i+8]
        if not (36 <= length <= 0x100000 and rev <= 30 and i + length <= n):
            continue
        sig = d[i:i+4].decode('ascii', 'replace')
        cks = sum(d[i:i+length]) & 0xFF
        pa = base + i
        entry = (pa, sig, length, rev, cks, os.path.basename(path))
        (valid if cks == 0 else others).append(entry)

print("VALID (checksum==0) table-like structures:", len(valid))
for pa, sig, length, rev, cks, path in valid:
    print(f"  0x{pa:016x}  {sig!r} len={length} rev={rev}  {path}")

print("\nnon-zero-checksum candidates (sig+len+rev plausible):", len(others))
for pa, sig, length, rev, cks, path in others[:100]:
    print(f"  0x{pa:016x}  {sig!r} len={length} rev={rev} cks=0x{cks:02x}  {path}")
