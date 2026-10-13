import os, struct, sys

DUMPDIR = r"C:/Users/USER/Caliper-C0re/kernel/hv_dump"

# Build list of (base, size, path) for every non-empty .bin
ranges = []
for f in sorted(os.listdir(DUMPDIR)):
    if not f.endswith('.bin'):
        continue
    path = os.path.join(DUMPDIR, f)
    size = os.path.getsize(path)
    if size == 0:
        continue
    if f.startswith('hvcluster_'):
        hexstr = f[len('hvcluster_'):-len('.bin')]
        base = int(hexstr, 16)
    elif f.startswith('hvdump_'):
        base = 0x26000000
    else:
        continue
    ranges.append((base, size, path))

ranges.sort()
total = sum(s for _, s, _ in ranges)
print("Total ranges:", len(ranges), "total bytes:", total, hex(total))

sigs = [b'RSD PTR ', b'XSDT', b'RSDT', b'IVRS', b'IVHD', b'FACP', b'DSDT',
        b'SSDT', b'MADT', b'APIC', b'FACS', b'MCFG', b'BGRT', b'HPET',
        b'WAET', b'CRAT', b'CDIT', b'SRAT', b'SLIT', b'DMAR', b'HEST',
        b'BERT', b'ERST', b'FPDT', b'GTDT', b'NFIT', b'WSMT', b'SPMI',
        b'UEFI', b'BOOT', b'DBG2', b'SLIC', b'MSDM']

hits = {}
for base, size, path in ranges:
    with open(path, 'rb') as fh:
        data = fh.read()
    for sig in sigs:
        start = 0
        while True:
            idx = data.find(sig, start)
            if idx < 0:
                break
            pa = base + idx
            hits.setdefault(sig, []).append((pa, path))
            start = idx + 1

for sig in sigs:
    h = hits.get(sig, [])
    if not h:
        continue
    print(f"\n{sig!r}: {len(h)} hit(s)")
    for pa, path in h[:100]:
        print(f"   0x{pa:016x}  {os.path.basename(path)}")

print("\nDONE")
