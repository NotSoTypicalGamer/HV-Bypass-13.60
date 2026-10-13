import os, struct

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

# Broad ACPI-table-like structure scan.
# A valid table header: 4 printable sig chars, LE u32 length in [36,1MB],
# revision byte small, and (optionally) checksum over table == 0.
def is_sig(b0):
    return (0x41 <= b0 <= 0x5A)  # A-Z

def sigchar(b):
    return (0x41 <= b <= 0x5A) or (0x30 <= b <= 0x39) or b in (0x20, 0x5F, 0x21, 0x40)

cands = []
for base, size, path in ranges:
    with open(path, 'rb') as fh:
        d = fh.read()
    n = len(d)
    i = 0
    # byte-aligned scan with cheap rejection
    while i < n - 36:
        b0 = d[i]
        if 0x41 <= b0 <= 0x5A:
            if sigchar(d[i+1]) and sigchar(d[i+2]) and sigchar(d[i+3]):
                length = d[i+4] | (d[i+5] << 8) | (d[i+6] << 16) | (d[i+7] << 24)
                rev = d[i+8]
                if 36 <= length <= 0x100000 and rev <= 30 and i + length <= n:
                    sig = d[i:i+4].decode('ascii', 'replace')
                    cks = sum(d[i:i+length]) & 0xFF
                    pa = base + i
                    cands.append((pa, sig, length, rev, cks, os.path.basename(path)))
                    i += 4
                    continue
        i += 1

print("total table-like candidates:", len(cands))
print("(sig 4 printable, len in [36,1MB], rev<=30)")
valid = [c for c in cands if c[4] == 0]
print("candidates with valid (zero) checksum:", len(valid))
for pa, sig, length, rev, cks, path in valid:
    print(f"  VALID  0x{pa:016x}  {sig!r} len={length} rev={rev} cks=0x{cks:02x}  {path}")
# Show non-checksum candidates grouped, top 60
print("\nnon-zero-checksum candidates (first 80):")
shown = 0
for pa, sig, length, rev, cks, path in cands:
    if cks == 0:
        continue
    print(f"  0x{pa:016x}  {sig!r} len={length} rev={rev} cks=0x{cks:02x}  {path}")
    shown += 1
    if shown >= 80:
        break
