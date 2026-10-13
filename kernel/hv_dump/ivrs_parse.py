import os, struct

DUMPDIR = r"C:/Users/USER/Caliper-C0re/kernel/hv_dump"

def build_ranges():
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
    return ranges

ranges = build_ranges()

# Known ACPI signatures (4-char)
KNOWN = set(b'DSDT SSDT FACP FACS APIC MCFG HPET WAET BGRT MADT XSDT RSDT SRAT SLIT CRAT CDIT IVRS DMAR HEST BERT ERST FPDT GTDT NFIT WSMT SPMI DBG2 UEFI SLIC MSDM BOOT TPM2 TCPA LITD ASF! S3PT'.split())

def read_at(pa, n):
    for base, size, path in ranges:
        if base <= pa < base + size:
            with open(path, 'rb') as fh:
                fh.seek(pa - base)
                return fh.read(n)
    return None

# Dump context around the DSDT / IVRS hits to understand what they are
interesting = {
    'DSDT': [0x15685f9c, 0x15c2f666, 0x2d493c8c, 0x2d681c94, 0x30447f58],
    'SSDT': [0x159bca3a, 0x2d42d5d5, 0x2d696cca],
    'IVRS': [0x3478ae37, 0x4408b369, 0x4408b3f0, 0x3f879db5],
}
for sig, pas in interesting.items():
    for pa in pas:
        data = read_at(pa - 16, 64)
        print(f"=== {sig} @ 0x{pa:016x} (ctx from -16) ===")
        if data:
            print(data.hex(' '))
            print(repr(data))
        else:
            print("  (not in any range)")

print("\n\n=== validated ACPI table header scan (checksum + length sanity) ===")
# Scan every range for 4-byte-aligned potential table headers whose sig is known,
# length plausible, and checksum zero.
found = []
for base, size, path in ranges:
    with open(path, 'rb') as fh:
        data = fh.read()
    n = len(data)
    i = 0
    while i < n - 36:
        # Only scan at 16-byte alignment to keep it fast, then relax to 4
        i += 16
    # reset to 4-byte alignment scan
    for i in range(0, n - 36, 4):
        sig = data[i:i+4]
        if sig not in KNOWN:
            continue
        length = struct.unpack_from('<I', data, i+4)[0]
        if length < 36 or length > 0x100000:
            continue
        if i + length > n:
            continue
        # checksum
        s = sum(data[i:i+length]) & 0xFF
        if s == 0:
            rev = data[i+8]
            oemid = data[i+10:i+16]
            oemtid = data[i+16:i+24]
            found.append((base+i, sig.decode(), length, rev, oemid, oemtid, path))

print("valid tables found:", len(found))
for pa, sig, ln, rev, oemid, oemtid, path in found:
    print(f"  0x{pa:016x}  {sig} len={ln} rev={rev} oem={oemid!r} oemtbl={oemtid!r}  {os.path.basename(path)}")
