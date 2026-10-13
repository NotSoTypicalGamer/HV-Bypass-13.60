import os, re, struct
from collections import defaultdict

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
files = sorted(f for f in os.listdir(D) if f.startswith("hvcluster_") and f.endswith(".bin"))

def chunk_base(fn):
    m = re.search(r'hvcluster_([0-9a-fA-F]+)\.bin', fn)
    return int(m.group(1), 16)

# analyze 8-byte-ALIGNED qwords that look like NPT/PTE entries
pte_like = defaultdict(list)      # (flags profile) -> [qword values]
nda_hits = []                     # entries with bit58 set
present_hits = []                 # entries with bit0 set
total_qw = 0
present_qw = 0

for fn in files:
    with open(os.path.join(D, fn), "rb") as f:
        data = f.read()
    base = chunk_base(fn)
    n = len(data)
    for off in range(0, n, 8):
        q = struct.unpack_from("<Q", data, off)[0]
        total_qw += 1
        if q == 0:
            continue
        if q & 1:  # present
            present_qw += 1
            present_hits.append((base + off, q))
        if q & (1 << 58):
            nda_hits.append((base + off, q))

print("total aligned qwords:", total_qw)
print("present (bit0) aligned qwords:", present_qw)

# classify present entries by their flag bits
def flagstr(q):
    f = []
    if q & 0x2: f.append("RW")
    if q & 0x4: f.append("US")
    if q & 0x8: f.append("PWT")
    if q & 0x10: f.append("PCD")
    if q & 0x20: f.append("A")
    if q & 0x40: f.append("D")
    if q & 0x80: f.append("PS")
    if q & 0x100: f.append("G")
    if q & 0x800: f.append("NX11")
    if q & (1<<58): f.append("NDA58")
    if q & (1<<59): f.append("NXS59")
    if q & (1<<63): f.append("NX63")
    return "|".join(f) if f else "P"

profiles = defaultdict(lambda: [0, 0])  # flagstr -> [count, first_q]
for pa, q in present_hits:
    fs = flagstr(q)
    d = profiles[fs]
    d[0] += 1
    if d[1] == 0: d[1] = q

print("\npresent-entry flag profiles (flagstr: count):")
for fs, (c, fq) in sorted(profiles.items(), key=lambda kv: -kv[1][0]):
    print(f"  [{fs:30s}] x{c}  example=0x{fq:016x}")

print("\nentries with bit58 (NDA) set:", len(nda_hits))
for pa, q in nda_hits[:20]:
    print(f"  0x{pa:08x}  0x{q:016x}  [{flagstr(q)}]")
