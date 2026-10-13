import os, re
from collections import defaultdict
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"

def chunk_base(fn):
    m = re.search(r'hvcluster_([0-9a-fA-F]+)\.bin', fn)
    return int(m.group(1), 16)

files = sorted(f for f in os.listdir(D) if f.startswith("hvcluster_") and f.endswith(".bin"))
md = Cs(CS_ARCH_X86, CS_MODE_64)

# 1) BMI / alternate shifts
alt = defaultdict(list)
for fn in files:
    with open(os.path.join(D, fn), "rb") as f:
        data = f.read()
    base = chunk_base(fn)
    for ins in md.disasm(data, base):
        if ins.mnemonic in ("shrx","shlx","bzhi","sarx","bt","bts","btr","btc","andn"):
            alt[ins.mnemonic].append((ins.address, ins.op_str))
for mn in sorted(alt):
    print(f"{mn}: {len(alt[mn])} hits")
    for pa, os_ in alt[mn][:8]:
        print(f"   0x{pa:08x} {mn} {os_}")

# 2) inspect the 27-identical-chunks content
rep_bases = [0x2e500000,0x34900000,0x39e00000,0x3af00000,0x3d900000,0x3df00000,0x3ee00000,0x3ef00000,0x3f600000,0x3f700000,0x40300000,0x40700000,0x42800000,0x43a00000,0x43b00000,0x43c00000,0x43e00000,0x4c600000,0x4cc00000,0x4d500000,0x4da00000,0x4eb00000,0x50d00000,0x55f00000,0x57600000,0x5a400000,0x5ff00000]
with open(os.path.join(D, "hvcluster_%08x.bin" % rep_bases[0]), "rb") as f:
    d = f.read()
nz = sum(1 for b in d if b != 0)
print("\nidentical-chunk content: nonzero bytes = %d / %d (%.1f%%)" % (nz, len(d), 100*nz/len(d)))
# first 64 nonzero bytes + their offsets
off = 0
print("first 48 nonzero byte positions:")
for i, b in enumerate(d):
    if b != 0:
        print("   +0x%06x: 0x%02x" % (i, b))
        off += 1
        if off >= 48: break
# disassemble the first 0x200 bytes
print("\ndisasm of identical-chunk head (0x200 bytes):")
for ins in md.disasm(d[:0x200], rep_bases[0]):
    print(f"  0x{ins.address:08x}: {ins.mnemonic:7s} {ins.op_str}")
