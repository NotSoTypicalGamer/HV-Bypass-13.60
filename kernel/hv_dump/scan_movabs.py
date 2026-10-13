import os, re
from collections import defaultdict
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
files = sorted(f for f in os.listdir(D) if f.startswith("hvcluster_") and f.endswith(".bin"))

def chunk_base(fn):
    m = re.search(r'hvcluster_([0-9a-fA-F]+)\.bin', fn)
    return int(m.group(1), 16)

md = Cs(CS_ARCH_X86, CS_MODE_64)
hexre = re.compile(r'0x[0-9a-fA-F]+')

movabs = defaultdict(lambda: [0, 0])
for fn in files:
    with open(os.path.join(D, fn), "rb") as f:
        data = f.read()
    base = chunk_base(fn)
    for ins in md.disasm(data, base):
        if ins.mnemonic in ("mov", "movabs"):
            m = hexre.findall(ins.op_str)
            if m:
                v = int(m[-1], 16)
                if v >= 0xFFFFFFFF:
                    d = movabs[v]; d[0] += 1
                    if d[1] == 0: d[1] = ins.address

print("distinct movabs imm64 (>=0xFFFFFFFF):", len(movabs))
print("\n--- all movabs imm64 with bit58 set (NDA masks / NDA entries) ---")
for v, (c, a) in sorted(((v, d) for v, d in movabs.items() if v & (1<<58)), key=lambda x: -x[1][0]):
    print(f"  0x{v:016x}  x{c}  first@0x{a:08x}")

print("\n--- movabs imm64 that look like NPT/PTE flags (low 12 bits nonzero, high 48 zero) ---")
for v, (c, a) in sorted(((v, d) for v, d in movabs.items() if (v >> 48) == 0 and (v & 0xFFF)), key=lambda x: -x[1][0]):
    flags = []
    if v & 0x1: flags.append("P")
    if v & 0x2: flags.append("RW")
    if v & 0x4: flags.append("US")
    if v & 0x8: flags.append("PWT")
    if v & 0x10: flags.append("PCD")
    if v & 0x20: flags.append("A")
    if v & 0x40: flags.append("D")
    if v & 0x80: flags.append("PS")
    if v & 0x100: flags.append("G")
    if v & 0x800: flags.append("NX11")
    if v & 0x40000000: flags.append("bit30")
    if v & 0x80000000: flags.append("bit31")
    print(f"  0x{v:012x}  x{c}  first@0x{a:08x}  [{'|'.join(flags)}]")

print("\n--- movabs imm64 = 0xFFFFFFFFFFFFFFFF and other common masks ---")
for v, (c, a) in sorted(((v, d) for v, d in movabs.items()), key=lambda x: -x[1][0])[:40]:
    print(f"  0x{v:016x}  x{c}  first@0x{a:08x}")
