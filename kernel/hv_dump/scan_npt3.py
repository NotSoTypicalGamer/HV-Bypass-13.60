import os, re
from collections import defaultdict
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
files = sorted(f for f in os.listdir(D) if f.startswith("hvcluster_") and f.endswith(".bin"))

def chunk_base(fn):
    m = re.search(r'hvcluster_([0-9a-fA-F]+)\.bin', fn)
    return int(m.group(1), 16)

md = Cs(CS_ARCH_X86, CS_MODE_64)

movabs_imm = defaultdict(lambda: [0, 0])
orimm = defaultdict(lambda: [0, 0])
andimm = defaultdict(lambda: [0, 0])
btsimm = defaultdict(lambda: [0, 0])
testimm = defaultdict(lambda: [0, 0])
cmpimm = defaultdict(lambda: [0, 0])
interesting = []

hexre = re.compile(r'0x[0-9a-fA-F]+')

def last_imm(op_str):
    m = hexre.findall(op_str)
    if m:
        return int(m[-1], 16)
    return None

for fn in files:
    with open(os.path.join(D, fn), "rb") as f:
        data = f.read()
    base = chunk_base(fn)
    for ins in md.disasm(data, base):
        mn = ins.mnemonic
        os_ = ins.op_str
        if mn in ("mov", "movabs"):
            v = last_imm(os_)
            if v is not None and v >= 0xFFFFFFFF:
                d = movabs_imm[v]
                d[0] += 1
                if d[1] == 0: d[1] = ins.address
        elif mn in ("bts", "btr", "btc", "bt"):
            v = last_imm(os_)
            if v is not None:
                d = btsimm[v]; d[0] += 1
                if d[1] == 0: d[1] = ins.address
                if v in (0,1,2,5,6,7,11,58,63):
                    interesting.append((ins.address, "%s %s" % (mn, os_)))
        elif mn == "or":
            v = last_imm(os_)
            if v is not None:
                d = orimm[v]; d[0] += 1
                if d[1] == 0: d[1] = ins.address
        elif mn == "and":
            v = last_imm(os_)
            if v is not None:
                d = andimm[v]; d[0] += 1
                if d[1] == 0: d[1] = ins.address
        elif mn == "test":
            v = last_imm(os_)
            if v is not None:
                d = testimm[v]; d[0] += 1
                if d[1] == 0: d[1] = ins.address
        elif mn == "cmp":
            v = last_imm(os_)
            if v is not None:
                d = cmpimm[v]; d[0] += 1
                if d[1] == 0: d[1] = ins.address

def dump(d, name, lo=0x20, topn=60):
    print(f"\n===== {name} (value>=0x{lo:x}) =====")
    items = sorted(((v, c) for v, (c, a) in d.items() if v >= lo), key=lambda x: -x[1])
    for v, c in items[:topn]:
        print(f"  0x{v:016x}  x{c}   first@0x{d[v][1]:08x}")

def is_pte_like(v):
    return (v & 1) and (v & 0xFFFFFFFFFFFFF000)

print("=== PTE-LIKE movabs immediates (bit0 set + phys bits) ===")
pte_vals = sorted(((v, c, a) for v, (c, a) in movabs_imm.items() if is_pte_like(v)), key=lambda x: -x[1])
for v, c, a in pte_vals[:80]:
    flags = []
    if v & 0x2: flags.append("RW")
    if v & 0x4: flags.append("US")
    if v & 0x20: flags.append("A")
    if v & 0x40: flags.append("D")
    if v & 0x80: flags.append("PS")
    if v & 0x800: flags.append("NX11")
    if v & (1<<58): flags.append("NDA58")
    if v & (1<<63): flags.append("NX63")
    print(f"  0x{v:016x} x{c} first@0x{a:08x}  [{','.join(flags)}]")

dump(orimm, "or imm", lo=0x20)
dump(andimm, "and imm", lo=0x100)
dump(btsimm, "bts/btr/btc/bt imm", lo=0)
dump(testimm, "test imm", lo=0x100)
dump(cmpimm, "cmp imm", lo=0x100)

print("\n=== interesting bts/bt instructions (bits 0/1/2/5/6/7/11/58/63) ===")
for addr, txt in interesting[:120]:
    print(f"  0x{addr:08x} {txt}")

with open(os.path.join(D, "scan_npt2_interesting.txt"), "w") as f:
    for addr, txt in interesting:
        f.write("0x%08x %s\n" % (addr, txt))
print("\nwrote scan_npt2_interesting.txt (%d lines)" % len(interesting))
