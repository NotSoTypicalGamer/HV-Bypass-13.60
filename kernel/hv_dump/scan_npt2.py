import os, re, struct
from collections import defaultdict
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
files = sorted(f for f in os.listdir(D) if f.startswith("hvcluster_") and f.endswith(".bin"))

def chunk_base(fn):
    m = re.search(r'hvcluster_([0-9a-fA-F]+)\.bin', fn)
    return int(m.group(1), 16)

md = Cs(CS_ARCH_X86, CS_MODE_64)  # no detail for speed

# collect distinct immediates for various classes
movabs_imm = defaultdict(lambda: [0, 0])   # imm -> [count, first_addr]
orimm = defaultdict(lambda: [0, 0])
andimm = defaultdict(lambda: [0, 0])
xorimm = defaultdict(lambda: [0, 0])
btsimm = defaultdict(lambda: [0, 0])
testimm = defaultdict(lambda: [0, 0])
cmpimm = defaultdict(lambda: [0, 0])

# also record full instruction text for bts/bt and bit-58/63 movabs
interesting = []

def is_imm(op):
    return op.type == 2  # X86_OP_IMM

for fn in files:
    with open(os.path.join(D, fn), "rb") as f:
        data = f.read()
    base = chunk_base(fn)
    for ins in md.disasm(data, base):
        mn = ins.mnemonic
        ops = ins.operands
        if mn == "mov" and len(ops) == 2 and is_imm(ops[1]) and ops[0].type == 1:  # reg, imm
            v = ops[1].imm
            if v >= 0xFFFFFFFF or (v & 0xFFF0000000000000):  # large imm => movabs
                d = movabs_imm[v]
                d[0] += 1
                if d[1] == 0: d[1] = ins.address
        elif mn == "movabs" and len(ops) == 2 and is_imm(ops[1]):
            v = ops[1].imm
            d = movabs_imm[v]
            d[0] += 1
            if d[1] == 0: d[1] = ins.address
        elif mn in ("bts", "btr", "btc", "bt") and len(ops) == 2 and is_imm(ops[1]):
            v = ops[1].imm
            d = btsimm[v]
            d[0] += 1
            if d[1] == 0: d[1] = ins.address
            if v in (58, 63, 11, 7, 6, 5, 1, 0):
                interesting.append((ins.address, "%s %s" % (mn, ins.op_str)))
        elif mn == "or" and len(ops) == 2 and is_imm(ops[1]):
            v = ops[1].imm
            d = orimm[v]
            d[0] += 1
            if d[1] == 0: d[1] = ins.address
        elif mn == "and" and len(ops) == 2 and is_imm(ops[1]):
            v = ops[1].imm
            d = andimm[v]
            d[0] += 1
            if d[1] == 0: d[1] = ins.address
        elif mn == "xor" and len(ops) == 2 and is_imm(ops[1]):
            v = ops[1].imm
            d = xorimm[v]
            d[0] += 1
            if d[1] == 0: d[1] = ins.address
        elif mn == "test" and len(ops) == 2 and is_imm(ops[1]):
            v = ops[1].imm
            d = testimm[v]
            d[0] += 1
            if d[1] == 0: d[1] = ins.address
        elif mn == "cmp" and len(ops) == 2 and is_imm(ops[1]):
            v = ops[1].imm
            d = cmpimm[v]
            d[0] += 1
            if d[1] == 0: d[1] = ins.address

def dump(d, name, lo=0x20, topn=60):
    print(f"\n===== {name} (distinct immediates, value>=0x{lo:x}) =====")
    items = sorted(((v, c) for v, (c, a) in d.items() if v >= lo), key=lambda x: -x[1])
    for v, c in items[:topn]:
        print(f"  0x{v:016x}  x{c}   first@0x{d[v][1]:08x}")

# PTEs: values with present bit (bit0) set and phys-addr-like high bits
def is_pte_like(v):
    return (v & 1) and (v & 0xFFFFFFFFFFFFF000)

print("=== PTE-LIKE movabs immediates (bit0 set + high phys bits) ===")
pte_vals = sorted(((v, c, a) for v, (c, a) in movabs_imm.items() if is_pte_like(v)), key=lambda x: -x[1])
for v, c, a in pte_vals[:80]:
    # decode flags
    flags = []
    if v & 0x2: flags.append("RW")
    if v & 0x4: flags.append("US")
    if v & 0x20: flags.append("A")
    if v & 0x40: flags.append("D")
    if v & 0x80: flags.append("PS")
    if v & 0x800: flags.append("NX(11)")
    if v & (1<<58): flags.append("NDA(58)")
    if v & (1<<63): flags.append("NX(63)")
    print(f"  0x{v:016x} x{c} first@0x{a:08x}  [{','.join(flags)}]")

dump(orimm, "or imm", lo=0x20)
dump(andimm, "and imm", lo=0x100)
dump(btsimm, "bts/btr/btc/bt imm", lo=0)
dump(testimm, "test imm", lo=0x100)

print("\n=== interesting bts/bt instructions (bits 0/1/5/6/7/11/58/63) ===")
for addr, txt in interesting[:100]:
    print(f"  0x{addr:08x} {txt}")

with open(os.path.join(D, "scan_npt2_interesting.txt"), "w") as f:
    for addr, txt in interesting:
        f.write("0x%08x %s\n" % (addr, txt))
print("\nwrote scan_npt2_interesting.txt (%d lines)" % len(interesting))
