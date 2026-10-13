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

shlshr = defaultdict(list)
or_reg_pte = defaultdict(list)
movcr = []
rep_stosq = []
ltr_lidt = []

for fn in files:
    with open(os.path.join(D, fn), "rb") as f:
        data = f.read()
    base = chunk_base(fn)
    for ins in md.disasm(data, base):
        mn = ins.mnemonic
        os_ = ins.op_str
        m = hexre.findall(os_)
        if mn in ("shl","shr") and m:
            v = int(m[-1],16)
            if v in (9,12,21,30,39,24,18,6,3):
                shlshr[(mn,v)].append((ins.address, os_))
        if mn == "or" and m and int(m[-1],16) in (0x63,0x67,0x27,0x23,0x3,0x83,0x87,0xa3,0xe3):
            or_reg_pte[int(m[-1],16)].append((ins.address, os_))
        if mn == "mov" and ("cr3" in os_ or "cr4" in os_ or "cr0" in os_):
            movcr.append((ins.address, os_))
        if mn == "stosq" or mn == "stosd":
            rep_stosq.append((ins.address, os_))

print("=== shl/shr by {9,12,21,30,39,24,18,6,3} ===")
for k in sorted(shlshr):
    lst = shlshr[k]
    byc = defaultdict(int)
    for pa,_ in lst: byc[pa & ~0xFFFFF] += 1
    print(f"  {k[0]} {k[1]}: {len(lst)} hits in {len(byc)} chunks")
    for pa, os_ in lst[:12]:
        print(f"       0x{pa:08x} {os_}")

print("\n=== or reg, PTE-flag (0x63/0x67/0x27/0x23/0x3/0x83/0x87/0xa3/0xe3) ===")
for v in sorted(or_reg_pte):
    lst = or_reg_pte[v]
    byc = defaultdict(int)
    for pa,_ in lst: byc[pa & ~0xFFFFF] += 1
    print(f"  0x{v:x}: {len(lst)} hits in {len(byc)} chunks")
    for pa, os_ in lst[:8]:
        print(f"       0x{pa:08x} {os_}")

print("\n=== mov cr0/cr3/cr4 ===")
for pa, os_ in movcr[:30]:
    print(f"  0x{pa:08x} {os_}")

print("\n=== stosq/stosd (page zeroing) ===")
byc = defaultdict(int)
for pa,_ in rep_stosq: byc[pa & ~0xFFFFF] += 1
print(f"  {len(rep_stosq)} hits in {len(byc)} chunks")
for pa, os_ in rep_stosq[:15]:
    print(f"  0x{pa:08x} {os_}")
