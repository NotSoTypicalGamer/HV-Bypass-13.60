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

pte_flag_ims = {1,2,3,4,0x20,0x21,0x22,0x23,0x25,0x27,0x63,0x67,0x83,0x87,0xa3,0xa7,0xe3,0xe7}
shr_levels = {9,12,21,30,39}
idx_masks = {0x1ff,0x3ff,0x7ff,0xfff,0xffe,0xfff8,0x3ffff,0x3fffe}

pte_writes = []   # (pa, mnemonic, op_str)
shifts = []
andmasks = []
or_smallmem = []

for fn in files:
    with open(os.path.join(D, fn), "rb") as f:
        data = f.read()
    base = chunk_base(fn)
    for ins in md.disasm(data, base):
        mn = ins.mnemonic
        os_ = ins.op_str
        m = hexre.findall(os_)
        if mn == "or" and m and ("ptr" in os_) and int(m[-1],16) in pte_flag_ims:
            pte_writes.append((ins.address, "or", os_))
        if mn == "mov" and m and "ptr" in os_ and len(m) >= 2 and int(m[-1],16) in pte_flag_ims:
            pte_writes.append((ins.address, "mov", os_))
        if mn == "shr" and m and int(m[-1],16) in shr_levels:
            shifts.append((ins.address, os_))
        if mn == "and" and m and int(m[-1],16) in idx_masks:
            andmasks.append((ins.address, os_))

def cluster(addr):
    return addr & ~0xFFFFF

print("=== or/mov [mem], PTE-flag-imm hits:", len(pte_writes), "===")
byc = defaultdict(list)
for pa, mn, os_ in pte_writes:
    byc[(cluster(pa), mn, os_)].append(pa)
for (c, mn, os_), pas in sorted(byc.items(), key=lambda kv: -len(kv[1]))[:60]:
    print(f"  chunk 0x{c:08x}  {mn} {os_:40s} x{len(pas)}  e.g. 0x{pas[0]:08x}")

print("\n=== shr {9,12,21,30,39} hits:", len(shifts), "===")
byc = defaultdict(list)
for pa, os_ in shifts:
    byc[(cluster(pa), os_)].append(pa)
for (c, os_), pas in sorted(byc.items(), key=lambda kv: -len(kv[1]))[:60]:
    print(f"  chunk 0x{c:08x}  shr {os_:40s} x{len(pas)}  e.g. 0x{pas[0]:08x}")

print("\n=== and index-mask hits:", len(andmasks), "===")
byc = defaultdict(list)
for pa, os_ in andmasks:
    byc[(cluster(pa), os_)].append(pa)
for (c, os_), pas in sorted(byc.items(), key=lambda kv: -len(kv[1]))[:60]:
    print(f"  chunk 0x{c:08x}  and {os_:40s} x{len(pas)}  e.g. 0x{pas[0]:08x}")
