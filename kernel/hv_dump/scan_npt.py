import os, re, struct, json
from collections import defaultdict

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
files = sorted(f for f in os.listdir(D) if f.startswith("hvcluster_") and f.endswith(".bin"))

def chunk_base(fn):
    m = re.search(r'hvcluster_([0-9a-fA-F]+)\.bin', fn)
    return int(m.group(1), 16)

# 8-byte LE immediates to hunt
IMM58 = struct.pack("<Q", 0x0400000000000000)   # bit 58 (NDA / xotext)
IMM63 = struct.pack("<Q", 0x8000000000000000)   # bit 63 (NX)
PAGEMASK = struct.pack("<Q", 0x000FFFFFFFFFF000) # page mask

bts58 = []      # (pa, )  bts/btc/btr imm8==58
bt58  = []      # bt imm8==58
bts63 = []
bts11 = []
imm58 = []      # 8-byte imm with bit58
imm63 = []
pagemask = []

def scan(data, base):
    n = len(data)
    i = 0
    while i < n - 3:
        b = data[i]
        # 0F BA group (bts/btr/btc r/m, imm8): 0F BA /r imm8 ; 0F A3 (bt)
        if b == 0x0F:
            nxt = data[i+1]
            if nxt in (0xBA, 0xA3) and i + 4 <= n:
                modrm = data[i+2]
                reg = (modrm >> 3) & 7
                imm = data[i+3]
                if nxt == 0xBA:   # bts=5 btr=6 btc=7
                    op = {5:"bts",6:"btr",7:"btc"}.get(reg)
                else:             # 0F A3 = bt (reg=4)
                    op = "bt" if reg == 4 else None
                if op and imm == 58:
                    bts58.append((base + i, op))
                elif op and imm == 63:
                    bts63.append((base + i, op))
                elif op and imm == 11:
                    bts11.append((base + i, op))
        i += 1
    # 8-byte immediates (bit patterns)
    for pat, lst, tag in ((IMM58, imm58, "imm58"), (IMM63, imm63, "imm63"), (PAGEMASK, pagemask, "pagemask")):
        off = data.find(pat)
        while off != -1:
            lst.append((base + off, tag))
            off = data.find(pat, off + 1)

total = 0
for fn in files:
    with open(os.path.join(D, fn), "rb") as f:
        data = f.read()
    base = chunk_base(fn)
    scan(data, base)

def summarize(lst, name):
    print(f"\n=== {name}: {len(lst)} hits ===")
    if not lst:
        return
    # cluster by 1MB chunk
    bychunk = defaultdict(int)
    for pa, *rest in lst:
        bychunk[pa & ~0xFFFFF] += 1
    for c, cnt in sorted(bychunk.items(), key=lambda kv: -kv[1])[:50]:
        print(f"  chunk 0x{c:08x}: {cnt}")

summarize(bts58, "bts/btr/btc imm58 (NDA/xotext)")
summarize(bts63, "bts/btr/btc imm63 (NX)")
summarize(bts11, "bts/btr/btc imm11 (NX-low)")
summarize(imm58, "8-byte imm with bit58 set")
summarize(imm63, "8-byte imm with bit63 set")
summarize(pagemask, "pagemask 0x000FFFFFFFFFF000")

# dump exact addresses for the rare/important ones
out = {"bts58": bts58, "bts63": bts63, "bts11": bts11, "imm58": imm58, "imm63": imm63, "pagemask": pagemask}
with open(os.path.join(D, "scan_npt_out.json"), "w") as f:
    json.dump(out, f)
print("\nwrote scan_npt_out.json")
print("\n--- sample bts58 exact addresses (first 60) ---")
for pa, op in bts58[:60]:
    print(f"  0x{pa:08x} {op}")
