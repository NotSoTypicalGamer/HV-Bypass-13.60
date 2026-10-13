import os, json
import numpy as np
from collections import Counter, defaultdict

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
CONTIG = "hvdump_0x26000000_600MB.bin"
CONTIG_BASE = 0x26000000

res = json.load(open(os.path.join(D, 'vcpu_periodic.json')))

# distribution by (period, run_len)
c = Counter((r['period'], r['run_len']) for r in res)
print("=== (period, run_len) distribution ===")
for (p, L), n in sorted(c.items()):
    print(f"  period={p:3d} len={L:3d}: {n}")

# exactly 16 and 8
print("\n=== len==16 arrays ===")
for r in res:
    if r['run_len'] == 16:
        print(f"  {r['label']} guest_pa=0x{r['guest_pa']:x} period={r['period']} col={r['col']} stride=0x{r['stride']:x}")
        print(f"    vals={[hex(v) for v in r['vals']]}")

print("\n=== len==8 arrays ===")
for r in res:
    if r['run_len'] == 8:
        print(f"  {r['label']} guest_pa=0x{r['guest_pa']:x} period={r['period']} col={r['col']} stride=0x{r['stride']:x}")
        print(f"    vals={[hex(v) for v in r['vals']]}")

# dump one period=24 structure in full (24-byte entries)
print("\n=== full 24-byte entries at a period=24 col=0 location (0x3f0004e8) ===")
data = np.fromfile(os.path.join(D, CONTIG), dtype='<u8')
off = 0x3f0004e8 - CONTIG_BASE
idx = off // 8
for k in range(20):
    i = idx + k*3  # period 24 = 3 u64
    if i+2 < len(data):
        print(f"  entry[{k}] @guest_pa 0x{CONTIG_BASE+i*8:x}: [0]=0x{int(data[i]):x} [1]=0x{int(data[i+1]):x} [2]=0x{int(data[i+2]):x}")
