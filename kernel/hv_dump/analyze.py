import glob, os, sys
from collections import Counter

files = sorted(glob.glob('hvcluster_*.bin'), key=lambda f:int(os.path.basename(f)[10:-4],16))

align4k = Counter()
align4k_region = Counter()
movabs_total = 0
chunk_movabs = {}

for f in files:
    gpa = int(os.path.basename(f)[10:-4],16)
    d = open(f,'rb').read()
    n=0
    for i in range(len(d)-9):
        if d[i]==0x48 and 0xB8 <= d[i+1] <= 0xBF:
            imm = int.from_bytes(d[i+2:i+10],'little')
            movabs_total += 1
            n += 1
            if (imm & 0xfff) == 0:
                align4k[imm]+=1
                if 0x60000000 <= imm < 0x70000000:
                    align4k_region[imm]+=1
    chunk_movabs[gpa]=n

print("total movabs r64,imm64 candidates:", movabs_total)
print("distinct 4KB-aligned imm values:", len(align4k))
print()
print("=== 4KB-aligned movabs immediates in 0x60000000..0x70000000 (HV carve-out) ===")
for imm,c in sorted(align4k_region.items()):
    print("  0x%08x  x%d" % (imm,c))
print()
print("=== top 60 4KB-aligned movabs immediates (any range) ===")
for imm,c in align4k.most_common(60):
    print("  0x%012x  x%d" % (imm,c))
print()
print("=== movabs count per chunk (top 30) ===")
for gpa,c in sorted(chunk_movabs.items(), key=lambda kv:-kv[1])[:30]:
    print("  0x%08x  movabs=%d" % (gpa,c))
