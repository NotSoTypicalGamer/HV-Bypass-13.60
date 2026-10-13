import os, re
from collections import defaultdict

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
files = sorted(f for f in os.listdir(D) if f.startswith("hvcluster_") and f.endswith(".bin"))

def chunk_base(fn):
    m = re.search(r'hvcluster_([0-9a-fA-F]+)\.bin', fn)
    return int(m.group(1), 16)

# SVM opcodes: 0F 01 D8..DF
svm_ops = {0xD8:"vmrun",0xD9:"vmmcall",0xDA:"vmsave",0xDB:"vmload",0xDC:"stgi",0xDD:"clgi",0xDE:"invlpga",0xDF:"skinit"}

svm_hits = []   # (pa, name)
bychunk = defaultdict(int)
for fn in files:
    with open(os.path.join(D, fn), "rb") as f:
        data = f.read()
    base = chunk_base(fn)
    n = len(data)
    i = 0
    while i < n - 2:
        if data[i] == 0x0F and data[i+1] == 0x01 and data[i+2] in svm_ops:
            svm_hits.append((base + i, svm_ops[data[i+2]]))
            bychunk[base] += 1
            i += 3
        else:
            i += 1

print("total SVM hits:", len(svm_hits))
print("\nper-chunk SVM density (chunk: count):")
for c, cnt in sorted(bychunk.items(), key=lambda kv: -kv[1]):
    print(f"  0x{c:08x}: {cnt}")

# list all hits sorted
print("\nall SVM instruction addresses:")
for pa, name in sorted(svm_hits):
    print(f"  0x{pa:08x} {name}")
