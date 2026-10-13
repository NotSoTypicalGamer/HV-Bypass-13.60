import os, re
import numpy as np

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"

def base_of(f):
    return int(re.match(r'hvcluster_([0-9a-f]+)\.bin', f).group(1), 16)

files = sorted((f for f in os.listdir(D)
                if f.startswith("hvcluster_") and f.endswith(".bin")
                and base_of(f) >= 0x100000000), key=base_of)

for f in files[:8]:
    b = base_of(f)
    arr = np.fromfile(os.path.join(D, f), dtype='<u8')
    nz = arr[arr != 0]
    print(f"{f} base=0x{b:x} len={len(arr)} nonzero={len(nz)}")
    if len(nz):
        print(f"   min=0x{int(nz.min()):x} max=0x{int(nz.max()):x}")
        uniq, cnt = np.unique(nz, return_counts=True)
        top = np.argsort(-cnt)[:6]
        for i in top:
            print(f"   val=0x{int(uniq[i]):x} x{cnt[i]}")

total = 0
totalnz = 0
for f in files:
    arr = np.fromfile(os.path.join(D, f), dtype='<u8')
    total += len(arr)
    totalnz += int(np.count_nonzero(arr))
print(f"\nTOTAL qwords={total} nonzero={totalnz} ({100.0*totalnz/total:.3f}%)")
