import os
import numpy as np

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
CONTIG = "hvdump_0x26000000_600MB.bin"
CONTIG_BASE = 0x26000000

data = np.fromfile(os.path.join(D, CONTIG), dtype='<u8')
BASE = CONTIG_BASE

# 16-entry aligned arrays (candidate VCPU) in host-PA range
locs = [0x37d17200, 0x38ea9e00, 0x3e018a00, 0x4b1e8000, 0x1d265e00, 0x346fca00, 0x40ef9400]

for gpa in locs:
    if gpa < CONTIG_BASE or gpa > CONTIG_BASE + len(data)*8:
        print(f"--- guest_pa 0x{gpa:x} NOT in contiguous dump ---")
        continue
    idx = (gpa - CONTIG_BASE)//8
    print(f"\n=== guest_pa 0x{gpa:x} (u64 idx {idx}) context ===")
    for k in range(idx-6, idx+22):
        if 0 <= k < len(data):
            marker = " <-- ARRAY" if k == idx else ""
            print(f"  gpa 0x{CONTIG_BASE+k*8:08x}: 0x{int(data[k]):016x}{marker}")

# check for any string magic 'SVM'/VMCB-like near these
print("\n=== ASCII dump around 0x37d17200 ===")
raw = open(os.path.join(D, CONTIG), 'rb').read()
off = 0x37d17200 - CONTIG_BASE
for i in range(off-64, off+64, 16):
    c = raw[i:i+16]
    print(f"  0x{CONTIG_BASE+i:08x}: {' '.join('%02x'%b for b in c)}  {''.join(chr(b) if 0x20<=b<0x7f else '.' for b in c)}")
