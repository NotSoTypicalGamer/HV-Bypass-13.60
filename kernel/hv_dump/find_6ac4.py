import glob, os
import numpy as np

files = sorted(glob.glob('hvcluster_*.bin'), key=lambda f:int(os.path.basename(f)[10:-4],16))

# find 0x6AC41D70 (and neighbors) as 4-byte LE values in the chunks, with context
targets = [0x6AC41D70, 0x6AC4160B, 0x6AC41AAE, 0x6AC41D71]

for f in files:
    gpa = int(os.path.basename(f)[10:-4],16)
    d = open(f,'rb').read()
    a32 = np.frombuffer(d, dtype='<u4')
    for t in targets:
        idx = np.where(a32 == t)[0]
        for i in idx[:3]:
            off = int(i)*4
            print("0x%08x chunk: value 0x%08x at +0x%x  ctx=%s" % (gpa, t, off, d[off-8:off+16].hex(' ')))
