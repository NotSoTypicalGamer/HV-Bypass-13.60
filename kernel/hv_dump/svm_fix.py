import glob, os
from collections import Counter

files = sorted(glob.glob('hvcluster_*.bin'), key=lambda f:int(os.path.basename(f)[10:-4],16))

# Correct SVM scan: bytes 0f 01 followed by opcode D8..DF
def svm_hits(d):
    n=0
    for i in range(len(d)-2):
        if d[i]==0x0f and d[i+1]==0x01 and (d[i+2] & 0xf8)==0xd8:
            n+=1
    return n

total=0
hist=Counter()
for f in files:
    gpa=int(os.path.basename(f)[10:-4],16)
    d=open(f,'rb').read()
    h=svm_hits(d)
    total+=h
    hist[h]+=1
print("=== distribution of SVM hits per chunk (correct scan) ===")
for h in sorted(hist):
    print("  %2d hits: %d chunks" % (h, hist[h]))
print("total SVM hits:", total)
print()
# chunks with >=3 hits (should match the 186 dumped if threshold is >=3)
dense=[gpa for gpa in [int(os.path.basename(f)[10:-4],16) for f in files]]
dense=[gpa for gpa in dense if svm_hits(open('hvcluster_%08x.bin'%gpa,'rb').read())>=3]
print("chunks with >=3 hits:", len(dense))
print("chunks with >=10 hits:")
for gpa in dense:
    h=svm_hits(open('hvcluster_%08x.bin'%gpa,'rb').read())
    if h>=10:
        print("  0x%08x  %d hits" % (gpa,h))
