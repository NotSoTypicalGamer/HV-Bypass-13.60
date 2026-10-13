import glob, os
from iced_x86 import Decoder, Mnemonic, Code
from collections import Counter

files = sorted(glob.glob('hvcluster_*.bin'), key=lambda f:int(os.path.basename(f)[10:-4],16))

SVM = {Mnemonic.VMRUN, Mnemonic.VMCALL, Mnemonic.VMLOAD, Mnemonic.VMSAVE,
       Mnemonic.STGI, Mnemonic.CLGI, Mnemonic.INVLPGA, Mnemonic.SKINIT}

genuine = Counter()   # chunk gpa -> count of genuine decoded SVM mnemonics
locations = []        # (gpa, ip, mnemonic name)
total_instr = 0

for f in files:
    gpa = int(os.path.basename(f)[10:-4],16)
    d = open(f,'rb').read()
    dec = Decoder(64, d, ip=gpa)
    cnt = 0
    for ins in dec:
        if ins.is_invalid:
            continue
        total_instr += 1
        if ins.mnemonic in SVM:
            cnt += 1
            locations.append((gpa, ins.ip, str(ins.mnemonic)))
    genuine[gpa] = cnt

print("chunks with >=1 genuine decoded SVM instruction:")
for gpa,c in sorted(genuine.items()):
    if c>0:
        print("  0x%08x  genuine_svm=%d" % (gpa,c))
print()
print("total genuine SVM instructions decoded:", sum(genuine.values()))
print("total valid instructions decoded:", total_instr)
print()
print("=== all genuine SVM locations ===")
for gpa, ip, mn in locations[:80]:
    print("  chunk 0x%08x  @0x%08x  %s" % (gpa, ip, mn))
