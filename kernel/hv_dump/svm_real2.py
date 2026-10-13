from iced_x86 import Decoder, Mnemonic, Code, FastFormatter
import glob, os
from collections import Counter

# First, print the enum values of the SVM mnemonics
for name in ['VMRUN','VMCALL','VMLOAD','VMSAVE','STGI','CLGI','INVLPGA','SKINIT']:
    m = getattr(Mnemonic, name)
    print(name, '=', int(m))

print()
SVM = {Mnemonic.VMRUN, Mnemonic.VMCALL, Mnemonic.VMLOAD, Mnemonic.VMSAVE,
       Mnemonic.STGI, Mnemonic.CLGI, Mnemonic.INVLPGA, Mnemonic.SKINIT}

formatter = FastFormatter()
files = sorted(glob.glob('hvcluster_*.bin'), key=lambda f:int(os.path.basename(f)[10:-4],16))

name_of = {}
for mn in SVM:
    name_of[int(mn)] = str(mn).split('.')[-1]

genuine = Counter()
for f in files:
    gpa = int(os.path.basename(f)[10:-4],16)
    d = open(f,'rb').read()
    dec = Decoder(64, d, ip=gpa)
    cnt=0
    for ins in dec:
        if ins.is_invalid: continue
        if ins.mnemonic in SVM:
            cnt+=1
            genuine[(gpa, int(ins.mnemonic), ins.ip)]+=1
    if cnt: pass

print("total genuine decoded SVM:", sum(genuine.values()))
print("breakdown by mnemonic:")
by = Counter()
for (gpa,mn,ip),c in genuine.items():
    by[name_of.get(mn,mn)] += c
for n,c in by.most_common():
    print("  %-10s x%d" % (n,c))
