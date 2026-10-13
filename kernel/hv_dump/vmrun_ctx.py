from iced_x86 import Decoder, Mnemonic, Code, FastFormatter
import glob, os
from collections import Counter

formatter = FastFormatter()
SVM = {Mnemonic.VMRUN, Mnemonic.VMCALL, Mnemonic.VMLOAD, Mnemonic.VMSAVE}
files = sorted(glob.glob('hvcluster_*.bin'), key=lambda f:int(os.path.basename(f)[10:-4],16))

hits=[]
for f in files:
    gpa = int(os.path.basename(f)[10:-4],16)
    d = open(f,'rb').read()
    dec = Decoder(64, d, ip=gpa)
    for ins in dec:
        if ins.is_invalid: continue
        if ins.mnemonic in SVM:
            hits.append((gpa, ins.ip, str(ins.mnemonic).split('.')[-1], d))

print("VMRUN/VMCALL/VMLOAD/VMSAVE hits:", len(hits))
print()
for gpa, ip, mn, d in hits:
    off = ip - gpa
    # disassemble 24 bytes before, 16 after
    start = max(0, off-0x30)
    end = min(len(d), off+0x20)
    dec = Decoder(64, d[start:end], ip=gpa+start)
    lines=[]
    for ins in dec:
        if ins.ip > ip+0x10: break
        mark = '  <<<<< '+mn if ins.ip==ip else ''
        lines.append("      %08x  %-30s%s" % (ins.ip, formatter.format(ins), mark))
    print("  @ chunk 0x%08x offset +0x%x:" % (gpa, off))
    for l in lines[-9:]:
        print(l)
    print()
