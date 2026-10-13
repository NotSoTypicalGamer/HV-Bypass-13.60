import os
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
md = Cs(CS_ARCH_X86, CS_MODE_64)

def dis(base, off, length, title):
    fn = "hvcluster_%08x.bin" % base
    with open(os.path.join(D, fn), "rb") as f:
        data = f.read()
    print(f"\n######## {title} (0x{base+off:x}) ########")
    for ins in md.disasm(data[off:off+length], base+off):
        print(f"  0x{ins.address:08x}: {ins.mnemonic:7s} {ins.op_str}")

dis(0x3fd00000, 0xa00, 0x300, "shrx/shlx cluster A")
dis(0x3fd00000, 0xe00, 0x300, "shrx/shlx cluster B")
dis(0x3fd00000, 0x1e00, 0x300, "shlx/shrx cluster C")
