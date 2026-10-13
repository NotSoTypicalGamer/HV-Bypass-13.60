import os, re, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"

def load(base):
    fn = "hvcluster_%08x.bin" % base
    with open(os.path.join(D, fn), "rb") as f:
        return f.read()

md = Cs(CS_ARCH_X86, CS_MODE_64)

def dis(base, start_off, length, title):
    data = load(base)
    code = data[start_off:start_off+length]
    print(f"\n######## {title}  (chunk 0x{base:x} + 0x{start_off:x}, {length} bytes) ########")
    for ins in md.disasm(code, base + start_off):
        print(f"  0x{ins.address:08x}: {ins.mnemonic:7s} {ins.op_str}")

# windows of interest
dis(0x41000000, 0x00c0, 0x60, "movabs 0x008000000000000d context")
dis(0x41000000, 0x1640, 0x120, "movabs 0x8000000000000000 (NX) context")
dis(0x41000000, 0x1590, 0xb0, "or powers-of-2 sequence context")
dis(0x3fd00000, 0x3760, 0x140, "and 0xfff / 0xfff000 / test 0x150 context")
