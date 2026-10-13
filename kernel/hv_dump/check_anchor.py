import os
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
FN = os.path.join(D, "hvdump_0x26000000_600MB.bin")
data = open(FN, "rb").read()

def hd(off, n, label):
    b = data[off:off+n]
    print("--- %s (off 0x%x) ---" % (label, off))
    for i in range(0, len(b), 16):
        c = b[i:i+16]
        print("  %08x: %-47s  %s" % (off+i, " ".join("%02x"%x for x in c),
              "".join(chr(x) if 0x20<=x<0x7f else "." for x in c)))

# lea rsi,[rip+0x771a9e] target = 0x2420002b + 0x771a9e = 0x29B1AC9
hd(0x29B1AC9 - 8, 64, "lea target region 0x29B1AC9")

# proper linear disasm starting at 0x24200001 (past the 0x28 mid-instruction byte)
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("\n===== proper disasm from 0x24200001 =====")
for ins in md.disasm(data[0x24200001:0x24200040], 0x24200001):
    print("  0x%08x: %-7s %s" % (ins.address, ins.mnemonic, ins.op_str))

# check where kdata_1360.bin lives
for p in [r"C:\Users\USER\Caliper-C0re\kernel\hv_dump\kdata_1360.bin",
          r"C:\Users\USER\Caliper-C0re\kernel\kdata_1360.bin",
          r"C:\Users\USER\AppData\Local\kex\cache\scratch\ps5\kdata_1360.bin"]:
    print("kdata?", p, os.path.exists(p))
