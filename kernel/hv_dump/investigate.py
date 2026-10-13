import os
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
FN = os.path.join(D, "hvdump_0x26000000_600MB.bin")

md = Cs(CS_ARCH_X86, CS_MODE_64)

f = open(FN, "rb")

def hexdump(off, n, label):
    f.seek(off)
    b = f.read(n)
    print("--- %s  (file off 0x%x, %d bytes) ---" % (label, off, n))
    for i in range(0, len(b), 16):
        chunk = b[i:i+16]
        hexs = " ".join("%02x" % c for c in chunk)
        ascii_ = "".join(chr(c) if 0x20 <= c < 0x7f else "." for c in chunk)
        print("  %08x: %-47s  %s" % (off + i, hexs, ascii_))

def disas(off, n, label):
    f.seek(off)
    code = f.read(n)
    print("\n===== %s  (file off 0x%x) =====" % (label, off))
    for ins in md.disasm(code, off):
        print("  0x%08x: %-7s %s" % (ins.address, ins.mnemonic, ins.op_str))

hexdump(0, 128, "file offset 0")
hexdump(0x24200000, 64, "start of dense code region")
hexdump(0x25800000, 64, "densest code block")
disas(0x25800000, 128, "disasm dense code block 0x25800000")
disas(0x24200000, 128, "disasm code region 0x24200000")

# check: is there a big all-zero region? scan for first non-zero byte and map zero/nonzero
f.seek(0)
# sample every 1MB byte
print("\n=== zero/ff map (sample byte at each 1MB) ===")
for mb in range(0, 0x26000000 // (1<<20)):
    f.seek(mb * (1<<20))
    b = f.read(1)
    if b == b"\x00":
        m = "ZERO"
    elif b == b"\xff":
        m = "0xFF"
    else:
        m = "0x%02x" % b[0]
    print("  MB %3d (off 0x%08x): %s" % (mb, mb*(1<<20), m))

f.close()
