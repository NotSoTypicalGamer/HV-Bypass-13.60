import sys
from capstone import *
from capstone.x86 import *

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def load(pa, size):
    # load bytes for guest-PA pa; try sparse chunk then contiguous dump
    chunk_base = pa & ~0xFFFFF
    fn = "hvcluster_%08x.bin" % chunk_base
    try:
        data = open(fn, "rb").read()
        off = pa - chunk_base
        return data[off:off+size], chunk_base
    except FileNotFoundError:
        data = open("hvdump_0x26000000_600MB.bin", "rb").read()
        off = pa - 0x26000000
        return data[off:off+size], 0x26000000

def disasm(pa, size, label=""):
    code, base = load(pa, size)
    print("="*70)
    print("DISASM %s @ gPA 0x%08x (source base 0x%08x), %d bytes" % (label, pa, base, size))
    print("="*70)
    for insn in md.disasm(code, pa):
        print("0x%08x  %-10s %s" % (insn.address, insn.mnemonic, insn.op_str))

if __name__ == "__main__":
    for (pa, sz, lbl) in [
        (0x3f8a1d00, 0x200, "func A (0x3f8a1db8 area)"),
        (0x3f8d2700, 0x300, "func B (0x3f8d27e6 area)"),
        (0x3f8d3b00, 0x300, "func C (0x3f8d3b46 area)"),
    ]:
        disasm(pa, sz, lbl)
