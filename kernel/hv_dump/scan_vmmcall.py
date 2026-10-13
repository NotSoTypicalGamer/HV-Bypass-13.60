import sys, os
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
FN = os.path.join(D, "hvdump_0x26000000_600MB.bin")

SLID_TEXT_BASE = 0xffffffffcfed0000
CANON_TEXT_BASE = 0xffffffff80200000

md = Cs(CS_ARCH_X86, CS_MODE_64)

# scan for vmmcall 0F 01 D9
pat = b"\x0f\x01\xd9"
hits = []
with open(FN, "rb") as f:
    off = 0
    chunk = 1 << 24  # 16 MB
    carry = b""
    while True:
        buf = f.read(chunk)
        if not buf:
            break
        data = carry + buf
        pos = data.find(pat)
        while pos != -1:
            hits.append(off + pos - len(carry))
            pos = data.find(pat, pos + 1)
        carry = data[-(len(pat)-1):]
        off += len(buf)

print("total vmmcall hits:", len(hits))
print("VA = 0x%x + file_offset  (slid text base)" % SLID_TEXT_BASE)
print("canonical VA = 0x%x + file_offset" % CANON_TEXT_BASE)
print()
for h in hits:
    va = SLID_TEXT_BASE + h
    cva = CANON_TEXT_BASE + h
    print("off=0x%08x  slid=0x%016x  canon=0x%016x" % (h, va, cva))
