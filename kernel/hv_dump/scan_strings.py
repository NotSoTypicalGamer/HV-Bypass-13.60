import os, re
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
FN = os.path.join(D, "hvdump_0x26000000_600MB.bin")
data = open(FN, "rb").read()

# 1. search for hv_/svmd strings (would be in .rodata/.data if present)
print("=== hv_/svmd/TMR/iommu string search (whole 608MB) ===")
for needle in [b"hv_iommu", b"hv_get_tmr", b"hv_unmap_pt_tmr", b"hv_restore_pt_tmr",
               b"hv_startup_mp", b"sce_svmd", b"svmd", b"vmmcall", b"VMMCALL",
               b"hv_map_pt_tmr", b"iommu_set_guest", b"TMR", b"tmr_violation"]:
    hits = []
    s = 0
    while True:
        i = data.find(needle, s)
        if i < 0:
            break
        hits.append(i)
        s = i + 1
    print("  %-22r -> %d hit(s)%s" % (needle, len(hits), ("  first at 0x%08x" % hits[0]) if hits else ""))

# 2. linear disassembly of code region, count vmmcall and check cleanliness
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("\n=== linear disasm of code region 0x24200000..0x24300000 (1MB), vmmcall/svm count ===")
vm = 0
svm = 0
total = 0
code = data[0x24200000:0x24300000]
for ins in md.disasm(code, 0x24200000):
    total += 1
    if ins.mnemonic == "vmmcall":
        vm += 1
        print("  VMMCALL at 0x%08x" % ins.address)
    if ins.mnemonic in ("vmrun","vmload","vmsave","stgi","clgi","skinit","invlpga","vmcall"):
        svm += 1
        print("  %s at 0x%08x" % (ins.mnemonic, ins.address))
print("  decoded %d instructions in 1MB; vmmcall=%d  other-SVM=%d" % (total, vm, svm))

# 3. the 2 swapgs / 2 vmcall hits inside code region -> show context
print("\n=== swapgs / vmcall(0F01C1) hits in code region, with 24-byte disasm ===")
for name, pat in [("vmcall 0F01C1", b"\x0f\x01\xc1"), ("swapgs 0F01F8", b"\x0f\x01\xf8")]:
    s = 0
    while True:
        i = data.find(pat, s)
        if i < 0:
            break
        if 0x21000000 <= i < 0x26000000:
            ctx = data[i-16:i+16]
            print("  %s @ 0x%08x ctx=%s" % (name, i, ctx.hex(' ')))
        s = i + 1

# 4. exact boundary of the code region: find first dense code
print("\n=== locate code region boundary (scan 0x21000000..0x26000000 per 4KB for code density) ===")
for off in range(0x21000000, 0x26000000, 0x100000):
    blk = data[off:off+0x100000]
    pro = blk.count(b"\x55\x48\x89\xe5") + blk.count(b"\x41\x57\x41\x56")  # push rbp;mov rbp,rsp  or push r15;push r14
    if pro > 50:
        print("  off=0x%08x prologues~%d" % (off, pro))
