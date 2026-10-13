import sys, os
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_REG

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
FN = os.path.join(D, "hvdump_0x26000000_600MB.bin")

SLID_TEXT_BASE = 0xffffffffcfed0000
CANON_TEXT_BASE = 0xffffffff80200000

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

hits = [0x02068e36, 0x052ca508, 0x0555e508, 0x062f2508, 0x074a384e, 0x07964fce,
        0x07e45537, 0x08cc1fa0, 0x0a211fa0, 0x0a6e57ee, 0x0bee722a, 0x0ca6722a,
        0x119357c6, 0x13ee1cfe, 0x157fb04b, 0x1fafb04b, 0x1fbe166c, 0x239332c3]

f = open(FN, "rb")

def read_at(off, n):
    f.seek(off)
    return f.read(n)

def disas(off, length, base_va):
    code = read_at(off, length)
    return list(md.disasm(code, base_va))

for h in hits:
    va = SLID_TEXT_BASE + h
    cva = CANON_TEXT_BASE + h
    print("=" * 100)
    print("vmmcall @ off=0x%08x  slidVA=0x%016x  canonVA=0x%016x" % (h, va, cva))
    # look backwards up to 80 bytes for the hypercall-number load (mov eax/rax, imm)
    back = 80
    insns = disas(h - back, back + 16, va - back)
    # find the vmmcall instruction and everything before it
    vmcall_idx = None
    for i, ins in enumerate(insns):
        if ins.mnemonic == "vmmcall" and ins.address == va:
            vmcall_idx = i
            break
    if vmcall_idx is None:
        # fall back: search any vmmcall
        for i, ins in enumerate(insns):
            if ins.mnemonic == "vmmcall":
                vmcall_idx = i
                break
    hc_num = None
    hc_load_insn = None
    if vmcall_idx is not None:
        for i in range(vmcall_idx - 1, -1, -1):
            ins = insns[i]
            if ins.mnemonic == "mov":
                # mov eax, imm  or mov rax, imm
                ops = ins.operands
                if len(ops) == 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_IMM:
                    r = ins.reg_name(ops[0].reg)
                    if r in ("eax", "rax") and ops[1].imm < 0x10000:
                        hc_num = ops[1].imm
                        hc_load_insn = ins
                        break
    if hc_num is not None:
        print("HYPERCALL NUMBER = 0x%x  (load: %s %s)" % (hc_num, hc_load_insn.mnemonic, hc_load_insn.op_str))
    else:
        print("HYPERCALL NUMBER = (not an immediate load; likely register-supplied)")
    # print disassembly from function-ish start
    for ins in insns:
        mark = ""
        if ins.address == va:
            mark = "   <-- VMMCALL"
        print("  0x%016x: %-7s %s%s" % (ins.address, ins.mnemonic, ins.op_str, mark))

f.close()
