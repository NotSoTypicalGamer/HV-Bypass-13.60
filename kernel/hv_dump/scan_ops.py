import os, re
from collections import Counter

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
FN = os.path.join(D, "hvdump_0x26000000_600MB.bin")

data = open(FN, "rb").read()
print("size", hex(len(data)))

def findall(pat):
    out = []
    start = 0
    while True:
        i = data.find(pat, start)
        if i < 0:
            break
        out.append(i)
        start = i + 1
    return out

# SVM opcodes: 0F 01 D8..DF (vmrun, vmmcall, vmload, vmsave, stgi, clgi, skinit, invlpga)
suffix = ["D8:VMRUN","D9:VMMCALL","DA:VMLOAD","DB:VMSAVE","DC:STGI","DD:CLGI","DE:SKINIT","DF:INVLPGA"]
print("\n=== SVM 0F 01 D8..DF counts ===")
for s in suffix:
    op = int(s[:2],16)
    pat = bytes([0x0f,0x01,op])
    hits = findall(pat)
    print("  0F 01 %s  %-9s  count=%d" % (s[:2], s[3:], len(hits)))

# other privileged/control opcodes
others = {
    "vmcall(Intel) 0F 01 C1": bytes([0x0f,0x01,0xc1]),
    "swapgs 0F 01 F8": bytes([0x0f,0x01,0xf8]),
    "sysret 0F 07": bytes([0x0f,0x07]),
    "sysretq 48 0F 07": bytes([0x48,0x0f,0x07]),
    "syscall 0F 05": bytes([0x0f,0x05]),
    "iretq 48 CF": bytes([0x48,0xcf]),
    "rdmsr 0F 32": bytes([0x0f,0x32]),
    "wrmsr 0F 30": bytes([0x0f,0x30]),
    "wbinvd 0F 09": bytes([0x0f,0x09]),
    "invlpg 0F 01 38": bytes([0x0f,0x01,0x38]),
    "cpuid 0F A2": bytes([0x0f,0xa2]),
}
print("\n=== other privileged opcodes (whole file) ===")
for name, pat in others.items():
    hits = findall(pat)
    # classify: in code region (0x21000000-0x25E00000)?
    in_code = [h for h in hits if 0x21000000 <= h < 0x26000000]
    print("  %-28s count=%4d  (in code region 0x21..0x26: %d)" % (name, len(hits), len(in_code)))

# ASCII strings in the code region to identify it
print("\n=== printable ASCII runs in code region 0x22000000..0x25e00000 (len>=8) ===")
code = data[0x22000000:0x25e00000]
strings = re.findall(rb"[ -~]{8,}", code)
seen = Counter(strings)
for s, c in seen.most_common(40):
    print("   x%d  %r" % (c, s.decode('latin1')))

# mov eax, imm32 (B8 imm32) followed by vmmcall within 16 bytes
print("\n=== 'mov eax, imm32' (B8) then vmmcall within 20 bytes ===")
vmc = b"\x0f\x01\xd9"
count = 0
for i in range(len(data)-3):
    if data[i] == 0xB8 and data[i+1:i+5] != b"\x00\x00\x00\x00":
        window = data[i+5:i+25]
        if vmc in window:
            imm = int.from_bytes(data[i+1:i+5], 'little')
            print("  off=0x%08x  mov eax,0x%x  -> vmmcall at +%d" % (i, imm, window.find(vmc)+5))
            count += 1
print("  total mov-eax->vmmcall candidates:", count)
