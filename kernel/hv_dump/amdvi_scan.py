import re, sys

DUMP = "hvdump_0x26000000_600MB.bin"
BASE = 0x26000000  # guest-PA base of the contiguous dump

# Region of interest: driver code around guest-PA 0x3f800000
LO = 0x3f800000
HI = 0x3f920000

data = open(DUMP, "rb").read()

def pa_to_off(pa):
    return pa - BASE

# Scan ASCII strings in the region
region = data[pa_to_off(LO):pa_to_off(HI)]
print("region len", hex(len(region)))

strings = []
pat = re.compile(rb'[\x20-\x7e]{5,}')
for m in pat.finditer(region):
    s = m.group().decode('ascii', 'replace')
    pa = LO + m.start()
    strings.append((pa, s))

# Print strings matching AMD-Vi / IOMMU / IVRS / ACPI keywords
kw = re.compile(r'(?i)(ivrs|amdvi|iommu|ivhd|ivmd|completion|inv_dte|inv_page|event|command|device table|dte|cmdbuf|dom?ain|interrupt|pci|acpi|bars?|baseaddr|phys|dma)', )
print("=== matching strings ===")
for pa, s in strings:
    if kw.search(s):
        print("0x%08x  %r" % (pa, s))

print()
print("=== ALL strings in region (count %d) ===" % len(strings))
for pa, s in strings:
    print("0x%08x  %r" % (pa, s))
