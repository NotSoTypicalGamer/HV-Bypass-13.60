import os, re, json, collections

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
with open(os.path.join(D, "hv_strings_raw.json"), encoding="utf-8") as f:
    strmap = json.load(f)

# The 8 kernel/rtld chunks (contain rtld + kernel printf + firmware patch strings)
KERNEL_CHUNKS = {'hvcluster_7d00000.bin','hvcluster_9f00000.bin','hvcluster_cb00000.bin',
                 'hvcluster_dc00000.bin','hvcluster_e800000.bin','hvcluster_19a00000.bin',
                 'hvcluster_1bc00000.bin','hvcluster_1f200000.bin'}

# kernel strings: those that appear ONLY/primarily in kernel chunks and look like kernel/loader text
kernel_strs = {}
for s, locs in strmap.items():
    chunks = set(l[0] for l in locs)
    if chunks & KERNEL_CHUNKS:
        # only keep if it appears in a kernel chunk
        kernel_strs[s] = locs

print("strings appearing in kernel chunks:", len(kernel_strs))

# Filter to "interesting" kernel strings: contain letters and length>=5, or format specifiers
def interesting(s):
    if not re.search(r'[A-Za-z]', s): return False
    if len(s) < 5: return False
    return True

kern = [(s, l) for s, l in kernel_strs.items() if interesting(s)]
kern.sort(key=lambda x: (-len(x[1]), -len(x[0])))

print("\n=== KERNEL/LOADER STRINGS (top 300) ===")
for s, locs in kern[:300]:
    chunks = sorted(set(l[0] for l in locs))
    offs = sorted(set(l[1] for l in locs))[:4]
    print(f"{s!r}\tocc={len(locs)}\tchunks={chunks}\toffs={[hex(o) for o in offs]}")

# relapse / HV RE tooling strings
rel = [(s,l) for s,l in strmap.items() if 'relapse' in s.lower() or 'PAIR-' in s or 'PREDECESSOR' in s or 'soniciso1' in s]
print("\n=== RELAPSE (user HV RE tooling) STRINGS ===")
for s, locs in sorted(rel, key=lambda x:-len(x[0])):
    chunks = sorted(set(l[0] for l in locs))
    print(f"{s!r}\tchunks={chunks}")
