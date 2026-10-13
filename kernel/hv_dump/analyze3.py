import os, re, json, collections, hashlib

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
files = sorted(f for f in os.listdir(D) if f.startswith("hvcluster_") and f.endswith(".bin"))

# 1) Hash every chunk to find duplicates
hashes = collections.defaultdict(list)
for fn in files:
    with open(os.path.join(D, fn), "rb") as f:
        h = hashlib.sha256(f.read()).hexdigest()
    hashes[h].append(fn)

uniq = {h: v for h, v in hashes.items()}
print("total chunks:", len(files), " unique content:", len(uniq))
dups = {h: v for h, v in hashes.items() if len(v) > 1}
print("duplicate groups:", len(dups))
for h, v in sorted(dups.items(), key=lambda x: -len(x[1])):
    print(f"  x{len(v)}: {v}")
print("singletons:", len(uniq) - len(dups))

with open(os.path.join(D, "hv_strings_raw.json"), encoding="utf-8") as f:
    strmap = json.load(f)

def hits_for(pat, flags=re.IGNORECASE):
    rx = re.compile(pat, flags)
    out = []
    for s, locs in strmap.items():
        if rx.search(s):
            out.append((s, locs))
    return out

def report(title, hits, out, maxn=300, bylen=False):
    out.append("\n========== %s  (n=%d) ==========" % (title, len(hits)))
    hits_sorted = sorted(hits, key=lambda h: (-len(h[1]), -len(h[0])) if not bylen else (-len(h[0]),))
    for s, locs in hits_sorted[:maxn]:
        chunks = sorted(set(l[0] for l in locs))
        offs = sorted(set(l[1] for l in locs))[:8]
        out.append(f"{s!r}\tocc={len(locs)}\tchunks={chunks}\toffs={[hex(o) for o in offs]}")

out = []

# Sony build paths (Windows-style, backslash)
report("Sony build paths (Windows)", hits_for(r'[A-Za-z]:\\\\[^\x00-\x1f]{3,}'), out, bylen=True)
report("Sony build paths (posix /)", hits_for(r'/(?:[A-Za-z0-9_.\-]+/){2,}[A-Za-z0-9_.\-]+'), out, bylen=True)
report("rnps / jnkd / workspace / releases", hits_for(r'rnps|jnkd|workspace|_releases_|13\.60|13_60'), out, bylen=True)

# Kernel-level identifiers (FreeBSD/Sce)
report("sce* identifiers", hits_for(r'\bsce[A-Za-z0-9_]{3,}'), out, maxn=400)
report("syscall/sysent/kernel/trap", hits_for(r'\b(syscall|sysent|sysentvec|trapframe|vm_fault|pmap|uma_|malloc|vnode|proc|thread|kern_|subr_)\w*'), out, maxn=400)
report("page fault / fault handler", hits_for(r'page fault|fault|trap [0-9]|exception|#GP|#PF|#UD|#NM|#DF'), out)
report("mmu/table/entry", hits_for(r'\b(mmu|page.?table|pml4|pdpe|pte|pgd|vm_map|vm_object|vm_page)\b'), out)

with open(os.path.join(D, "hv_targeted2.txt"), "w", encoding="utf-8") as f:
    f.write("\n".join(out))
print("\n".join(out))
