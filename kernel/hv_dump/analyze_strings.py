import os, re, json, collections

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"

with open(os.path.join(D, "hv_strings_raw.json"), encoding="utf-8") as f:
    strmap = json.load(f)

# Build reverse index: which strings contain a keyword (case-insensitive)
def kw_search(kws, maxres=400):
    hits = []
    for s, locs in strmap.items():
        ls = s.lower()
        for kw in kws:
            if kw in ls:
                hits.append((s, locs))
                break
    return hits

def dump_hits(title, hits, out, maxlines=400):
    out.append("\n### " + title + "  (n=%d)" % len(hits))
    # sort by number of occurrences desc, then length
    hits_sorted = sorted(hits, key=lambda h: (-len(h[1]), -len(h[0])))
    for s, locs in hits_sorted[:maxlines]:
        # show unique chunks
        chunks = sorted(set(l[0] for l in locs))
        first_off = locs[0][1]
        out.append(f"{s!r}\tocc={len(locs)}\tchunks={chunks[:8]}{'...' if len(chunks)>8 else ''}\toff={first_off:#x}")

out = []

# --- SVM / hypercall machinery ---
svm_kws = ["vmmcall","vmrun","vmload","vmsave","clgi","stgi","skinit","vmcb","svm","npt","vmexit","vmentry","#vc","sev","vmgif","vintr","amdiv","amd-v","gif","intercept","virtualize","hypervis"]
dump_hits("SVM / hypervisor machinery", kw_search(svm_kws), out)

# --- Hypercall names ---
hc_kws = ["hypercall","hvc_","hvc ","hyperv","syscall_","kern_","sysent"]
dump_hits("Hypercall names", kw_search(hc_kws), out)

# --- IOMMU / TMR ---
iommu_kws = ["iommu","tmr","dte","devtab","ppr","ivrs","interrupt remap","intremap","amdiommu","gcr3","iommu_reg"]
dump_hits("IOMMU / TMR", kw_search(iommu_kws), out)

# --- error/panic/format strings ---
err_kws = ["%s","%d","%x","failed","error","invalid","panic","assert","fatal","bug","unsupported","unexpected","corrupt","overflow","underflow","not found","out of","cannot","unable"]
dump_hits("Error / panic / format strings", kw_search(err_kws), out)

# --- build paths / module names ---
path_kws = ["/", "\\", ".c", ".h", ".s", ".S", ".cpp", "kernel", "module", "libc", "src/", "orc", "eboot", "safe", "main", "kmem", "vm/"]
dump_hits("Build paths / module names", kw_search(path_kws), out)

with open(os.path.join(D, "hv_analysis_scratch.txt"), "w", encoding="utf-8") as f:
    f.write("\n".join(out))

print("total lines:", len(out))
# print first 600 lines to stdout for review
print("\n".join(out[:600]))
