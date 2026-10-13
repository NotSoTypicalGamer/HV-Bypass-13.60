import os, re, json, collections

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
with open(os.path.join(D, "hv_strings_raw.json"), encoding="utf-8") as f:
    strmap = json.load(f)

def hits_for(pat, flags=re.IGNORECASE):
    rx = re.compile(pat, flags)
    out = []
    for s, locs in strmap.items():
        if rx.search(s):
            out.append((s, locs))
    return out

def report(title, hits, out, maxn=200):
    out.append("\n========== %s  (n=%d) ==========" % (title, len(hits)))
    hits_sorted = sorted(hits, key=lambda h: (-len(h[1]), -len(h[0])))
    for s, locs in hits_sorted[:maxn]:
        chunks = sorted(set(l[0] for l in locs))
        offs = [l[1] for l in locs][:6]
        out.append(f"{s!r}\tocc={len(locs)}\tchunks={chunks}\toffs={[hex(o) for o in offs]}")

out = []

# Exact SVM instruction mnemonics / AMD-V terms (word-boundary, case-sensitive where meaningful)
report("vmmcall/vmrun/vmload/vmsave/clgi/stgi/skinit", hits_for(r'\b(vmmcall|vmrun|vmload|vmsave|clgi|stgi|skinit|vmgif|vintr|vmlaunch|vmresume|invd|wbinvd|invlpga|invlpg|clflush)\b'), out)
report("vmcb (any case)", hits_for(r'vmcb'), out)
report("SVM (word)", hits_for(r'\bSVM\b'), out)
report("NPT / nested paging", hits_for(r'\b(npt|nested.?paging|nested_paging|NPT)\b'), out)
report("hypercall/hypervisor", hits_for(r'\b(hypercall|hypervisor|hyp_|hyperv)\w*'), out)
report("IOMMU", hits_for(r'iommu', ), out)
report("TMR (word)", hits_for(r'\bTMR\b|\btmr\b|TMR\d|_tmr|tmr_'), out)
report("vmexit/vmentry/#VMEXIT", hits_for(r'vmexit|vmentry|#VMEXIT|VMEXIT'), out)
report("intercept", hits_for(r'intercept'), out)
report("Sony build paths", hits_for(r'(/[A-Za-z0-9_.\-]+)+\.(c|h|S|cpp|s)\b|/\w+/src/|\bsrc/[a-z]|@\(#\)|#pragma|\$NetBSD|\$FreeBSD'), out)
report("GET_MESSAGE_CONF / message conf", hits_for(r'message.?conf|GET_MESSAGE|MSG_CONF|msg.?conf'), out)
report("FreeBSD/rtld kernel", hits_for(r'\[rtld\]|\[%s:%d ERR\]|panic:|kernel: |FreeBSD|SceKernel|sceKernel'), out)
report("panic/assert/abort/trap", hits_for(r'\b(panic|assert|abort|trap)\w*'), out)

with open(os.path.join(D, "hv_targeted.txt"), "w", encoding="utf-8") as f:
    f.write("\n".join(out))

# Also dump to stdout the sections that matter most
print("\n".join(out))
