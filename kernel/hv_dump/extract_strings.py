import os, re, json, collections

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
files = sorted(f for f in os.listdir(D) if f.startswith("hvcluster_") and f.endswith(".bin"))
print("num files:", len(files))

# chunk base address = hex in filename
def chunk_base(fn):
    m = re.search(r'hvcluster_([0-9a-fA-F]+)\.bin', fn)
    return int(m.group(1), 16) if m else None

# ASCII string extraction: printable bytes 0x20..0x7e, length >= 4
PRINTABLE = set(range(0x20, 0x7f))

# dict: string -> list of (filename, offset)
strmap = collections.defaultdict(list)
total_strings = 0

for fn in files:
    path = os.path.join(D, fn)
    with open(path, "rb") as f:
        data = f.read()
    base = chunk_base(fn)
    i = 0
    n = len(data)
    while i < n:
        b = data[i]
        if b in PRINTABLE:
            j = i
            while j < n and data[j] in PRINTABLE:
                j += 1
            ln = j - i
            if ln >= 4:
                s = data[i:j].decode("ascii", "replace")
                strmap[s].append((fn, i))
                total_strings += 1
            i = j
        else:
            i += 1

print("total raw strings (>=4, with dups):", total_strings)
print("unique strings:", len(strmap))

# write full JSON map (string -> locations)
out_json = os.path.join(D, "hv_strings_raw.json")
with open(out_json, "w", encoding="utf-8") as f:
    json.dump({s: locs for s, locs in strmap.items()}, f, ensure_ascii=False)
print("wrote", out_json)

# Save a compact TSV too: string, count, chunk, offset
out_tsv = os.path.join(D, "hv_strings_all.tsv")
with open(out_tsv, "w", encoding="utf-8") as f:
    for s, locs in strmap.items():
        f.write("%s\t%d\t%s\t%s\n" % (s, len(locs), locs[0][0], locs[0][1]))
print("wrote", out_tsv)
