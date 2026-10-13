import os, re, json, collections, hashlib

D = r"C:\Users\USER\Caliper-C0re\kernel\hv_dump"
files = sorted(f for f in os.listdir(D) if f.startswith("hvcluster_") and f.endswith(".bin"))

# Verify the 27-dup group content (zero-fill?)
hashes = collections.defaultdict(list)
for fn in files:
    with open(os.path.join(D, fn), "rb") as f:
        data = f.read()
        hashes[sha256 := hashlib.sha256(data).hexdigest()].append(fn)
dup = [v for v in hashes.values() if len(v) > 1][0]
with open(os.path.join(D, dup[0]), "rb") as f:
    d = f.read()
nonzero = sum(1 for b in d if b != 0)
print("dup group x%d first file nonzero bytes: %d / %d" % (len(dup), nonzero, len(d)))
print("first 64 bytes:", d[:64].hex())

with open(os.path.join(D, "hv_strings_raw.json"), encoding="utf-8") as f:
    strmap = json.load(f)

# Collect ALL Sony build paths
build_paths = collections.defaultdict(list)
for s, locs in strmap.items():
    if ('W:/Build/' in s or 'W:\\Build\\' in s or 'jnkd' in s or '/sys/' in s or 'orbis-build' in s
        or re.search(r'\.(prx|sprx|elf|self|bin|hbc)\b', s, re.I)):
        if re.search(r'[A-Za-z]:[/\\]|[A-Za-z0-9_./\\\-]{20,}', s):
            build_paths[s].extend(locs)

print("\n=== SONY BUILD PATHS / MODULE NAMES (n=%d) ===" % len(build_paths))
for s, locs in sorted(build_paths.items(), key=lambda x: -len(x[1])):
    chunks = sorted(set(l[0] for l in locs))
    offs = sorted(set(l[1] for l in locs))[:6]
    print(f"{s}\tocc={len(locs)}\tchunks={chunks}\toffs={[hex(o) for o in offs]}")
