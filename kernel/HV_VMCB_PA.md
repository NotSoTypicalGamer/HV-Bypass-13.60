# PS5 13.60 Hypervisor — VMCB Physical Address Recovery

**Status: VMCB PA NOT RECOVERABLE from this dump. The "40-VMRUN clusters" are data tables, not VMCB-launch code.**

---

## 1. Bottom line

1. The six "40-VMRUN clusters" (`0x3fd00000`, `0x41000000`, `0x43d00000`, `0x45700000`,
   `0x46100000`, `0x46400000`) are **not** the VMCB-launch code. The `0F 01 D8` (VMRUN)
   byte sequences found there are **false positives**: each cluster contains a ~34 KB table
   of 16-bit little-endian words, and `0F 01 D8` straddles the boundary between word `0x010F`
   and word `0x00D8`.
2. **No genuine VMRUN instruction exists anywhere in the 186-chunk dump.** Every one of the
   296 occurrences of `0F 01 D8` is inside data (16-bit tables or repeated/encrypted blobs).
   The other SVM instructions are likewise all false positives, and no SVM MSR constants
   (`VM_HSAVE_PA` = `0xC0010117`, `VM_CR` = `0xC0010114`, etc.) are present in the dump.
3. The real `vcpu_run` code — which loads the VMCB physical address into `RAX` and executes
   `VMRUN` — lives in a physical-memory chunk that was **not captured** by this dump.
4. Therefore the VMCB physical address, the per-core VMCB array, and the stride cannot be
   derived from this dump by the VMRUN-adjacent-load method.

---

## 2. Why the 40-VMRUN clusters are data, not code

Hexdump of `hvcluster_3fd00000.bin` around the first "VMRUN" site (file offset `0x8ec7e`):

```
0008ec6e: 3e 01 d2 00 d4 00 d8 00 3e 01 d8 00 c9 00 d2 00   ......>.......>.
0008ec7e: 0f 01 d8 00 c9 00 d2 00 0f 01 c9 00 d8 00 0e 01   ................
0008ec8e: 44 01 c9 00 d8 00 0e 01 44 01 c9 00 d8 00 0e 01   ..D.......D.....
```

Read as **16-bit little-endian words on even offsets**, this region is:

```
0x013e 0x00d2 0x00d4 0x00d8 0x013e 0x00d8 0x00c9 0x00d2
0x010f 0x00d8 0x00c9 0x00d2 0x010f 0x00c9 0x00d8 0x010e
0x0144 0x00c9 0x00d8 0x010e 0x0144 0x00c9 0x00d8 0x010e
```

The byte triple `0F 01 D8` is formed by the **last byte of word `0x010F` (`0F`), its second
byte (`01`), and the first byte of the following word `0x00D8` (`D8`)** — a classic
word-boundary straddling false positive. The table's words are small values
(`0x0000`–`0x02xx`, mostly `0x00XX`/`0x01XX`) with a sliding-window repetition pattern; it
is a compact data structure (opcode/ModRM-looking value pairs), not executable x86-64 code.

The same table appears in all six clusters at different file offsets (anchor `0F 01 D8 00 C9 00 D2 00`
at `0x8ec7e` / `0x2ac7e` / `0x56c7e` / `0x5ac7e` / `0x12c7e` / `0x96c7e` respectively), i.e.
each cluster is a *different* 1 MB region carrying its *own* instance of this table — not a
replicated per-core code stub.

## 3. Full inventory of SVM-instruction byte patterns (all false positives)

```
VMRUN    296        (240 in the six clusters' data tables + 56 in data blobs)
VMMCALL   38        INVLPG 218
VMLOAD    69        STGI   179
VMSAVE    73        CLGI   170
SKINIT   143        SWAPGS  35   RDTSCP   2
```

Every one of these sits in the 16-bit table (`0F 01 <next word's low byte>`), in repeated
encrypted/compressed blobs (identical byte runs at the same low offset across many chunks,
e.g. `fd 96 c3 1b 15 77 ec 57 …` at `0x??7d0` and `c1 65 45 3e 59 62 40 1f …` at `0x??363`),
or in `0x10000000`-filled NPT-style tables. None is preceded by a `movabs rax, imm64`
(`48 B8`) or `mov rax, [mem]` load. A whole-dump scan for `movabs r64, imm64` with a
page-aligned immediate in the HV address range returns **0 hits** — the HV does not load
physical-address literals via `movabs` at all.

## 4. Where the code actually is, and where vcpu_run must be

The dump (186 × 1 MB chunks, `0x07d00000`–`0x5ff00000`, ~15% coverage) is a **mix** of HV
code/data and guest "normal world" (Orbis/FreeBSD) code/data:

* `hvcluster_3fd00000.bin` (and the other five clusters) contain genuine Clang-compiled
  x86-64 code — 154 function prologues `41 57 41 56 41 55 41 54 53` (`push r15;…;push rbx`).
  Example (real code, `0x3fd00244`):
  ```
  3fd00244: push r15 / push r14 / push r13 / push r12 / push rbx / sub rsp,0x18
  3fd00265: call 0x3fcf4b40          ; helper in the UN-DUMPED 0x3fcf0000 chunk
  3fd0026d: call 0x3fcf4c80
  3fd00293: call 0x3fcfd380
  ```
* The code at `0x3fd00000` is a *fragment*: its calls target `0x3fcf4b40 … 0x3fcfd380`, i.e.
  the `0x3fc00000–0x3fd00000` chunk, which is **not** in the dump (coverage there is only
  `0x3f600000, 0x3f700000, 0x3f800000, 0x3fd00000, 0x40300000, 0x40700000`).
* Other heavy code chunks: `0x42400000` (420 prologues, `psfx_caesar_room` string),
  `0x37f00000` (321 prologues; `/app0/eboot.bin`, `NPXS40210`, `DISCORD DAEMON`, React-Native
  UI — i.e. system-software/guest code), plus `0x15f00000`, `0x46400000`, `0x46100000`, …
* `0x10000000`-valued runs (e.g. 109 qwords at `0x3fd48020`) are NPT/memory-map entries
  (guest-RAM base `0x10000000`), not VMCB pointers.

The `vcpu_run` routine (VMRUN + the VMCB-PA load into `RAX`) is in a **gap** — most plausibly
`0x3fc00000–0x3fd00000` (the chunk the `0x3fd00000` code calls into), or one of the other
~84% of the address space that was not dumped. It is not present in any captured chunk.

## 5. Answers to the specific questions

* **(a) VMCB PA literal(s) / per-core stride:** not recoverable — the VMRUN sites are false
  positives and no `movabs`/`mov rax,[…]` VMCB load exists in the dump.
* **(b) Literal vs array:** cannot be determined from this dump. The only thing that can be
  ruled out is `movabs rax, imm64` (0 occurrences). On prior firmwares (8.00+) the VMCB PA is
  known to come from a per-core array, but that array is not visible here.
* **(c) VMCB array base PA:** not derivable from this dump.

## 6. Recommendation

Dump the missing `0x3fc00000–0x3fd00000` chunk (and, more generally, the contiguous
`0x3fc00000–0x3ff00000` range). The `vcpu_run` function there will contain the sequence
`mov rax, <vmcb-array base + core*8>` (or a RIP-relative load of the array) immediately
followed by `0F 01 D8`, which yields the VMCB base PA and the per-core stride directly.
