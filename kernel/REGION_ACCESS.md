# REGION_ACCESS — why `kernel_copyout(0xffffffffcfed0000)` = −1, and the real read path

**Status:** RESOLVED. The "second region" is NOT a readable module BSS — it is the KASLR-slid
kernel **TEXT/rodata (RX, XOM)**. Hypothesis **(a)** is correct: it is XOM-protected exactly like
the kernel text, so `kernel_copyout` can never read it at any alias. The correct read primitive is
single-stepping (code semantics) or a hypervisor/NPT physical read (raw bytes).

---

## 1. Root cause (concrete, verified against `kdata_1360.bin`)

The `.data` dump stores **code pointers in two address forms** that are the *same* XOM code:

| form | example | used by | kernel_copyout |
|---|---|---|---|
| **canonical** (`0xffffffff80…`) | `sy_call` = `0xffffffff804772b8`, `filt_fileattach` = `0xffffffff8046d788` | sysent `sy_call`, some filterops | −1 (XOM, zero-fill, no panic) |
| **slid** (`0xffffffffcf…`) | DDB handlers `0xffffffffcfede108`, iommu methods `0xffffffffcfed8550`, `filt_fileattach` = `0xffffffffcfecd788` | filterops/fileops, DDB tables, driver method tables | −1 (XOM, zero-fill, no panic) |

The slide is **uniform +0x4FA60000** (slid = canonical + 0x4FA60000). Verified: **all 8309**
slid pointers in `kdata_1360.bin` map back into the canonical text range
`0xffffffff80200000..0xffffffff83be1cb0` after subtracting 0x4FA60000 (8309/8309).

Therefore the "second region" is a **slid view of the kernel's RX segment**:

```
slid text base   0xffffffffcfc60000  =  0xffffffff80200000 + 0x4FA60000   (min slid ptr in .data)
region base      0xffffffffcfed0000  =  0xffffffff80470000 + 0x4FA60000   <-- the probed VA
.data base       0xffffffffd0930000  =  0xffffffff80ed0000 + 0x4FA60000
```

So `0xffffffffcfed0000` ≡ canonical `0xffffffff80470000`, which sits **inside the kernel
`.text`/`.rodata`** (the first syscall handler is `0xffffffff804772b8`, only 0x1B58 above it; the
DDB command handlers `0xffffffffcfede108` ≡ `0xffffffff8047e108` and the `pci/iommu` method table
`0xffffffffcfed8550` ≡ `0xffffffff80478550` are both inside the region). The 6878 `.data` pointers
into `0xffffffffcfed0000..0xffffffffcff00000` are **code/const pointers** (function pointers,
method tables, DDB command handlers, 8-byte-stride slot arrays), **not** a separate RW module BSS.

The region is mapped **execute-only** (hypervisor SLAT bit-58 "nda"). A data read of an
execute-only page faults at the SLAT level; the etaHEN `kernel_copyout` primitive catches that
fault and returns **−1 with zero-fill, no panic** — the same "mapped-but-unreadable" signature as
reading canonical text `0xffffffff80200000`. This is *distinct* from an unmapped address (PANIC)
and from the live-exec mapping `0xffffff80…` (PANIC).

**So `SECOND_REGION_MAP.md`'s premise was wrong**: it read "pointers into a region below `.data`"
as "data pointers into module BSS". They are code pointers. There is no static TMR/psp_mbox/a53mm
data structure here to dump — those "singletons" (IOMMU root `0xffffffffcfed1098`, a53mm root
`0xffffffffcfed5760`, psp_mbox ctl `0xffffffffcfee09e8`) are executable code/const tables in the
kernel's RX image.

---

## 2. Why each hypothesis resolves the way it does

**(a) XOM-protected like kernel text — CORRECT.** The region is the slid `.text`/`.rodata`.
`kernel_copyout` = −1 (zero-fill, no panic) is the exact XOM signature. It is not readable via any
`kernel_copyout` VA.

**(b) canonical-vs-slid alias — PARTIAL, and it does NOT give a readable VA.** The relationship is
real and now pinned: slide = **+0x4FA60000**, region = canonical `0xffffffff80470000` slid. But the
canonical side (`0xffffffff80470000`) is *also* XOM text — subtracting the slide lands you back in
XOM text, not in readable data. There is no "readable alias" of this content.

**(c) kernel_copyout window restriction — NO.** The primitive reads the slid `.data` fine
(`0xffffffffd0930000..0xffffffffd1830000`, our 15 MB dump) and reads canonical pointers; the −1 on
`0xffffffffcfed0000` is not an address-window refusal, it is the XOM protection on the RX pages.
(Confirmed: `kernel_copyout` panics on `0xffffff80…` and on unmapped addresses, but returns −1 on
*all* XOM text aliases — canonical and slid alike.)

---

## 3. Which VA range IS readable

| range (13.60) | readable? | what it is |
|---|---|---|
| `0xffffffffd0930000..0xffffffffd1830000` | **YES** | slid `.data` — already dumped (`kdata_1360.bin`, 15 MB) |
| `0xffffffffcfc60000..0xffffffffd0866ee0` (slid text) | NO (XOM) | the code the pointers reference — incl. the "second region" |
| `0xffffffff80200000..0xffffffff83be1cb0` (canonical text) | NO (XOM) | link-time alias of the same code |
| `0xffffff80…` (live-exec mapping) | NO (PANIC) | where the CPU fetches instructions |

The *readable* kernel data is exactly what we already have: the slid `.data` dump (and, by the same
slide, any slid data above it). **The region `0xffffffffcfed0000` is not and never will be
`kernel_copyout`-readable — it is code.**

---

## 4. Correct read primitive

1. **Single-stepping (recommended, code semantics/offsets).** The r0gdb / sleirsgoevy "On offsets"
   method: set TF / DR watchpoints, execute, read `RIP`. This recovers instruction offsets and
   gadget semantics of the a53mm/psp_mbox/IOMMU code — the standard PS5 substitute for a text dump
   (see `XOM_BYPASS.md` §4). The slide **+0x4FA60000** lets you translate any `.data` code pointer
   (`0xffffffffcf…`) to its canonical `0xffffffff80…` form for symbolizing against the FreeBSD
   source tree.

2. **Hypervisor / NPT physical read (raw bytes).** The 13.60 lead (root-0 NPT maps the HV's own
   physical memory) is the only route to *raw* bytes of XOM pages: find the guest-physical alias of
   these RX pages and read them with `hvdump.elf` / the chunked physical dumper (`probe54`). Do it
   in small chunks — a blind physical sweep panics past RAM (`HANDOFF.md`).

3. **Instruction-fetch side channel** — theoretical only; do not plan around it.

Do **not** retry `kernel_copyout` on `0xffffffffcfed0000` (or its canonical form
`0xffffffff80470000`) — it is XOM and returns −1 by design; retrying on the wrong alias
(`0xffffff80…`) panics the console.

---

## 5. Correction log vs prior docs

- `SECOND_REGION_MAP.md` — superseded on the access question: the region is slid **TEXT/rodata**,
  not RW BSS. Its "dump priority 1–6" plan is unexecutable via `kernel_copyout`; use single-stepping
  or the NPT read instead. Its *pointer-graph* observations (singleton clusters, the 607-entry
  48-byte table, the 8 IOMMU unit-contexts, the DDB/method tables) remain valid **as code-pointer
  evidence** and are what let us pin the slide.
- `DATA_DIFF_761_1360.md` — its "static mailbox state lives in `0xffffffffcfed0000`" note is
  incorrect in the same way; that state, if it exists as data, is at a *readable* slid `.data`
  address, not in the XOM region. The `.data`-resident string anchors (`psp_mbox_*`,
  `hv_iommu_*`, TMR strings) remain the correct way to find the *code* that touches that state.
