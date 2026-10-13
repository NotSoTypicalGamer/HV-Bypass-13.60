# HCI_map.md — PS5 kernel Bluetooth/HCI parser structure map (from 48 MB data dump)

Data base this boot: `0xffffffffc9570000` (KASLR-slid). Dump = 48 MiB, file offset N →
virtual address `0xffffffffc9570000 + N`. Kernel TEXT is XOM at `0xffffffff80200000..0xffffffff83c00000`
(60 MiB, unreadable). Loadable-module TEXT sits above it at `0xffffffff84000000..0xffffffff8c000000`.

## Headline finding

**The `bt_hci` / `bt_usb` / `bluetooth_hid` code is a set of LOADABLE kernel modules (klds), not
statically-linked code.** Their HCI command/event dispatch tables (arrays of function pointers) live in
the modules' *own* data, which is allocated from the kernel heap at `0xffffffffcf000000+` (and a second
region at `0xffffffffd0000000+`) — **outside** the 48 MiB static-data segment that was dumped
(`0xffffffffc9570000..0xffffffffcc570000`). Therefore the HCI event/command handler tables themselves are
**NOT present in kernel_data.bin**. What *is* present is enumerated below.

## Evidence the bt stack is loadable, not static

- Module load-path format strings in static rodata: `/%s/priv/modules/%s` (off `0x3e90f1`),
  `/%s/priv/modules/%.*s%s` (off `0x381265`), `%s.ko` (off `0x364aac`).
- Module code pointers cluster in a *separate* KVA region above the 60 MiB main text:
  - module A text: `0xffffffff84065000..0xffffffff840cb000` (~600 KiB; 117 refs from main data)
  - module B text: `0xffffffff872d0000..0xffffffff8751e000` (~2.3 MiB; 403 refs from main data)
  - module C text: `0xffffffff8b3b2b47` (1 fn, 3 refs)
- No stride-8/16/24 arrays of module-code pointers exist anywhere in the dump → the modules' internal
  dispatch tables are not reachable from static data.

## What IS in the dump (bt-stack anchors)

| item | file offset | virtual addr | note |
|---|---|---|---|
| `bt_hci` module name string | `0x9844dd` | `0xffffffffc9ef44dd` | packed module-name/reloc table |
| `bt_usb` module name string | `0x9844e4` | `0xffffffffc9ef44e4` | immediately follows |
| `bt_hci` copy 2 | `0x981de8` | `0xffffffffc9ef1de8` | module symbol/string pool |
| `bt_usb` copy 2 | `0x97f150` | `0xffffffffc9eef150` | module symbol/string pool |
| queue/thread name table | `0x9846e0` | `0xffffffffc9ef46e0` | `HCI_Q`, `LM_Q`, `LL_Q`, `TRAN_Q`, `TMSVR_Q`; `HCI Thread`, `LM Thread`, `LL Thread`, `TRAN Thread`, `TMSVR Thread` (each entry = 8-byte name + 32-bit value) |
| `bluetooth_hid.c` source path | `0x41f258` | `0xffffffffc998f258` | `W:\Build\J01736804\sys\internal\modules\bluetooth_hid\bluetooth_hid.c` (static rodata) |
| thread name `SceBtSync` | `0x31a02d` | `0xffffffffc988a02d` | referenced from `0x2a70d28` |
| thread name `SceBtHidGiant` | `0x329be7` | `0xffffffffc9899be7` | |
| thread name `SceBtTimer` | `0x3f613d` | `0xffffffffc996613d` | |
| thread name `SceBtDriver` | `0x40fa1c` | `0xffffffffc997fa1c` | |
| thread name `SceBttsSync` | `0x42c63f` | `0xffffffffc999c63f` | referenced from `0x2a70d18` |

Notes:
- `SceBt*` thread names live in the *static* rodata string pool (`0x310000..0x440000`) alongside `SceHid*`
  names, i.e. a statically-linked BT/HID integration layer spawns these threads; the loadable
  `bt_hci`/`bt_usb`/`bluetooth_hid` modules are the protocol engines.
- The string at `0x3f52d6` is `ahci_cmd_print() ccb:NULL` (SATA/AHCI), NOT Bluetooth — a substring trap.

## Dispatch tables actually reachable from static data

These are **not** the HCI event/command tables; they are the kobj method tables the main kernel keeps to
call *into* the modules. They are the only dense arrays of module-code function pointers in the dump.

### 1. Master kobj method table — `kobj_methods[]`
- file offset `0x59000`, VA `0xffffffffc95c9000`, stride 16 (`{kobjop_desc*, default_method*}`).
- `0xffffffff87434b40` (module B) is referenced ~50× here as a default method implementation
  (first ref `0x591d8`); main-text defaults `0xffffffff811xxxxx`/`0xffffffff8282xxxx` fill the rest.
- Entries continue through ~`0x5a600`.

### 2. Dense dispatch region (per-class kobj op tables / method stubs)
- file offsets `0x117000..0x14f000`, VA `0xffffffffc9687000..0xffffffffc96a6000`.
- Holds ~340 function pointers per 4 KiB page; every module-B function below is referenced from here at
  ~144-byte stride (24-byte base stride). This is where the kernel dispatches into the module's public
  device methods, NOT its HCI parsers.

## Module-B (0x87) function addresses referenced from static data (= public bt-stack entry points)

Full sorted list is in `scratch/ps5/module87_functions.txt`. Highlights (refcount):

- `0xffffffff87434b40` — refcount 140 (kobj default method; most-referenced module fn)
- `0xffffffff87482bc8` — refcount 9
- `0xffffffff874753e0..0xffffffff87475440` — 4-byte-strided thunk/stub table (~26 stubs) referenced from
  `0x135f90..0x136ad0` (144-byte stride) — classic kobj per-method stub block.
- Range `0xffffffff872d02c0..0xffffffff8751db48` — the module's code span.

## Top fuzz targets (ranked) — see notes for the honest caveat

The *actual* HCI event (controller→host) and command-complete parsers are **internal** to `bt_hci`; their
function-pointer table is in module data at `0xffffffffcf000000+` / `0xffffffffd0000000+` and is not in this
dump. Until module data is dumped (or module text single-stepped through XOM), the concrete handler
addresses cannot be enumerated. Ranked candidate *regions* for the parser code:

1. `bt_hci` module text region — largest contiguous bt module (~2.3 MiB `0xffffffff872d0000..0xffffffff8751e000`);
   highest density of public references = most likely home of the HCI command/event parsers.
2. `0xffffffff874753e0..0xffffffff87475440` stub table + its real implementations (kobj methods → the
   HCI layer's entry points for L2CAP/HID data).
3. `0xffffffff87434b40` (default method, refcount 140) — reached on unhandled HCI paths.
4. Module-A region `0xffffffff84065000..0xffffffff840cb000` (~600 KiB) — second bt module (bt_usb or
   bluetooth_hid); the USB-to-HCI bridging parser candidate.
5. `0xffffffff8b3b2b47` — isolated module fn (3 refs).

## How to actually get the tables (next step)

- Dump module data: read KVA `0xffffffffcf000000..0xffffffffd1000000` (heap/module-data) with the same
  `kernel_copyout` path that produced this dump, then re-run the stride-8/16 run scan for text-range
  pointers → the real HCI event/command handler arrays will appear.
- Or single-step/single-step the XOM module text to disassemble `bt_hci`'s event dispatcher and recover
  the in-module table addresses.
