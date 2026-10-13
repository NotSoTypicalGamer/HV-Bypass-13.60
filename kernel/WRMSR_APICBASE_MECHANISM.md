# WRMSR_APICBASE_MECHANISM.md — what the 6.00–7.61 `wrmsr(MSR_APICBASE, hv_stack)` primitive actually does, and how to check if the intercept survives on 13.60

**Date:** 2026-10-06
**Question:** the 6.00–7.61 HV-defeat (`ps5-linux-loader/source/hv_defeat_0607.c`) triggers HV code
execution with `wrmsr(MSR_APICBASE, get_hv_stack() | 0x800 | 0x100)`. What is the exact HV-side
mechanism of that write — does the HV *store* the base somewhere it later dereferences/jumps to,
or does it *treat the base as an MMIO address*? And what is the **minimal** probe that tells us
whether that intercept is still live on 13.60?

**Bottom line: neither "store-to-X" nor "jump-to-X" — it is an *APIC-base relocation* plus a
`#SX` (Security Exception) injection.** The wrmsr is intercepted (VMEXIT_MSR) and the HV does
three things: (1) stores the value in its per-VCPU struct at `vc+0xe8` ("guest_apic_base"),
(2) passes the value through to the **host's real APIC_BASE MSR** — i.e. it treats the guest's
base as the hardware local-APIC MMIO address, relocating the APIC window onto whatever X is, and
(3) because the write sets the **BSP flag (bit 8)**, it injects a **`#SX` (vector 30) Security
Exception into the guest**. The directly-observable effect is that `#SX` — not a klog `#VMEXIT`
line (MSR exits are silent). HV RIP control is a *consequence* of (2): with X = the HV's own
stack (`0x628ec000`), the HV's stack region becomes the APIC MMIO window and the HV's next
exit-handler stack traffic is corrupted, so the HV resumes at PA 0 (the staged shellcode). The
BSP→`#SX` path is **patched since 8.00** (psdevwiki), so the minimal 13.60 probe is the **`#SX`
probe**, not the scratch-page write.

---

## 1. The primitive, exactly (source)

`source/hv_defeat_0607.c`, `build_gp_rop()` (firmware 6.50–7.61):

```c
#define MSR_APICBASE      0x01b
#define APICBASE_ENABLED  0x00000800   // bit 11
#define APICBASE_BSP      0x00000100   // bit 8

static uint64_t get_hv_stack(void) {
  if (fw >= 0x0700 && fw < 0x0800) return 0x628ec000;
  if (fw == 0x0650)                return 0x628d0000;
  return -1;
}

// GP ROP chain (runs on ACPI-resume #GP):
// 1. memcpy(shellcode_0607, pa_to_dmap(0), len)     -- stage HV shellcode at PA 0
// 2. wrmsr(MSR_APICBASE, get_hv_stack() | 0x800 | 0x100);
// 3. "Trigger hv code execution." -> GAD_WRMSR_RET   (wrmsr again, same RCX/RAX/RDX)
```

- Written value = `0x628ec000 | 0x800 | 0x100` = **`0x628ec900`** on fw ≥ 7.00 (base field bits
  12–35 = `0x628ec`, i.e. page-aligned base `0x628ec000`; bit 11 = APIC enabled; bit 8 = BSP).
- `0x628ec000` is **inside the HV's own carve-out** (`0x60000000–0x70000000`), the HV's stack.
  `get_hv_stack()` is the HV's *stack pointer region*, not a guest address.
- The `#GP` ROP is fired by corrupting `ACPIGBL_FACS` (AcpiSetFirmwareWakingVector self-overwrite
  during suspend) exactly like the ≤6.02 exploit; the *new* part is the wrmsr.

### 1.1 Why there are TWO wrmsr's

The chain ends in `GAD_WRMSR_RET` twice. `wrmsr;ret` does not change RCX/RAX/RDX, so **both** writes
are `wrmsr(0x1B, 0x628ec900)`. The first write corrupts `guest_apic_base` + relocates the host
APIC + arms the BSP flag; the second (`// Trigger hv code execution.`) re-enters the HV's MSR
handler with the APIC base *already* pointing at the HV stack, which is what actually diverts HV
execution to PA 0.

---

## 2. What the HV handler does on `wrmsr(MSR_APICBASE, X)` — the three confirmed effects

Confirmation comes from `shellcode_0607/main.c`, the code that runs *inside the HV* after the
hijack (staged at PA 0). It must undo everything the exploit corrupted, which enumerates the
side-effects precisely:

```c
// (a) Restore guest_apic_base  ->  the HV STORES the written value in its per-VCPU struct
*(uint64_t *)(vc + 0xe8) = DEFAULT_APIC_BASE | APICBASE_ENABLED | APICBASE_BSP; // 0xfee00900
...
// (b) Restore host apic base   ->  the HV ALSO passes the value through to the HOST MSR 0x1B
wrmsr(MSR_APICBASE, DEFAULT_APIC_BASE | APICBASE_ENABLED | APICBASE_BSP);        // 0xfee00900
// (c) Restore gs base
wrmsr(MSR_GSBASE, ((uint64_t*)HV_STACK_TABLE)[0] + 0x1000);
// then: walk hv_pml4 -> vCPU[i] -> (vCPU[i]+0x08)=VMCB -> clear NESTED_CTRL bit0 (NP_ENABLE)
//       for all 16 VMCBs, and re-enter the hypercore loop.
```

`vc` is the HV's per-VCPU context: `vc+0x08` = pointer to the VMCB, `vc+0xe8` =
**`guest_apic_base`** (the HV's shadow of the guest's APIC base). So the handler:

1. **Stores X into `vc+0xe8` (`guest_apic_base`).** This is a store *of* the value into an
   HV-private struct field — *not* a store *to* address X. Not guest-observable.
2. **Reflects X into the host's real `MSR_APICBASE`.** This is the "treat the base as an MMIO
   address" behavior: the guest's APIC base becomes the *hardware* local-APIC MMIO base. On the
   next CPU access into the 4 KB page at X, the access is decoded as an APIC access. Because the
   shellcode must `wrmsr(0x1B, 0xfee00900)` to "restore host apic base", we know the exploit's
   write did move the host APIC base to `0x628ec000`.
3. **BSP flag (bit 8) → inject `#SX`.** Setting the BSP bit is a security-sensitive event: per
   psdevwiki, "By setting the BSP (bootstrap processor) flag, the Security interrupts get
   enabled" — the HV raises/delivers a **Security Exception (`#SX`, vector 30)** into the guest.

The **#SX delivery is the directly-observable effect** and the guest-side code-exec trigger: the
exploit points the guest's `IDT[30]` at a stack-pivot gadget (`IDT_SX=30`, TSS `IST7`) so the
`#SX` runs the "SX ROP" → `memcpy(shellcode_kernel → KERNEL_CODE_CAVE)` → jump to it.
`shellcode_kernel/main.c` for fw `0x0500 ≤ fw < 0x0800` just says `// Already escaped.` — i.e.
**the HV defeat already happened in the GP ROP chain (the wrmsr), before shellcode_kernel runs.**

---

## 3. AMD SVM semantics backing this up

- **MSR intercept:** MSR `0x1B` is in the PS5 HV's MSR protection map —
  `MSR 0000001b protected: READ & WRITE` (Cryptogenic's parsed MSRPM dump, linked from psdevwiki
  `Hypervisor`). A guest `wrmsr(0x1B)` therefore raises **`VMEXIT_MSR` (exit code `0x7C`)** with
  the MSR number in EXITINFO1 and the value in the saved RAX/RDX (AMD64 SVM/Pacifica ref 33047,
  Appendix D + §2.7). Unlike the "protected → #GP" MSRs, APIC_BASE is *emulated* (the guest may
  legitimately relocate its APIC), which is why the HV handler stores + reflects instead of
  faulting.
- **`#SX` = Security Exception, vector 30.** Fault-class exception like `#GP`, pushes an error
  code (AMD64 SVM ref 33047 §3.3). On the PS5's Zen 2 the HV uses `#SX` for security-sensitive
  guest events, and the APIC-base BSP-bit write is one such event.

---

## 4. How the corrupted base yields HV RIP control (INFERRED — not publicly spelled out)

What is *confirmed*: HV shellcode is staged at **PA 0**; the host APIC base is moved to
`0x628ec000` (the HV stack); a second wrmsr "triggers hv code execution"; and the HV shellcode
that runs then restores both `guest_apic_base` and the host APIC base before re-entering the
hypercore.

The precise corrupting step is **not documented** in any public source I found (deepwiki is
indexed from a pre-7.61 commit and does not cover `hv_defeat_0607`; the releases/commit message
are terse). The consistent reading of the evidence:

> With `APIC_BASE = 0x628ec000`, any CPU access into `0x628ec000–0x628ecFFF` — *including the
> HV's own stack pushes/pops/call/ret in that window* — is decoded as a local-APIC MMIO access,
> not a DRAM access. The HV's next exit-handler invocation (the 2nd wrmsr) runs with its stack
> now overlapping the APIC window, so its `ret`/return path is corrupted and control lands at
> PA 0 (the staged HV shellcode), which then walks `hv_pml4` to clear NP_ENABLE in all 16 VMCBs.

Treat the *exact register/offset that corrupts RIP* as unknown until the aliased HV code is
disassembled. Do **not** build a 13.60 port on this paragraph — build the *probe* on §2, which is
confirmed.

---

## 5. Minimal verification on 13.60

The primitive is **"Patched: Yes since PS5 FW 8.00"** (psdevwiki §12.1). So on 13.60 the full
chain is presumably dead — but "patched" can mean *any one* of: the MSR is no longer intercepted,
the reflect-to-host is removed, the BSP→`#SX` injection is removed, or the write is now masked/#GP.
The minimal probe is the one that **disambiguates those in one shot**, and that is the **`#SX`
probe**, not the scratch-page write.

### 5.1 PRIMARY — the `#SX` probe (cheapest, most diagnostic)

1. With the kernel R/W primitive, redirect the guest `IDT[30]` (`#SX`) to a marker handler — the
   exact move `hv_defeat_0607.c` already does: `kwrite(ktext + IDT + 30*16, gate{func=pivot,
   ist=7, type=SDT_SYSIGT, dpl=KPL})` + set `COMMON_TSS.tss_ist7` (IDT stride is 16 bytes;
   `IDT_SX = 30`).
2. Execute `wrmsr(0x1B, 0xFEE00000 | 0x800 | 0x100)` — **base = the safe default**, only the BSP
   bit matters for this test. (Do NOT point the base at HV memory yet; that is the destructive
   half and only matters if the trigger is confirmed live.)
3. Observe whether the `#SX` handler ran.

| outcome | meaning |
|---|---|
| `#SX` fires (handler runs) | intercept + BSP→`#SX` emulation **still live** on 13.60; "patched since 8.00" was the full escape, not this trigger — port proceeds |
| no `#SX`, and `rdmsr(0x1B)` shows the value *took* | MSR **no longer intercepted** (write passed through to the guest's own APIC base) |
| no `#SX`, and `rdmsr(0x1B)` unchanged | write **silently masked** (handler still intercepts but drops it) |
| a `#GP` fires instead | handler now **faults** the BSP write (emulation changed to reject) |

Safety: this write *can* fault/panic on a changed 13.60 path. Run on the workhorse (10.0.0.x),
never the 11.60 Pro; capture klog **before** firing (klog is the fault-reader — `ps5-bug-hunting` /
`ps5-kernel-research` skill). A BSP-bit write is exactly the kind of security-sensitive event
whose *new* 13.60 handling is unknown until probed.

### 5.2 SECONDARY — the scratch-page probe (tests the reflect-to-host half only)

The task's suggested test — `wrmsr(0x1B, <scratch guest-physical> | 0x800)` then `kernel_copyout`
the scratch page — is worth running **only as a second signal**, and with this caveat:

> If the mechanism is §2-(2) "reflect X into the host APIC_BASE MSR", then accesses to the X page
> are decoded by the CPU as **on-die APIC MMIO, not DRAM** — so the HV's APIC traffic does **not**
> land in the scratch page. A *clean* scratch page therefore does **not** rule out a live
> intercept; it only rules out an AVIC-style "backing page in DRAM" write variant. The `#SX` probe
> (§5.1) is the reliable signal; the scratch-page probe is a discriminator *between* the
> reflect-to-hardware and backing-page models, not a liveness check.

If a scratch-page probe *does* show HV writes (non-zero APIC-register data at, e.g., the APIC ID
`+0x20`, Spurious-Interrupt Vector `+0xF0`, or EOI `+0xB0`), that confirms the HV writes APIC
state to the base as DRAM — a write-what-where — and changes the porting plan entirely (re-derive
with the guest-physical scratch page, no HV-stack guess needed). Capture klog first, and do not
set the BSP bit in this variant (you are testing the store/reflect half, not the `#SX` trigger).

### 5.3 klog observability of the `#VMEXIT` itself

There is **no** klog line for a `VMEXIT_MSR` — MSR intercepts are handled silently by the HV
(no logging in the public description of any intercept handler). The *observable* klog event is
the `#SX` (or the panic if the handler is absent/misconfigured). So do not look for a "VMEXIT"
message in klog; instrument the `#SX` vector instead.

---

## 6. Assessment for the 13.60 port

- **What survives 8.00?** The kernel-side *wrappers* around the hypercalls persist 7.61→13.60
  unchanged (see `HV_UNMAP_PT_TMR.md`), but that says nothing about this APIC-base path: the
  `wrmsr` intercept + BSP→`#SX` emulation is entirely HV-side and unreadable offline (the HV is a
  separately-loaded component; its handler code is only reachable via the NPT-alias dump).
- **The 8.00+ HV moved off `0x628xxxxx`.** Even if the intercept+`#SX` trigger were live, the
  `get_hv_stack()` anchor (`0x628ec000`) is dead on 13.60 — `kdata_1360.bin` has zero u64
  references into `0x62800000–0x62B00000` (`VMCB_PA.md` §3). A port would need the **new** HV
  stack/base recovered from the aliased HV code before it could re-derive the "reflect base onto
  the HV stack" half.
- **Order of work:** (1) `#SX` probe §5.1 — is the trigger live at all? (2) only if yes, recover
  the 13.60 HV stack/base from the NPT-alias dump to re-derive `hv_stack`. (3) The actual RIP
  hijack (§4) still needs the aliased HV code disassembled to pin the corrupting write.

---

## 7. Sources

- `ps5-linux/ps5-linux-loader` `source/hv_defeat_0607.c` (the wrmsr + "Trigger hv code execution"),
  `shellcode_0607/main.c` (the HV-side "restore guest_apic_base @ vc+0xe8" + "restore host apic
  base" + hv_pml4 VMCB walk), `shellcode_kernel/main.c` ("Already escaped." for 0x0500–0x0800),
  `include/offsets.h` (`IDT_SX=30`, `HV_CODE_CAVE_PA`, `HV_HANDLE_VMEXIT_PA`).
- psdevwiki `Vulnerabilities` §12.1 "<=7.61 - Local APIC Configuration can trigger code execution
  via a Secure Exception" (discovered TheFloW before 2026-03-06, disclosed 2026-06-30; "Patched …
  since PS5 FW 8.00") and `Hypervisor` (MSRPM + `#SX`/"security-sensitive events on AMD SVM VMM").
- AMD64 SVM "Pacifica" reference 33047 rev 3.02: `VMEXIT_MSR = 0x7C`, §2.7 MSR intercept, §3.3
  `#SX` Security Exception (vector 30, fault-class, error code).
- Cryptogenic MSRPM parse (psdevwiki gist) — `MSR 0000001b protected: READ & WRITE`.
- Prior workspace docs: `HV_UNMAP_PT_TMR.md` (0607 switches to this wrmsr primitive at 6.50),
  `VMCB_PA.md`, `HYPERCALL_PROBE.md` (ring-0 vmmcall only), `HV_RESEARCH.md` (NPT-alias lane).

## 8. Change log

- 2026-10-06: created. Pinned the exact write (`wrmsr(0x1B, 0x628ec900)` = base `0x628ec000` +
  EN|BSP); established the three confirmed handler effects (store @ `vc+0xe8`, reflect to host
  MSR 0x1B, BSP→`#SX`) from the HV-shellcode restore block; established `#SX` delivery as the
  directly-observable effect and the guest-side trigger; marked the RIP-hijack step (§4) INFERRED;
  specified the `#SX` probe as the minimal 13.60 liveness check with the scratch-page probe as a
  secondary discriminator (with the MMIO-vs-DRAM caveat).
