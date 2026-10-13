// dryrun.c — isolate the ring-0-exec primitive (syscall-hijack) WITHOUT the hypercall.
//
// Hijacks sysent[20].sy_call with a function that just returns 0x1337. If the
// hijacked syscall returns 0x1337, the ring-0 exec path (kernel calling our
// userland page) is confirmed; if it panics, the fault is in staging/hijack/exec,
// not in the vmmcall.

#include <ps5/kernel.h>
#include <ps5/payload.h>
#include <stdio.h>

extern const intptr_t KERNEL_ADDRESS_DMAP_BASE;

#define AP_RIP          0x3ffff000
#define MARKER_PA       0x40000000
#define SYSENT_OFF      0x38
#define SYSCALL_STRIDE  24
#define SY_CALL_OFF     8
#define HIJACK_SYSCALL  20

__attribute__((noinline, used))
static long dryrun_handler(void) {
    return 0x1337;
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

    FILE *log = fopen("/data/kex_dryrun.txt", "w");
    if (log) {
        fprintf(log, "kdata=0x%lx dmap=0x%llx\n", (unsigned long)kdata,
                (unsigned long long)dmap);
        fflush(log);
    }

    // verify kernel R/W works first (read the sysent slot before touching it)
    intptr_t slot = kdata + SYSENT_OFF + HIJACK_SYSCALL * SYSCALL_STRIDE + SY_CALL_OFF;
    uint64_t orig = kernel_getlong(slot);
    if (log) { fprintf(log, "sysent[%d] @ 0x%lx orig=0x%llx\n", HIJACK_SYSCALL,
                        (unsigned long)slot, (unsigned long long)orig); fflush(log); }

    // hijack -> our handler
    kernel_setlong(slot, (uint64_t)(uintptr_t)&dryrun_handler);

    long rc = raw_syscall(HIJACK_SYSCALL);
    if (log) { fprintf(log, "hijack syscall returned rc=0x%lx\n", rc); fflush(log); }

    // restore
    kernel_setlong(slot, orig);

    if (log) {
        fprintf(log, "RESULT: %s\n", (rc == 0x1337) ? "RING0 EXEC OK" : "HANDLER DID NOT RUN");
        fflush(log);
    }
    if (log) fclose(log);
    return 0;
}
