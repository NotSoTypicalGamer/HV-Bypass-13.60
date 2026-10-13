/* probe93/carveout.elf — scan the HV carve-out (0x60000000..0x72000000) at 4 KB steps
 * for READABLE pages (r=0). On this boot the carve-out reads -1 (not-present); the root-0
 * NPT bug (Sonic-Iso, ≤14.00) flips any HV-owned page to present+readable, and the VMCB
 * lives here. Safe: not-present returns -1, no panic. Logs to /data/kex_carveout.txt.
 */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <ps5/kernel.h>
#include <ps5/payload.h>

extern const intptr_t KERNEL_ADDRESS_DMAP_BASE;

static int g_logfd = -1;
static void logline(const char *m){ if(g_logfd>=0){write(g_logfd,m,strlen(m));write(g_logfd,"\n",1);fsync(g_logfd);} printf("%s\n",m); }

int main(void) {
  g_logfd = open("/data/kex_carveout.txt", O_WRONLY|O_CREAT|O_TRUNC|O_SYNC, 0666);
  uint64_t dmap = (uint64_t)(uintptr_t)KERNEL_ADDRESS_DMAP_BASE;
  char b[256];
  snprintf(b,sizeof b,"carveout: fw=0x%x dmap=0x%llx", kernel_get_fw_version(), (unsigned long long)dmap);
  logline(b);

  uint64_t start = 0x60000000ull;
  uint64_t end   = 0x72000000ull;
  uint64_t readable = 0;
  for (uint64_t pa = start; pa < end; pa += 0x1000ull) {
    if ((pa & 0x7fffffull) == 0) {   /* progress every 8 MB */
      snprintf(b, sizeof b, "PROG 0x%llx (readable=%llu)", (unsigned long long)pa, (unsigned long long)readable);
      logline(b);
    }
    uint64_t v = 0;
    int r = kernel_copyout((intptr_t)(dmap + pa), &v, 8);
    if (r == 0) {
      readable++;
      /* VMCB predicate: asid@0x58 1..16, np_enable@0x90 bit0, n_cr3@0xB0 4K-aligned */
      uint64_t asid=0, np=0, ncr3=0;
      kernel_copyout((intptr_t)(dmap + pa + 0x58), &asid, 8);
      kernel_copyout((intptr_t)(dmap + pa + 0x90), &np, 8);
      kernel_copyout((intptr_t)(dmap + pa + 0xB0), &ncr3, 8);
      uint32_t a = (uint32_t)asid;
      if (a >= 1 && a <= 16 && (np & 1) && (ncr3 & 0xfff) == 0 && ncr3 != 0xffffffffffffffffull) {
        snprintf(b, sizeof b, "VMCB-CAND 0x%llx asid=%u np=0x%llx ncr3=0x%llx",
                 (unsigned long long)pa, a, (unsigned long long)np, (unsigned long long)ncr3);
        logline(b);
      } else {
        snprintf(b, sizeof b, "READABLE 0x%llx val=0x%016llx", (unsigned long long)pa, (unsigned long long)v);
        logline(b);
      }
    }
  }
  snprintf(b, sizeof b, "done readable=%llu", (unsigned long long)readable);
  logline(b);
  return 0;
}
