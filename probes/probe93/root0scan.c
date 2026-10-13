/* probe93/root0scan.elf — fine sweep of the HV's host-PA (root-0 NPT) for the VMCB.
 * Scans 0x800000000..0x880000000 (32..34 GB, the known-readable window) at 2 MB steps,
 * reads the VMCB predicate fields (asid@0x58, np_enable@0x90, n_cr3@0xB0) and logs
 * candidates. Progress marker before every read so a panic leaves its exact address.
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
static int read64(uint64_t dmap, uint64_t pa, uint64_t *out){
  return kernel_copyout((intptr_t)(dmap + pa), out, 8);
}

int main(void) {
  g_logfd = open("/data/kex_root0scan.txt", O_WRONLY|O_CREAT|O_TRUNC|O_SYNC, 0666);
  uint64_t dmap = (uint64_t)(uintptr_t)KERNEL_ADDRESS_DMAP_BASE;
  char b[256];
  snprintf(b,sizeof b,"root0scan: dmap=0x%llx fw=0x%x", (unsigned long long)dmap, kernel_get_fw_version());
  logline(b);

  uint64_t base = 0x880000000ull;
  uint64_t end  = 0xa00000000ull;   /* 34..40 GB */
  for (uint64_t pa = base; pa < end; pa += 0x200000ull) {
    snprintf(b, sizeof b, "READ 0x%llx", (unsigned long long)pa);
    logline(b);   /* mark BEFORE the read so a panic leaves the exact address */
    uint64_t asid=0, np=0, ncr3=0;
    read64(dmap, pa + 0x58, &asid);
    read64(dmap, pa + 0x90, &np);
    read64(dmap, pa + 0xB0, &ncr3);
    uint32_t a = (uint32_t)asid;
    if (a >= 1 && a <= 16 && (np & 1) && (ncr3 & 0xfff) == 0 && ncr3 != 0xffffffffffffffffull) {
      snprintf(b, sizeof b, "VMCB-CAND 0x%llx asid=%u np=0x%llx ncr3=0x%llx",
               (unsigned long long)pa, a, (unsigned long long)np, (unsigned long long)ncr3);
      logline(b);
    }
  }
  logline("done");
  return 0;
}
