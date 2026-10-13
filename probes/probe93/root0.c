/* probe93/root0.elf — read the HV's own physical memory (root-0 NPT) at host-PA
 * 0x800000000..0x900000000 via the DMAP. Logs BEFORE each read so a panic marks the
 * faulting address. The root-0 NPT should map this range readable (Sonic-Iso, ≤14.00).
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
  g_logfd = open("/data/kex_root0.txt", O_WRONLY|O_CREAT|O_TRUNC|O_SYNC, 0666);
  uint64_t dmap = (uint64_t)(uintptr_t)KERNEL_ADDRESS_DMAP_BASE;
  char b[256];
  snprintf(b,sizeof b,"root0: kdata=0x%llx fw=0x%x dmap=0x%llx",
           (unsigned long long)payload_get_args()->kdata_base_addr,
           kernel_get_fw_version(), (unsigned long long)dmap);
  logline(b);

  /* control reads first (known-safe) */
  static const uint64_t ctrl[] = { 0x0ull, 0x60000000ull, 0x100000000ull };
  for (int i = 0; i < 3; i++) {
    uint64_t v = 0;
    snprintf(b, sizeof b, "READ 0x%llx", (unsigned long long)ctrl[i]);
    logline(b);
    int r = kernel_copyout((intptr_t)(dmap + ctrl[i]), &v, 8);
    snprintf(b, sizeof b, "   ret=%d val=0x%016llx", r, (unsigned long long)v);
    logline(b);
  }

  /* the HV host-PA range 32..40 GB, 256MB steps */
  for (uint64_t pa = 0x800000000ull; pa < 0x1000000000ull; pa += 0x10000000ull) {
    uint64_t v = 0;
    snprintf(b, sizeof b, "READ 0x%llx", (unsigned long long)pa);
    logline(b);
    int r = kernel_copyout((intptr_t)(dmap + pa), &v, 8);
    snprintf(b, sizeof b, "   ret=%d val=0x%016llx", r, (unsigned long long)v);
    logline(b);
  }
  logline("done");
  return 0;
}
