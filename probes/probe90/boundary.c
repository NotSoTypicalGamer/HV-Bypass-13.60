/* probe90/boundary.elf — map the exact HV carve-out (CPU kernel_copyout -1 vs 0)
 * across 0x60000000..0x72000000 at 1MB granularity. Logs BEFORE each read so a panic
 * leaves its mark; carve-out (not-present) is expected to return -1 cleanly.
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
  g_logfd = open("/data/kex_boundary.txt", O_WRONLY|O_CREAT|O_TRUNC|O_SYNC, 0666);
  uint64_t dmap = (uint64_t)(uintptr_t)KERNEL_ADDRESS_DMAP_BASE;
  char b[200];
  snprintf(b,sizeof b,"boundary: kdata=0x%llx fw=0x%x",(unsigned long long)payload_get_args()->kdata_base_addr, kernel_get_fw_version());
  logline(b);

  for (uint64_t pa = 0x60000000ull; pa <= 0x72000000ull; pa += 0x100000ull) {
    snprintf(b, sizeof b, "READ 0x%llx", (unsigned long long)pa);
    logline(b);   /* log BEFORE the read so a panic leaves the last address */
    uint64_t v = 0;
    int r = kernel_copyout((intptr_t)(dmap + pa), &v, 8);
    snprintf(b, sizeof b, "   ret=%d val=0x%016llx", r, (unsigned long long)v);
    logline(b);
  }
  logline("done");
  return 0;
}
