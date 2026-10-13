/* probe90/verify_carveout.elf — confirm the CPU (kernel_copyout / DMAP) CANNOT read
 * the carve-out (expect -1 / panic), establishing that the GPU-DMA READ that returned
 * data from the same physical range is a genuine NPT bypass.
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
  g_logfd = open("/data/kex_verifycarveout.txt", O_WRONLY|O_CREAT|O_TRUNC|O_SYNC, 0666);
  uint64_t dmap = (uint64_t)(uintptr_t)KERNEL_ADDRESS_DMAP_BASE;
  char b[200];
  intptr_t kb = payload_get_args()->kdata_base_addr;
  snprintf(b,sizeof b,"verify_carveout: kdata=0x%llx fw=0x%x",(unsigned long long)kb,kernel_get_fw_version());
  logline(b);

  uint64_t addrs[] = {0x60000000ull, 0x60100000ull, 0x62000000ull, 0x6f000000ull};
  for (int i = 0; i < 4; i++) {
    uint64_t pa = addrs[i];
    uint64_t v = 0xDEADBEEFDEADBEEFull;
    int r = kernel_copyout((intptr_t)(dmap + pa), &v, 8);
    snprintf(b, sizeof b, "kernel_copyout(0x%llx) ret=%d val=0x%016llx",
             (unsigned long long)pa, r, (unsigned long long)v);
    logline(b);
  }
  logline("done");
  return 0;
}
