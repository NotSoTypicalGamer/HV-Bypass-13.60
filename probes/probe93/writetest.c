/* probe93/writetest.elf — test whether the root-0 NPT window (0x605f0000) is WRITABLE.
 * Reads baseline, writes a sentinel via a direct ring-0 store (goes through the NPT),
 * reads back. Logs to /data/kex_wt.txt + stdout, fsync before the write so a panic
 * (W-bit clear -> #NPF) leaves the exact address. Recoverable (ciphertext boot, not lucky).
 */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <ps5/kernel.h>
#include <ps5/payload.h>

extern const intptr_t KERNEL_ADDRESS_DMAP_BASE;

static int g_fd = -1;
static void logline(const char *m){ if(g_fd>=0){write(g_fd,m,strlen(m));write(g_fd,"\n",1);fsync(g_fd);} printf("%s\n",m); }

int main(void) {
  g_fd = open("/data/kex_wt.txt", O_WRONLY|O_CREAT|O_TRUNC|O_SYNC, 0666);
  uint64_t dmap = (uint64_t)(uintptr_t)KERNEL_ADDRESS_DMAP_BASE;
  char b[256];
  snprintf(b,sizeof b,"wt: fw=0x%x dmap=0x%llx", kernel_get_fw_version(), (unsigned long long)dmap);
  logline(b);

  uint64_t addr = dmap + 0x605f0000ull;
  uint64_t before=0, after=0;
  kernel_copyout((intptr_t)addr, &before, 8);
  snprintf(b,sizeof b,"before=0x%016llx", (unsigned long long)before);
  logline(b);

  logline("WRITE 0x605f0000 sentinel=0x1122334455667788 (kernel_setlong)");
  int wr = kernel_setlong((intptr_t)addr, 0x1122334455667788ull);
  snprintf(b,sizeof b,"kernel_setlong rc=%d", wr);
  logline(b);

  kernel_copyout((intptr_t)addr, &after, 8);
  snprintf(b,sizeof b,"after=0x%016llx", (unsigned long long)after);
  logline(b);

  if (after == 0x1122334455667788ull) logline("WRITABLE");
  else logline("NOT-WRITABLE-or-encrypted");
  logline("done");
  return 0;
}
