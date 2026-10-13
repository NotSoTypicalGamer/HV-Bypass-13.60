/* probe93/diff.elf — locate the VMCB inside the encrypted band (0x60600000..0x607fffff)
 * by temporal diff: the VMCB's ciphertext changes on every VMEXIT (event-injection fields),
 * while the NPT / free memory is static. Read the band twice ~200ms apart, diff 4KB pages,
 * log the changing pages (the VMCB). Read-only, safe (stays inside the readable window).
 */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <ps5/kernel.h>
#include <ps5/payload.h>

extern const intptr_t KERNEL_ADDRESS_DMAP_BASE;

static int g_fd = -1;
static void logline(const char *m){ if(g_fd>=0){write(g_fd,m,strlen(m));write(g_fd,"\n",1);fsync(g_fd);} printf("%s\n",m); }

int main(void) {
  g_fd = open("/data/kex_diff.txt", O_WRONLY|O_CREAT|O_TRUNC|O_SYNC, 0666);
  uint64_t dmap = (uint64_t)(uintptr_t)KERNEL_ADDRESS_DMAP_BASE;
  char b[256];
  snprintf(b,sizeof b,"diff: fw=0x%x dmap=0x%llx", kernel_get_fw_version(), (unsigned long long)dmap);
  logline(b);

  uint64_t start = 0x60600000ull;
  uint64_t len   = 0x200000ull;   /* 2 MB, 512 pages; 0x60800000 is NDA (panic) */
  uint64_t pages = len / 0x1000;

  uint8_t *A = malloc(len);
  uint8_t *B = malloc(len);
  if (!A || !B) { logline("malloc fail"); return 1; }

  for (uint64_t o = 0; o < len; o += 0x1000)
    if (kernel_copyout((intptr_t)(dmap + start + o), A + o, 0x1000) != 0) { logline("read A fail"); return 1; }
  logline("snapshot A done");

  usleep(200000);   /* 200 ms — VMEXITs rewrite the VMCB's dynamic fields */

  for (uint64_t o = 0; o < len; o += 0x1000)
    if (kernel_copyout((intptr_t)(dmap + start + o), B + o, 0x1000) != 0) { logline("read B fail"); return 1; }
  logline("snapshot B done");

  int changed = 0;
  for (uint64_t o = 0; o < len; o += 0x1000) {
    if (memcmp(A + o, B + o, 0x1000) != 0) {
      changed++;
      snprintf(b, sizeof b, "CHANGED 0x%llx", (unsigned long long)(start + o));
      logline(b);
    }
  }
  snprintf(b, sizeof b, "changed_pages=%d/%llu", changed, (unsigned long long)pages);
  logline(b);
  logline("done");
  return 0;
}
