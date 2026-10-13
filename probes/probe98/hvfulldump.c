/* hvfulldump.c — dump EVERY readable non-zero page in the lucky-boot HV-alias range
 * (0x7d00000..0x5ff00000), not just the SVM-dense clusters. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <ps5/kernel.h>
#include <sys/stat.h>

extern const intptr_t KERNEL_ADDRESS_DMAP_BASE;

#define PAGE 4096u
#define START 0x7d00000ull
#define END   0x5ff00000ull

int main(void) {
  static unsigned char page[PAGE];
  char b[256];
  mkdir("/mnt/usb0/hvfulldump", 0777);
  unsigned long dumped = 0;
  for (uint64_t off = START; off < END; off += PAGE) {
    int32_t r = kernel_copyout(KERNEL_ADDRESS_DMAP_BASE + (intptr_t)off, page, PAGE);
    if (r != 0) continue;                       /* not present / trapped */
    int nonzero = 0;
    for (int i = 0; i < PAGE; i++) { if (page[i]) { nonzero = 1; break; } }
    if (!nonzero) continue;
    char name[96];
    snprintf(name, sizeof name, "/mnt/usb0/hvfulldump/page_%llx.bin", (unsigned long long)off);
    int d = open(name, O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, 0666);
    if (d >= 0) { write(d, page, PAGE); fsync(d); close(d); }
    dumped++;
    if ((off & (256ull * 1024ull * 1024ull - 1)) == 0) {
      snprintf(b, sizeof b, "dumped %lu pages at 0x%llx", dumped, (unsigned long long)off);
      printf("%s\n", b);
    }
  }
  snprintf(b, sizeof b, "DONE dumped=%lu", dumped);
  printf("%s\n", b);
  int df = open("/mnt/usb0/hvfulldump/DONE.txt", O_WRONLY | O_CREAT | O_TRUNC, 0666);
  if (df >= 0) { snprintf(b, sizeof b, "dumped=%lu\n", dumped); write(df, b, strlen(b)); fsync(df); close(df); }
  return 0;
}
