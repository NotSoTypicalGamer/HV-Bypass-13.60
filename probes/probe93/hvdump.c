/* probe93/hvdump.elf — dump the root-0 NPT readable window (0x605f0000..0x607fffff, 2.1 MB)
 * and characterize it: byte entropy, zero-byte fraction, x86-prologue count, VMCB-predicate scan.
 * Writes raw bytes to /data/kex_hv.bin for offline analysis. Stays strictly inside the
 * known-readable window (never touches 0x60800000+ = NDA/panic).
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
static void logline(const char *m){ printf("%s\n", m); }

int main(void) {
  uint64_t dmap = (uint64_t)(uintptr_t)KERNEL_ADDRESS_DMAP_BASE;
  char b[256];

  uint64_t start = 0x605f0000ull;
  uint64_t end   = 0x60800000ull;   /* 2.1 MB window; 0x60800000+ is NDA */
  uint64_t len   = end - start;
  snprintf(b,sizeof b,"hvdump: fw=0x%x dmap=0x%llx start=0x%llx len=0x%llx",
           kernel_get_fw_version(), (unsigned long long)dmap,
           (unsigned long long)start, (unsigned long long)len);
  logline(b);

  uint8_t *buf = (uint8_t*)malloc(len);
  if (!buf) { logline("malloc fail"); return 1; }

  uint64_t ok = 0;
  for (uint64_t off = 0; off < len; off += 0x1000) {
    int r = kernel_copyout((intptr_t)(dmap + start + off), buf + off, 0x1000);
    if (r == 0) ok++;
  }
  snprintf(b,sizeof b,"pages_read=%llu/%llu", (unsigned long long)ok, (unsigned long long)(len/0x1000));
  logline(b);

  /* byte histogram: distinct-byte count + zero/ff fraction (uniform-random -> ~256 distinct, ~0.4% zeros) */
  uint64_t hist[256] = {0};
  for (uint64_t i = 0; i < len; i++) hist[buf[i]]++;
  int distinct = 0;
  for (int i = 0; i < 256; i++) if (hist[i]) distinct++;
  snprintf(b,sizeof b,"distinct_bytes=%d/256 zeros=%.2f%% ff=%.2f%%",
           distinct, 100.0*(double)hist[0]/(double)len, 100.0*(double)hist[255]/(double)len);
  logline(b);

  /* x86 prologue count: 41 57 41 56 41 55 41 54 53 (push r15;push r14;push r13;push r12;push rbx) */
  uint64_t prologues = 0;
  static const uint8_t pro[9] = {0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53};
  for (uint64_t i = 0; i + 9 <= len; i++)
    if (memcmp(buf+i, pro, 9) == 0) prologues++;
  snprintf(b,sizeof b,"x86_prologues=%llu", (unsigned long long)prologues);
  logline(b);

  /* VMCB scan at 4KB alignment */
  uint64_t vmcb = 0;
  for (uint64_t off = 0; off < len; off += 0x1000) {
    uint64_t asid=0, np=0, ncr3=0;
    memcpy(&asid, buf+off+0x58, 8);
    memcpy(&np,   buf+off+0x90, 8);
    memcpy(&ncr3, buf+off+0xB0, 8);
    uint32_t a = (uint32_t)asid;
    if (a >= 1 && a <= 16 && (np & 1) && (ncr3 & 0xfff) == 0 && ncr3 != 0xffffffffffffffffull) {
      snprintf(b,sizeof b,"VMCB-CAND off=0x%llx pa=0x%llx asid=%u np=0x%llx ncr3=0x%llx",
               (unsigned long long)off, (unsigned long long)(start+off), a,
               (unsigned long long)np, (unsigned long long)ncr3);
      logline(b);
      vmcb++;
    }
  }
  snprintf(b,sizeof b,"vmcb_candidates=%llu", (unsigned long long)vmcb);
  logline(b);

  /* write raw dump to /data for offline pull */
  int fd = open("/data/kex_hv.bin", O_WRONLY|O_CREAT|O_TRUNC|O_SYNC, 0666);
  if (fd >= 0) { write(fd, buf, len); fsync(fd); close(fd); logline("wrote /data/kex_hv.bin"); }
  else logline("open /data/kex_hv.bin FAILED");
  logline("done");
  return 0;
}
