/* dpi_escalate.c — escalation watchdog for DPI v2 v1.2 on FW 11.00+ (13.60).
 *
 * DPI v2 v1.2 calls sceAppInstUtilInitialize() at startup without first setting
 * SYSTEM_AUTHID, which on FW 11.00+ makes init return -0xDEAD and every install
 * silently fail. This payload escalates itself, then loops escalating any OTHER
 * process whose authid is still 0 (the payload default), catching the DPI the
 * instant it is spawned. Deploy this FIRST, then deploy DPiv2_1.2.bin.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/sysctl.h>
#include <ps5/kernel.h>

#define SYSTEM_AUTHID 0x4800000000010003L

static int g_logfd = -1;

static void logline(const char *m) {
  if (g_logfd >= 0) { write(g_logfd, m, strlen(m)); write(g_logfd, "\n", 1); fsync(g_logfd); }
  printf("%s\n", m);
}

/* escalate every process (except self) whose authid is 0 -> SYSTEM_AUTHID */
static int escalate_zero_authid(pid_t self) {
  int mib[4] = {1, 14, 8, 0};   /* CTL_KERN=1, KERN_PROC=14, KERN_PROC_ALL=0 */
  size_t sz = 0;
  uint8_t *buf;
  int n = 0;

  if (sysctl(mib, 4, 0, &sz, 0, 0)) return -1;
  if (!(buf = malloc(sz))) return -1;
  if (sysctl(mib, 4, buf, &sz, 0, 0)) { free(buf); return -1; }

  for (uint8_t *p = buf; p < (buf + sz); ) {
    int ki_structsize = *(int *)p;
    pid_t pid = *(pid_t *)&p[72];
    char *tdname = (char *)&p[447];
    p += ki_structsize;
    if (pid <= 0 || pid == self) continue;
    if (ki_structsize < 448) continue;
    uint64_t authid = kernel_get_ucred_authid(pid);
    if (authid == 0) {
      kernel_set_ucred_authid(pid, SYSTEM_AUTHID);
      kernel_set_proc_rootdir(pid, kernel_get_root_vnode());
      char b[256];
      snprintf(b, sizeof b, "escalated pid=%d name=%s authid->0x4801...0003", pid, tdname);
      logline(b);
      n++;
    }
  }
  free(buf);
  return n;
}

int main(void) {
  g_logfd = open("/data/dpi_escalate.log", O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, 0666);
  pid_t self = getpid();

  kernel_set_ucred_authid(self, SYSTEM_AUTHID);
  kernel_set_proc_rootdir(self, kernel_get_root_vnode());
  char b[256];
  snprintf(b, sizeof b, "dpi_escalate: self=%d escalated, watching for DPI...", self);
  logline(b);

  for (int i = 0; i < 300; i++) {   /* ~30 s of watching */
    int n = escalate_zero_authid(self);
    if (n > 0) {
      snprintf(b, sizeof b, "watch tick %d: escalated %d process(es)", i, n);
      logline(b);
    }
    usleep(100 * 1000);
  }
  logline("dpi_escalate: done watching");
  return 0;
}
