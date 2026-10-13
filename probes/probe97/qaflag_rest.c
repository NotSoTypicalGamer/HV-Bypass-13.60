/* probe97/qaflag_rest.elf — §(d) QA-flag negative test.
 * Set qa_flags[1] |= 0x02 (System Level debugger) then enter rest mode.
 * On resume the user re-JBs and a rescan probe checks 0x605f0000-0x607fffff
 * for a bit-58-cleared / plaintext window.
 */
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <dlfcn.h>
#include <ps5/kernel.h>

int sceKernelOpenEventFlag(void *, const char *);
int sceKernelNotifySystemSuspendStart(void);
int sceKernelSetEventFlag(void *, int);
int sceKernelCloseEventFlag(void *);

int main(void) {
  uint8_t qa[16];
  kernel_get_qaflags(qa);
  printf("qaflag: before = %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x\n",
         qa[0],qa[1],qa[2],qa[3], qa[4],qa[5],qa[6],qa[7],
         qa[8],qa[9],qa[10],qa[11], qa[12],qa[13],qa[14],qa[15]);

  qa[1] |= 0x02;   /* System Level (SL) debugging flag */
  int r = kernel_set_qaflags(qa);
  printf("qaflag: set_qaflags ret=%d\n", r);

  uint8_t qb[16];
  kernel_get_qaflags(qb);
  printf("qaflag: after  = %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x\n",
         qb[0],qb[1],qb[2],qb[3], qb[4],qb[5],qb[6],qb[7],
         qb[8],qb[9],qb[10],qb[11], qb[12],qb[13],qb[14],qb[15]);

  /* rest mode */
  void *event = NULL;
  int rr = sceKernelOpenEventFlag(&event, "SceSystemStateMgrStatus");
  printf("qaflag: OpenEventFlag=%d ev=%p\n", rr, event);
  if (rr != 0) return 1;

  rr = sceKernelNotifySystemSuspendStart();
  printf("qaflag: NotifySystemSuspendStart=%d\n", rr);

  rr = sceKernelSetEventFlag(event, 0x400);
  printf("qaflag: SetEventFlag(0x400)=%d\n", rr);

  sceKernelCloseEventFlag(&event);
  printf("qaflag: done — entering rest mode, press power to resume\n");
  return 0;
}
