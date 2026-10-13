/* fwquery.elf — print firmware version to stdout and exit (for host identification). */
#include <stdio.h>
#include <ps5/kernel.h>

int main(void) {
  printf("fw=0x%x\n", kernel_get_fw_version());
  return 0;
}
