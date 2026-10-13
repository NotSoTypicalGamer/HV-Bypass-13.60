#include <stdio.h>
#include <stdint.h>
#include <ps5/kernel.h>
#include <ps5/payload.h>

extern const intptr_t KERNEL_ADDRESS_DMAP_BASE;

int main(void){
  intptr_t kb = payload_get_args()->kdata_base_addr;
  printf("ident: kdata=0x%llx fw=0x%x dmap=0x%llx\n",
    (unsigned long long)kb, kernel_get_fw_version(), (unsigned long long)(uintptr_t)KERNEL_ADDRESS_DMAP_BASE);
  return 0;
}
