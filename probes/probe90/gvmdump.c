#include <stdio.h>
#include <stdint.h>
#include <ps5/kernel.h>
#include <ps5/payload.h>

extern const intptr_t KERNEL_ADDRESS_DMAP_BASE;

int main(void){
  intptr_t kb = payload_get_args()->kdata_base_addr;
  intptr_t gvm = kb + 0x2EEA570ull;
  printf("gvmspace base=0x%llx kdata=0x%llx\n", (unsigned long long)gvm, (unsigned long long)kb);
  for(int vm=0; vm<16; vm++){
    intptr_t pdv = kernel_getlong(gvm + vm*0x100 + 0x38);
    printf("vm%d page_dir_va=0x%llx\n", vm, (unsigned long long)pdv);
  }
  return 0;
}
