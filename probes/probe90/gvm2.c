#include <stdio.h>
#include <stdint.h>
#include <ps5/kernel.h>
#include <ps5/payload.h>

struct idtr_t { uint16_t limit; uint64_t base; } __attribute__((packed));

int main(void){
  struct idtr_t idtr; asm volatile("sidt %0" : "=m"(idtr));
  uint64_t idt = idtr.base;
  printf("idt base=0x%llx limit=0x%x\n", (unsigned long long)idt, idtr.limit);
  intptr_t kb = payload_get_args()->kdata_base_addr;
  printf("idt - kdata = 0x%llx\n", (unsigned long long)(idt - (uint64_t)kb));
  intptr_t gvm = (intptr_t)(idt - 0x9D90ull);
  printf("gvmspace (idt-0x9D90)=0x%llx\n", (unsigned long long)gvm);
  for(int vm=0; vm<16; vm++){
    intptr_t pdv = kernel_getlong(gvm + vm*0x100 + 0x38);
    if(pdv) printf("vm%d page_dir_va=0x%llx\n", vm, (unsigned long long)pdv);
  }
  return 0;
}
