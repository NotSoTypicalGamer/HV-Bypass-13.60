#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ps5/kernel.h>
#include <ps5/payload.h>

int main(void){
  printf("gvm3 start\n");
  uint8_t idt[10]; memset(idt,0,sizeof idt);
  asm volatile("sidt %0" : "=m"(*idt) : : "memory");
  uint64_t idt_base; memcpy(&idt_base, idt+2, 8);
  printf("idt base=0x%llx\n", (unsigned long long)idt_base);
  intptr_t kb = payload_get_args()->kdata_base_addr;
  printf("idt - kdata = 0x%llx\n", (unsigned long long)(idt_base - (uint64_t)kb));
  intptr_t gvm = (intptr_t)(idt_base - 0x9D90ull);
  printf("gvm (idt-0x9D90)=0x%llx\n", (unsigned long long)gvm);
  for(int vm=0; vm<16; vm++){
    intptr_t pdv = kernel_getlong(gvm + vm*0x100 + 0x38);
    if(pdv) printf("vm%d page_dir_va=0x%llx\n", vm, (unsigned long long)pdv);
  }
  printf("gvm3 done\n");
  return 0;
}
