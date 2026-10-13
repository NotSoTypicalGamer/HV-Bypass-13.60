#include <stdio.h>
#include <stdint.h>
#include <ps5/kernel.h>
#include <ps5/payload.h>

extern const intptr_t KERNEL_ADDRESS_DMAP_BASE;

#define ECAM 0xF00C2000ULL
#define TMR_INDEX 0x80
#define TMR_DATA  0x84

static uint32_t tmr_read(uint64_t dmap, uint32_t addr){
  kernel_setint((intptr_t)(dmap + ECAM + TMR_INDEX), addr);
  return kernel_getint((intptr_t)(dmap + ECAM + TMR_DATA));
}

int main(void){
  uint64_t dmap = (uint64_t)KERNEL_ADDRESS_DMAP_BASE;
  printf("tmr: dmap=0x%llx\n", (unsigned long long)dmap);
  for(int n=0; n<22; n++){
    uint32_t b = tmr_read(dmap, n*0x10 + 0x00);
    uint32_t l = tmr_read(dmap, n*0x10 + 0x04);
    uint32_t c = tmr_read(dmap, n*0x10 + 0x08);
    if(b || l || c)
      printf("tmr[%2d] base=0x%08x pa=0x%08llx limit=0x%08x cfg=0x%08x\n",
        n, b, (unsigned long long)((uint64_t)b<<16), l, c);
  }
  uint32_t t16 = tmr_read(dmap, 16*0x10);
  uint32_t t17 = tmr_read(dmap, 17*0x10);
  printf("TMR16 ktext=0x%08x -> pa 0x%08llx\n", t16, (unsigned long long)((uint64_t)t16<<16));
  printf("TMR17 hvdata=0x%08x -> pa 0x%08llx\n", t17, (unsigned long long)((uint64_t)t17<<16));
  return 0;
}
