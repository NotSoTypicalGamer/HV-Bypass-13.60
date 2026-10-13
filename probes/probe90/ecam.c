#include <stdio.h>
#include <stdint.h>
#include <ps5/kernel.h>
#include <ps5/payload.h>

extern const intptr_t KERNEL_ADDRESS_DMAP_BASE;

static uint32_t rd4(uint64_t dmap, uint64_t pa){ return kernel_getint((intptr_t)(dmap+pa)); }

int main(void){
  uint64_t dmap = (uint64_t)KERNEL_ADDRESS_DMAP_BASE;
  printf("ecam dmap=0x%llx\n", (unsigned long long)dmap);
  // VID (offset 0) + DID (offset 2) of each bus-0 device, function 0
  for(int dev=0; dev<0x20; dev++){
    uint32_t vid = rd4(dmap, 0xF0000000ull + (uint64_t)dev*0x8000);
    if(vid != 0xFFFFFFFF && vid != 0)
      printf("dev 0x%02x fn0 vid=0x%08x\n", dev, vid);
  }
  // device 0x18, all functions
  for(int fn=0; fn<8; fn++){
    uint32_t vid = rd4(dmap, 0xF0000000ull + 0x18ull*0x8000 + (uint64_t)fn*0x1000);
    if(vid != 0xFFFFFFFF)
      printf("dev 0x18 fn%d vid=0x%08x\n", fn, vid);
  }
  // raw TMR index/data at dev 0x18 fn2
  printf("fn2 @0x80=0x%08x @0x84=0x%08x\n",
    rd4(dmap, 0xF00C2000ull + 0x80), rd4(dmap, 0xF00C2000ull + 0x84));
  return 0;
}
