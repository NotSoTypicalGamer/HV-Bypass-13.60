#include <stdio.h>
#include <stdint.h>
#include <ps5/kernel.h>
#include <ps5/payload.h>

/* scan the kernel BSS for the gvmspace array: 16 entries x 0x100,
 * page_dir_va at +0x38. Active vmids on 11.60 = 4 (compositor) + 6 (dev).
 * Look for entries 4 and 6 having a DMAP-ish kernel VA (0xffffff80...). */
int main(void){
  intptr_t kb = payload_get_args()->kdata_base_addr;
  printf("scan kdata=0x%llx\n", (unsigned long long)kb);
  int fields[5] = {0x30, 0x38, 0x40, 0x48, 0x50};
  int n=0;
  for(intptr_t off = 0x200000; off < 0x3000000 && n<20; off += 0x100){
    intptr_t o = kb + off;
    for(int fi=0; fi<5; fi++){
      intptr_t p4 = kernel_getlong(o + 4*0x100 + fields[fi]);
      intptr_t p6 = kernel_getlong(o + 6*0x100 + fields[fi]);
      int ok4 = ((uint64_t)p4 >> 48) == 0xffff;
      int ok6 = ((uint64_t)p6 >> 48) == 0xffff;
      if(ok4 && ok6){
        printf("CAND off=0x%llx f=0x%x p4=0x%llx p6=0x%llx\n",
          (unsigned long long)off, fields[fi], (unsigned long long)p4, (unsigned long long)p6);
        n++;
        break;
      }
    }
  }
  printf("scan done candidates=%d\n", n);
  return 0;
}
