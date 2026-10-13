/* probe90/leafsize.elf — does garlic allocation SIZE force 8KB (system-RAM-capable) leaves?
 * Allocate garlic buffers at several sizes, walk the dev vmid, report each buffer's leaf
 * size (2MB vs 8KB). Log: /data/kex_leafsize.txt
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <ps5/kernel.h>
#include <ps5/payload.h>

extern const intptr_t KERNEL_ADDRESS_DMAP_BASE;

#define PROT_GPU_READ   0x10
#define PROT_GPU_WRITE  0x20
#define MAP_NO_COALESCE 0x00400000u
#define DMEM_TYPE_GARLIC 0xb
#define DMEM_RANGE_END   0x400000000ull

#define GPU_PDE_VALID   0x1ull
#define GPU_PDE_IS_PTE  (1ull << 54)
#define GPU_PDE_TF      (1ull << 56)
#define GPU_ADDR_MASK   0x0000FFFFFFFFFFC0ull
#define GPU_ADDR_8K_MASK 0x0000FFFFFFFFE000ull
#define GPU_ADDR_2M_MASK 0x0000FFFFFFE00000ull

#define GVMSPACE_SIZE        0x100
#define GVMSPACE_PAGE_DIR_VA 0x38
#define DATA_BASE_GVMSPACE   0x2EEA570u

#define CPU_PG_V     0x001ull
#define CPU_PG_FRAME 0x000FFFFFFFFFF000ull
#define RAM_MAX      0x400000000ull

static int      g_logfd = -1;
static uint64_t g_dmap;

static void logline(const char *m){ if(g_logfd>=0){write(g_logfd,m,strlen(m));write(g_logfd,"\n",1);fsync(g_logfd);} printf("%s\n",m); }

typedef int (*fn_alloc_dmem)(off_t, off_t, size_t, size_t, int, off_t *);
typedef int (*fn_map_dmem)(void **, size_t, int, int, off_t, size_t);
typedef int (*fn_release_dmem)(off_t, size_t);
static fn_alloc_dmem   p_AllocateDirectMemory;
static fn_map_dmem     p_MapDirectMemory;
static fn_release_dmem p_ReleaseDirectMemory;

static int read_phys(uint64_t pa, uint64_t *out){ if(pa>=RAM_MAX) return -1; return kernel_copyout((intptr_t)(g_dmap+pa), out, 8)==0; }

typedef struct { uint64_t gva, phys, pte_pa, raw; int is_2m; } leaf_t;
#define MAX_LEAVES 65536
static leaf_t leaves[MAX_LEAVES];
static int     nleaves = 0;

static void add_leaf(uint64_t gva,uint64_t phys,uint64_t pte_pa,uint64_t raw,int is_2m){
  if(nleaves<MAX_LEAVES){leaves[nleaves].gva=gva;leaves[nleaves].phys=phys;leaves[nleaves].pte_pa=pte_pa;leaves[nleaves].raw=raw;leaves[nleaves].is_2m=is_2m;}
  nleaves++;
}
static void walk_vmid(intptr_t gvmspace_base,int vmid){
  uint64_t page_dir_va=kernel_getlong(gvmspace_base+(intptr_t)vmid*GVMSPACE_SIZE+GVMSPACE_PAGE_DIR_VA);
  if(!page_dir_va) return;
  for(int i4=0;i4<512;i4++){
    uint64_t pml4e;
    if(kernel_copyout((intptr_t)(page_dir_va+i4*8),&pml4e,8)!=0||!(pml4e&GPU_PDE_VALID)) continue;
    uint64_t pdpt_pa=pml4e&GPU_ADDR_MASK;
    for(int i3=0;i3<512;i3++){
      uint64_t pdpe;
      if(!read_phys(pdpt_pa+i3*8,&pdpe)||!(pdpe&GPU_PDE_VALID)) continue;
      uint64_t pd_pa=pdpe&GPU_ADDR_MASK;
      for(int i2=0;i2<512;i2++){
        uint64_t pde;
        if(!read_phys(pd_pa+i2*8,&pde)||!(pde&GPU_PDE_VALID)) continue;
        uint64_t gva2=((uint64_t)i4<<39)|((uint64_t)i3<<30)|((uint64_t)i2<<21);
        if(pde&GPU_PDE_IS_PTE){ add_leaf(gva2,pde&GPU_ADDR_MASK,pd_pa+i2*8,pde,1); }
        else {
          uint64_t frag=(pde>>59)&0x1F, ptb_pa=pde&GPU_ADDR_MASK;
          for(int i1=0;i1<256;i1++){
            uint64_t pte;
            if(!read_phys(ptb_pa+i1*8,&pte)||!(pte&GPU_PDE_VALID)) continue;
            if((pte&GPU_PDE_TF)&&frag==4){
              uint64_t subtab=pte&GPU_ADDR_MASK;
              for(int i1b=0;i1b<8;i1b++){
                uint64_t leaf;
                if(!read_phys(subtab+i1b*8,&leaf)||!(leaf&GPU_PDE_VALID)) continue;
                add_leaf(gva2|((uint64_t)i1<<16)|((uint64_t)i1b<<13),leaf&GPU_ADDR_8K_MASK,subtab+i1b*8,leaf,0);
              }
            } else {
              uint64_t shift=(frag==1)?13:16;
              add_leaf(gva2|((uint64_t)i1<<shift),pte&GPU_ADDR_MASK,ptb_pa+i1*8,pte,0);
            }
          }
        }
      }
    }
  }
}

int main(void){
  g_logfd=open("/data/kex_leafsize.txt",O_WRONLY|O_CREAT|O_TRUNC|O_SYNC,0666);
  g_dmap=(uint64_t)(uintptr_t)KERNEL_ADDRESS_DMAP_BASE;
  char b[256];
  intptr_t kb=payload_get_args()->kdata_base_addr;

  p_AllocateDirectMemory=(fn_alloc_dmem)dlsym(RTLD_DEFAULT,"sceKernelAllocateDirectMemory");
  p_MapDirectMemory=(fn_map_dmem)dlsym(RTLD_DEFAULT,"sceKernelMapDirectMemory");
  p_ReleaseDirectMemory=(fn_release_dmem)dlsym(RTLD_DEFAULT,"sceKernelReleaseDirectMemory");
  if(!p_AllocateDirectMemory||!p_MapDirectMemory){ logline("FAIL: resolve"); return 1; }

  snprintf(b,sizeof b,"leafsize: kdata=0x%llx fw=0x%x",(unsigned long long)kb,kernel_get_fw_version());
  logline(b);

  int prot=PROT_READ|PROT_WRITE|PROT_GPU_READ|PROT_GPU_WRITE;
  size_t sizes[]={0x10000,0x40000,0x100000,0x200000};   /* 64K, 256K, 1M, 2M */
  enum{NSZ=4};
  void *gva[NSZ]={0}; off_t goff[NSZ]={0};
  for(int i=0;i<NSZ;i++){
    if(p_AllocateDirectMemory(0,DMEM_RANGE_END,sizes[i],sizes[i],DMEM_TYPE_GARLIC,&goff[i])!=0||
       p_MapDirectMemory(&gva[i],sizes[i],prot,MAP_NO_COALESCE,goff[i],sizes[i])!=0){
      snprintf(b,sizeof b,"alloc/map fail size=0x%zx",sizes[i]); logline(b); return 1;
    }
    snprintf(b,sizeof b,"alloc size=0x%zx va=0x%llx off=0x%llx",sizes[i],(unsigned long long)(uintptr_t)gva[i],(unsigned long long)goff[i]);
    logline(b);
  }

  intptr_t gvmspace_base=(intptr_t)kb+(intptr_t)DATA_BASE_GVMSPACE;
  int dev_vmid=-1;
  for(int vm=0;vm<16&&dev_vmid<0;vm++){
    nleaves=0; memset(leaves,0,sizeof leaves);
    walk_vmid(gvmspace_base,vm);
    int n=nleaves<MAX_LEAVES?nleaves:MAX_LEAVES;
    for(int i=0;i<n;i++) if(leaves[i].gva==(uint64_t)(uintptr_t)gva[0]){dev_vmid=vm;break;}
  }
  snprintf(b,sizeof b,"dev vmid=%d",dev_vmid); logline(b);
  if(dev_vmid<0){ logline("FAIL: no dev vmid"); return 1; }

  nleaves=0; memset(leaves,0,sizeof leaves);
  walk_vmid(gvmspace_base,dev_vmid);
  int n=nleaves<MAX_LEAVES?nleaves:MAX_LEAVES;
  int n2m=0,n8k=0;
  for(int i=0;i<n;i++){ if(leaves[i].is_2m) n2m++; else n8k++; }
  snprintf(b,sizeof b,"dev vmid leaves: 2MB=%d 8KB=%d",n2m,n8k); logline(b);

  for(int i=0;i<NSZ;i++){
    uint64_t va=(uint64_t)(uintptr_t)gva[i];
    int found=0; const char *kind="none";
    for(int j=0;j<n;j++){
      if(leaves[j].gva==va){ kind=leaves[j].is_2m?"2MB":"8KB"; found=1;
        snprintf(b,sizeof b,"  va=0x%llx size=0x%zx -> %s leaf raw=0x%016llx phys=0x%llx",
          (unsigned long long)va,sizes[i],kind,(unsigned long long)leaves[j].raw,(unsigned long long)leaves[j].phys);
        logline(b); break; }
    }
    if(!found){ snprintf(b,sizeof b,"  va=0x%llx size=0x%zx -> NOT FOUND",(unsigned long long)va,sizes[i]); logline(b); }
  }
  for(int i=0;i<NSZ;i++) p_ReleaseDirectMemory(goff[i],sizes[i]);
  logline("done");
  return 0;
}
