
jit_syscall = {}

function jit_syscall.init()    
    jit_syscall.collect_info()
    
    if PLATFORM == "PS4" then
        -- Reuse syscall.syscall_wrapper offsets, rebased to JIT_LIBKERNEL_BASE
        local base_delta = JIT_LIBKERNEL_BASE - LIBKERNEL_BASE
        jit_syscall.syscall_wrapper = {}
        for num, addr in pairs(syscall.syscall_wrapper) do
            jit_syscall.syscall_wrapper[num] = addr + base_delta
        end
    elseif PLATFORM == "PS5" then
        jit_syscall.syscall_address = jit_getpid_addr + 7
    else
        error("invalid platform " .. PLATFORM)
    end

    jit_syscall.resolve(SYSCALL_TABLE)
    jit_syscall.do_sanity_check()
end


function jit_syscall.collect_info()
    local INIT_PROC_ADDR_OFFSET = 0x128
    local SEGMENTS_OFFSET = 0x160
    
    local addr_inside_libkernel = jit_getpid_addr
    local mod_info = OOB_SCRATCH_BASE + 0x6000
    
    local ret = jit_sceKernelGetModuleInfoFromAddr(addr_inside_libkernel, 1, mod_info)
    if ret ~= 0 then
        error("jit_sceKernelGetModuleInfoFromAddr error: " .. to_hex(ret))
    end
    
    JIT_LIBKERNEL_BASE = read64(mod_info + SEGMENTS_OFFSET)
end


function jit_syscall.resolve(list)
    for name, num in pairs(list) do
        if not jit_syscall[name] then
            if PLATFORM == "PS4" then
                if jit_syscall.syscall_wrapper[num] then
                    jit_syscall[name] = jit_func_wrap_with_rax(jit_syscall.syscall_wrapper[num], num)
                else
                    error(string.format("jit_syscall wrapper for %s (%d) not found in libkernel", name, num))
                end
            elseif PLATFORM == "PS5" then
                jit_syscall[name] = jit_func_wrap_with_rax(jit_syscall.syscall_address, num)
            end
        end
    end
end

function jit_syscall.do_sanity_check()
    local pid = jit_syscall.getpid(20)
    if not (pid and pid ~= 0) then
        error("jit_syscall test failed")
    end
end