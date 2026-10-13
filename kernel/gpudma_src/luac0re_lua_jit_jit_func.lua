
function jit_func_wrap(function_address)
    return function(arg1, arg2, arg3, arg4, arg5, arg6)
        return jit_rop(function_address, 0, arg1, arg2, arg3, arg4, arg5, arg6)
    end
end

function jit_func_wrap_with_rax(function_address, rax)
    return function(arg1, arg2, arg3, arg4, arg5, arg6)
        return jit_rop(function_address, rax, arg1, arg2, arg3, arg4, arg5, arg6)
    end
end

function jit_init_native_functions()

    jit_getpid_addr = jit_read64(JIT_BASE + 0x1B5160)
    jit_calloc_addr = jit_read64(JIT_BASE + 0x1B5020)
    jit_sceKernelJitCreateSharedMemory_addr = jit_read64(JIT_BASE + 0x1B52C0)
    jit_sceKernelJitCreateAliasOfSharedMemory_addr = jit_read64(JIT_BASE + 0x1B52C8)
    jit_sceKernelJitMapSharedMemory_addr = jit_read64(JIT_BASE + 0x1B52B8)
    
    JIT_LIBC_BASE = jit_calloc_addr - 0x1F820    

    jit_libc_error_addr = JIT_LIBC_BASE + 0x258
    
    jit_sceKernelGetModuleInfoFromAddr_addr = jit_read64(JIT_LIBC_BASE + 0xCBDA8)
    
    jit_memcpy_addr = jit_read64(JIT_BASE + 0x1B53E8)
    jit_memset_addr = jit_read64(JIT_BASE + 0x1B53F8)
    
    jit_sceKernelVirtualQuery_addr = jit_read64(JIT_BASE + 0x1B5310)
    jit_sceKernelVirtualQueryAll_addr = jit_sceKernelVirtualQuery_addr + 0x30
    
    jit_calloc = jit_func_wrap(jit_calloc_addr)
    jit_libc_error = jit_func_wrap(jit_libc_error_addr)
    jit_sceKernelGetModuleInfoFromAddr = jit_func_wrap(jit_sceKernelGetModuleInfoFromAddr_addr)
    jit_sceKernelJitCreateSharedMemory = jit_func_wrap(jit_sceKernelJitCreateSharedMemory_addr)
    jit_sceKernelJitCreateAliasOfSharedMemory = jit_func_wrap(jit_sceKernelJitCreateAliasOfSharedMemory_addr)
    jit_sceKernelJitMapSharedMemory = jit_func_wrap(jit_sceKernelJitMapSharedMemory_addr)
    jit_memcpy = jit_func_wrap(jit_memcpy_addr)
    jit_memset = jit_func_wrap(jit_memset_addr)
    
    jit_sceKernelVirtualQuery = jit_func_wrap(jit_sceKernelVirtualQuery_addr)
    jit_sceKernelVirtualQueryAll = jit_func_wrap(jit_sceKernelVirtualQueryAll_addr)

end