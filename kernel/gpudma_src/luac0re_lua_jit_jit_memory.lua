
function jit_read64(address)
    return jit_rop(JIT_ROP.MOV_RAX_DEREF_RAX_RET, address - 0x4150)
end

function jit_read32(address)
    return jit_read64(address) & 0xFFFFFFFF
end

function jit_read16(address)
    return jit_read64(address) & 0xFFFF
end

function jit_read8(address)
    return jit_read64(address) & 0xFF
end

function jit_write64(address, value)
    jit_rop(JIT_ROP.MOV_DEREF_RAX_R8_RET, address, 0, 0, 0, 0, value)
end

function jit_write32(address, value)
    local current = jit_read64(address)
    jit_write64(address, (current & ~0xFFFFFFFF) | (value & 0xFFFFFFFF))
end

function jit_write16(address, value)
    local current = jit_read64(address)
    jit_write64(address, (current & ~0xFFFF) | (value & 0xFFFF))
end

function jit_write8(address, value)
    local current = jit_read64(address)
    jit_write64(address, (current & ~0xFF) | (value & 0xFF))
end

function jit_malloc(size)
    return jit_calloc(size, 1)
end

function jit_read_buffer(addr, size)
    local str = string.rep("\0", size)
    local str_data_addr = addrof(str) + 0x20
    
    local qwords = size // 8
    for i = 0, qwords - 1 do
        local val = jit_read64(addr + i * 8)
        write64(str_data_addr + i * 8, val)
    end
    
    local remaining = size % 8
    for i = 0, remaining - 1 do
        local byte_val = jit_read8(addr + qwords * 8 + i)
        write8(str_data_addr + qwords * 8 + i, byte_val)
    end
    
    return str
end

function jit_write_buffer(dest, buffer)
    local buffer_addr = addrof(buffer) + 0x20
    local size = #buffer
    
    local qwords = size // 8
    for i = 0, qwords - 1 do
        local val = read64(buffer_addr + i * 8)
        jit_write64(dest + i * 8, val)
    end
    
    local remaining = size % 8
    for i = 0, remaining - 1 do
        local byte_val = read8(buffer_addr + qwords * 8 + i)
        jit_write8(dest + qwords * 8 + i, byte_val)
    end
end

function jit_read_null_terminated_string(addr)
    local result = ""
    while true do
        local chunk = jit_read_buffer(addr, 0x8)
        local null_pos = chunk:find("\0")
        if null_pos then 
            return result .. chunk:sub(1, null_pos - 1)
        end
        result = result .. chunk
        addr = addr + #chunk
    end
end

