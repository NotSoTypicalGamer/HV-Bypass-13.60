function printf(fmt, ...)
    print(string.format(fmt, ...))
end

function errorf(fmt, ...)
    error(string.format(fmt, ...))
end

function to_hex(value)
    return string.format("0x%016X", value & 0xFFFFFFFFFFFFFFFF)
end

function file_exists(name)
    local f = io.open(name, "r")
    if f ~= nil then
        io.close(f)
        return true
    else
        return false
    end
 end

function file_write(filename, data, mode)
    local fd = io.open(filename, mode or "wb")
    fd:write(data)
    fd:close()
end

function file_read(filename, mode)
    return io.open(filename, mode):read("*all")
end

function send_notification(text)
    print(text)
    local notify_buffer_size = 0xc30
    local notify_buffer = malloc(notify_buffer_size)
    local icon_uri = "cxml://psnotification/tex_icon_system"
    
    write32(notify_buffer + 0x0, 0)           -- type
    write32(notify_buffer + 0x28, 0)          -- unk3
    write32(notify_buffer + 0x2C, 1)          -- use_icon_image_uri
    write32(notify_buffer + 0x10, -1)         -- target_id
    write_buffer(notify_buffer + 0x2D, text)  -- message
    write_buffer(notify_buffer + 0x42D, icon_uri) -- uri
    
    local dev_path = "/dev/notification0"
    local fd = sceKernelOpen(dev_path, O_WRONLY, 0)
    sceKernelWrite(fd, notify_buffer, notify_buffer_size)
    sceKernelClose(fd)
end

function show_dialog(message)
    sceMsgDialogTerminate()
    sceMsgDialogInitialize()
    
    local dialog_param_addr = DIALOG_SCRATCH
    local msg_param_addr = DIALOG_SCRATCH + 0x88
    
    -- Zero dialog_param buffer
    memset(dialog_param_addr, 0, 0x87)
    
    -- Zero msg_param buffer
    memset(msg_param_addr, 0, 0x1F)
    
    -- Calculate magic (32-bit address)
    local magic = (0xC0D1A109 + dialog_param_addr) & 0xFFFFFFFF
    
    -- Setup dialog_param structure
    write64(dialog_param_addr + 0x00, 0x30)           -- baseParam.size
    write32(dialog_param_addr + 0x2C, magic)          -- magic
    write64(dialog_param_addr + 0x30, 0x88)           -- size
    write32(dialog_param_addr + 0x38, 1)              -- mode
    write64(dialog_param_addr + 0x40, msg_param_addr) -- msg_param pointer
    write32(dialog_param_addr + 0x58, USER_ID)        -- userId
    
    -- Setup msg_param structure
    write32(msg_param_addr + 0x00, 0)
    write64(msg_param_addr + 0x08, message)
    
    local msg_ret = sceMsgDialogOpen(dialog_param_addr)
    
    if msg_ret ~= 0 then
        send_notification("sceMsgDialogOpen failed")
    end
end

function microsleep(val)
    sceKernelUsleep(val // 1)
end

function sleep(val)
    microsleep(val * 1000000)
end

function find_pattern(buffer, pattern)
    local pattern_bytes = {}
    local is_wildcard = {}
    
    -- Parse pattern
    for hex in pattern:gmatch("%S+") do
        if hex == "?" then
            pattern_bytes[#pattern_bytes + 1] = 0
            is_wildcard[#is_wildcard + 1] = true
        else
            pattern_bytes[#pattern_bytes + 1] = tonumber(hex, 16)
            is_wildcard[#is_wildcard + 1] = false
        end
    end
    
    local pattern_len = #pattern_bytes
    local buffer_len = #buffer
    local matches = {}
    
    -- Search byte-by-byte
    for i = 1, buffer_len - pattern_len + 1 do
        local match = true
        for j = 1, pattern_len do
            if not is_wildcard[j] then
                if string.byte(buffer, i + j - 1) ~= pattern_bytes[j] then
                    match = false
                    break
                end
            end
        end
        if match then
            matches[#matches + 1] = i
        end
    end
    
    return matches
end

function get_error_string()
    local error_addr = libc_error()
    local errno = read64(error_addr)
    local str_addr = libc_strerror(errno)
    return "errno : " .. to_hex(errno) .. "\nerror : " .. read_null_terminated_string(str_addr)
end

function sysctlbyname(name, oldp, oldp_len, newp, newp_len)
    local translate_name_mib = malloc(0x8)
    local buf_size = 0x70
    local mib = malloc(buf_size)
    local size = malloc(0x8)
    
    write32(translate_name_mib, 0)
    write32(translate_name_mib + 4, 3)
    write64(size, buf_size)
    
    local name_len = #name
    
    local ret = syscall.sysctl(translate_name_mib, 2, mib, size, name, name_len)
    if ret == -1 then
        error("failed to translate sysctl name to mib (" .. name .. ")")
    end
    
    local mib_len = read64(size) // 4
    
    ret = syscall.sysctl(mib, mib_len, oldp, oldp_len, newp, newp_len)
    if ret == -1 then
        return false
    end
    
    return true
end

function get_fwversion()
    local buf = malloc(0x8)
    local size = malloc(0x8)
    write64(size, 0x8)
    
    if sysctlbyname("kern.sdk_version", buf, size, 0, 0) then
        local byte1 = read8(buf + 2)  -- Minor version
        local byte2 = read8(buf + 3)  -- Major version
        
        local version = string.format("%x.%02x", byte2, byte1)
        return version
    end
    
    return nil
end

function get_current_ip()
    -- Get interface count
    local count = syscall.netgetiflist(0, 10)
    if count < 0 then
        return nil
    end
    
    -- Allocate buffer for interfaces
    local iface_size = 0x1e0
    local iface_buf = malloc(iface_size * count)
    
    -- Get interface list
    if syscall.netgetiflist(iface_buf, count) < 0 then
        return nil
    end
    
    -- Parse interfaces
    for i = 0, count - 1 do
        local offset = i * iface_size
        
        -- Read interface name (null-terminated string at offset 0)
        local iface_name = ""
        for j = 0, 15 do
            local c = read8(iface_buf + offset + j)
            if c == 0 then break end
            iface_name = iface_name .. string.char(c)
        end
        
        -- Read IP address (4 bytes at offset 0x28)
        local ip_offset = offset + 0x28
        local ip1 = read8(iface_buf + ip_offset)
        local ip2 = read8(iface_buf + ip_offset + 1)
        local ip3 = read8(iface_buf + ip_offset + 2)
        local ip4 = read8(iface_buf + ip_offset + 3)
        local iface_ip = ip1 .. "." .. ip2 .. "." .. ip3 .. "." .. ip4
        
        -- Check if this is eth0 or wlan0 with valid IP
        if (iface_name == "eth0" or iface_name == "wlan0") and 
           iface_ip ~= "0.0.0.0" and iface_ip ~= "127.0.0.1" then
            return iface_ip
        end
    end
    
    return nil
end

function is_jailbroken()
    local cur_uid = syscall.getuid()
    local is_in_sandbox = syscall.is_in_sandbox()
    if cur_uid == 0 and is_in_sandbox == 0 then
        return true
    else
        -- Check if elfldr is running at 9021
        local sockaddr_in = malloc(16)
        local enable = malloc(4)
        
        local sock_fd = create_socket(AF_INET, SOCK_STREAM, 0)
        if sock_fd == -1 then
            error("socket failed: " .. to_hex(sock_fd))
        end
        
        write32(enable, 1)
        syscall.setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, enable, 4)
        
        write8(sockaddr_in + 1, AF_INET)
        write16(sockaddr_in + 2, 0x3D23)      -- port 9021
        write32(sockaddr_in + 4, 0x0100007F)  -- 127.0.0.1
        
        -- Try to connect to 127.0.0.1:9021
        local ret = syscall.connect(sock_fd, sockaddr_in, 16)
        
        syscall.close(sock_fd)
        
        if ret == 0 then
            return true
        else
            return false
        end
    end
end

function get_nidpath()
    local path_buffer = malloc(0x255)
    local len_ptr = malloc(8)
    
    write64(len_ptr, 0x255)
    
    local ret = syscall.randomized_path(0, path_buffer, len_ptr)
    if ret == -1 then
        error("randomized_path failed : " .. to_hex(ret))
    end
    
    return read_null_terminated_string(path_buffer)
end

function run_lua_buffer(code)
    local func, err = load(code)
    if not func then
        send_notification("Lua load error:\n" .. err)
        return
    end
    
    local status, result = xpcall(func, debug.traceback)
    if not status then
        show_dialog("Lua exec error:\n" .. result)
    end
end

function run_lua_file(filename)
    local func, err = loadfile(filename)
    if not func then
        send_notification("Lua load error:\n" .. err)
        return
    end
    
    local status, result = xpcall(func, debug.traceback)
    if not status then
        show_dialog("Lua exec error:\n" .. result)
    end
end

function create_socket(domain, type, protocol)

    -- PS4 below firmware 14.00 or PS5 below firmware 8.00 or domain = 0: use syscall directly
    if (PLATFORM == "PS4" and tonumber(FW_VERSION) < 14.00) or (PLATFORM == "PS5" and tonumber(FW_VERSION) < 8.00) or domain == AF_UNIX then
        local fd = syscall.socket(domain, type, protocol)
        if fd < 0 then
            send_notification("create_socket error: " .. get_error_string())
            return -1
        end
        return fd
    end

    -- PS4 firmware 14.00+, PS5 firmware 8.00+, non-zero domain: route through JIT socket path
    local jit_fd = jit_syscall.socket(domain, type, protocol)
    if jit_fd < 0 then
        send_notification("create_socket error: " .. jit_get_error_string())
        return -1
    end

    local fd = jit_send_recv_fd(jit_fd, NEW_JIT_SOCK, NEW_MAIN_SOCK)
    if fd < 0 then
        send_notification("create_socket error")
        return -1
    end

    return fd
    
end

function write_string(dest, str)
    write_buffer(dest, str)
    write8(dest + #str, 0)
end

function hex_to_binary(hex)
    return (hex:gsub('..', function(cc)
        return string.char(tonumber(cc, 16))
    end))
end

function bin_to_hex(str)
    return (str:gsub('.', function(c)
        return string.format('%02x', string.byte(c))
    end))
end

function write_shellcode(dest, str)
    local shellcode = hex_to_binary(str)
    if #shellcode < 0x400000 then
        write_buffer(SHELLCODE_SCRATCH, shellcode)
        jit_memcpy(dest, SHELLCODE_SCRATCH, #shellcode)
    else
        error("shellcode is larger than 0x400000 bytes")
    end
end

function write_shellcode_network(dest)
    local maxsize = 0x400000
    local sockaddr_in = malloc(16)
    local enable = malloc(4)

    local function htons(port)
        return ((port << 8) | (port >> 8)) & 0xFFFF
    end

    local sock_fd = create_socket(AF_INET, SOCK_STREAM, 0)
    if sock_fd < 0 then error("create_socket error") end

    write32(enable, 1)
    syscall.setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, enable, 4)

    write8(sockaddr_in + 1, AF_INET)
    write16(sockaddr_in + 2, htons(9027))
    write32(sockaddr_in + 4, INADDR_ANY)

    syscall.bind(sock_fd, sockaddr_in, 16)
    syscall.listen(sock_fd, 1)

    local client_fd = syscall.accept(sock_fd, sockaddr_in, enable)
    if client_fd < 0 then
        syscall.close(sock_fd)
        error("accept() error")
    end

    local total_read = 0
    while total_read < maxsize do
        local n = syscall.read(client_fd, SHELLCODE_SCRATCH + total_read, maxsize - total_read)
        if n == 0 then break end
        if n < 0 then
            syscall.close(client_fd)
            syscall.close(sock_fd)
            error("read() error")
        end
        total_read = total_read + n
    end

    syscall.close(client_fd)
    syscall.close(sock_fd)

    if total_read == 0 then error("no data received") end

    jit_memcpy(dest, SHELLCODE_SCRATCH, total_read)
end


function get_title_id()
    local pid = syscall.getpid()
    
    if PLATFORM ~= "PS4" and PLATFORM ~= "PS5" then
        error("Unknown PLATFORM: " .. tostring(PLATFORM))
    end

    local app_info_size
    if PLATFORM == "PS4" then
        app_info_size = 0x48
    elseif PLATFORM == "PS5" then
        app_info_size = 0x58
    end

    local mib = malloc(0x10)
    write32(mib + 0x0, 1)
    write32(mib + 0x4, 14)
    write32(mib + 0x8, 35)
    write32(mib + 0xC, pid)
    local app_info = malloc(0x100)
    local oldlen = malloc(0x8)
    write64(oldlen, app_info_size)
    local result = syscall.sysctl(mib, 4, app_info, oldlen, 0, 0)
    if result ~= 0 then
        error("sysctl error: " .. get_error_string())
    end
    return read_null_terminated_string(app_info + 0x10)
end