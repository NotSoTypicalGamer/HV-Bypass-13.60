
function remote_lua_loader(port)
    assert(port)

    local enable = malloc(4)
    local sockaddr_in = malloc(16)
    local addrlen = malloc(8)

    local maxsize = 500 * 1024  -- 500kb
    local payload_buf = malloc(maxsize)

    local sock_fd = create_socket(AF_INET, SOCK_STREAM, 0)
    if sock_fd < 0 then
        error("create_socket error")
    end

    write32(enable, 1)
    if syscall.setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, enable, 4) < 0 then
        error("setsockopt() error: " .. get_error_string())
    end

    local function htons(port)
        return ((port << 8) | (port >> 8)) & 0xFFFF
    end

    write8(sockaddr_in + 1, AF_INET)
    write16(sockaddr_in + 2, htons(port))
    write32(sockaddr_in + 4, INADDR_ANY)

    if syscall.bind(sock_fd, sockaddr_in, 16) < 0 then
        error("bind() error: " .. get_error_string())
    end
 
    if syscall.listen(sock_fd, 3) < 0 then
        error("listen() error: " .. get_error_string())
    end

    local current_ip = get_current_ip()
    local network_str
    
    if current_ip then
        network_str = string.format("%s:%d", current_ip, port)
    else
        show_dialog("Network not found")
        return
    end

    show_dialog(string.format("%s\nRemote Lua Loader\nPlatform: %s\nFW: %s\nTitle ID: %s\nListening: %s",
            version_string, PLATFORM, FW_VERSION, TITLE_ID, network_str))

    while true do
        write32(addrlen, 16)
        local client_fd = syscall.accept(sock_fd, sockaddr_in, addrlen)
        
        -- If accept failed, recreate socket
        if client_fd < 0 then
            syscall.close(sock_fd)
            
            sock_fd = create_socket(AF_INET, SOCK_STREAM, 0)
            if sock_fd < 0 then
                error("create_socket error")
            end

            write32(enable, 1)
            syscall.setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, enable, 4)

            write8(sockaddr_in + 1, AF_INET)
            write16(sockaddr_in + 2, htons(port))
            write32(sockaddr_in + 4, INADDR_ANY)

            syscall.bind(sock_fd, sockaddr_in, 16)
            syscall.listen(sock_fd, 3)
        else
            -- Connection accepted, read data
            local total_read = 0
            local read_error = false
            
            while total_read < maxsize do
                local bytes_read = syscall.read(
                    client_fd,
                    payload_buf + total_read,
                    maxsize - total_read
                )
                
                if bytes_read == 0 then
                    break
                end
                
                if bytes_read < 0 then
                    read_error = true
                    break
                end
                
                total_read = total_read + bytes_read
            end
            
            syscall.close(client_fd)
            
            if not read_error and total_read > 0 then
                local lua_code = read_buffer(payload_buf, total_read)
                send_notification("Executing payload...")
                run_lua_buffer(lua_code)
                send_notification("Executed successfully")
            end
        end
    end

    syscall.close(sock_fd)
end
