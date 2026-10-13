
-- Luac0re 13.60 port -- func.lua (patched init_dlsym)
-- Change: the PS5 sceKernelDlsym delta is now data-driven via DLSYM_DELTAS with an
-- explicit 13.60 entry, instead of a bare `major >= 10` branch. Functional behaviour is
-- unchanged (delta -0x450 for all PS5 >= 10.01); a self-check flags drift on boot.
-- See LUACORE_1360_PORT.md section 1.5 for the 13.60 verification procedure.

function func_wrap(function_address)
    return function(arg1, arg2, arg3, arg4, arg5, arg6)
        return call_rop(function_address, 0, arg1, arg2, arg3, arg4, arg5, arg6)
    end
end

function func_wrap_with_rax(function_address, rax)
    return function(arg1, arg2, arg3, arg4, arg5, arg6)
        return call_rop(function_address, rax, arg1, arg2, arg3, arg4, arg5, arg6)
    end
end

-- Distance from sceKernelGetModuleInfoFromAddr to sceKernelDlsym (both libkernel exports).
-- SCE_KERNEL_DLSYM = read64(sceKernelGetModuleInfoFromAddr) - delta
-- PS5 < 10.01 used -0x480; PS5 >= 10.01 uses -0x450, stable through 13.20.
-- 13.60: expected unchanged -0x450 (libkernel userland layout stable 13.00->13.60);
--        TODO verify against a 13.60 libkernel export list, update if different.
DLSYM_DELTAS = {
    ["09.xx"] = 0x480,
    ["10.xx"] = 0x450,
    ["11.xx"] = 0x450,
    ["12.xx"] = 0x450,
    ["13.00"] = 0x450,
    ["13.20"] = 0x450,
    ["13.40"] = 0x450,
    ["13.60"] = 0x450, -- TODO verify on console / 13.60 libkernel dump
}

function get_dlsym_delta(fw_version)
    local major, minor = fw_version:match("(%d+)%.(%d+)")
    major, minor = tonumber(major), tonumber(minor)
    if not major then return nil end

    local function resolve(key)
        local v = DLSYM_DELTAS[key]
        for _ = 1, 4 do
            if type(v) ~= "string" then break end
            v = DLSYM_DELTAS[v]
        end
        return type(v) == "number" and v or nil
    end

    local d = resolve(string.format("%d.%02d", major, minor))
    if not d then d = resolve(string.format("%02d.xx", major)) end
    return d
end

function get_dlsym_offset()
    local major, minor = FW_VERSION:match("(%d+)%.(%d+)")
    major = tonumber(major)
    minor = tonumber(minor)

    if not major or not minor then
        error("Invalid firmware version format: " .. FW_VERSION)
    end

    -- Try exact match first
    local version_key = string.format("%d.%02d", major, minor)
    if DLSYM_OFFSETS[version_key] then
        return DLSYM_OFFSETS[version_key]
    end

    -- Find closest version within same major
    local available_versions = {}
    for key, offset in pairs(DLSYM_OFFSETS) do
        local v_major, v_minor = key:match("(%d+)%.(%d+)")
        v_major = tonumber(v_major)
        v_minor = tonumber(v_minor)

        if v_major == major then
            table.insert(available_versions, {
                key = key,
                minor = v_minor,
                offset = offset
            })
        end
    end

    if #available_versions == 0 then
        error("No dlsym offset found for firmware version " .. fw_version)
    end

    -- Find version with minimum distance to current minor
    local closest = available_versions[1]
    local min_distance = math.abs(closest.minor - minor)

    for _, version in ipairs(available_versions) do
        local distance = math.abs(version.minor - minor)
        if distance < min_distance then
            min_distance = distance
            closest = version
        end
    end

    return closest.offset
end

function dlsym(handle, sym)
    if not sceKernelDlsym then
        error("dlsym not inited")
    end

    if type(sym) ~= "string" then
        error("dlsym expects string symbol name")
    end

    local addr_out = malloc(0x8)

    local result = sceKernelDlsym(handle, sym, addr_out)
    if result == -1 then
        error("dlsym error for symbol: " .. sym)
    end

    return read64(addr_out)
end

function init_dlsym()
    assert(FW_VERSION)
    if type(sceKernelDlsym) == "function" then
        return
    end

    local major, minor = FW_VERSION:match("(%d+)%.(%d+)")
    major = tonumber(major)
    minor = tonumber(minor)

    if not major or not minor then
        error("Invalid firmware version: " .. FW_VERSION)
    end

    if PLATFORM == "PS4" then
        -- PS4: Verify dlsym signature at expected offset
        local base_addr = read64(LIBC_OFFSETS.sceKernelGetModuleInfoFromAddr)
        local expected_addr = base_addr - 0x3A0

        -- Expected dlsym function signature bytes
        local expected_pattern = "55 48 89 E5 41 57 41 56 41 55 41 54 53 48 83 EC 68 48"

        -- Read bytes at expected address
        local signature_bytes = read_buffer(expected_addr, 18)

        -- Convert to hex string for comparison
        local hex_string = ""
        for i = 1, #signature_bytes do
            hex_string = hex_string .. string.format("%02X", string.byte(signature_bytes, i))
            if i < #signature_bytes then
                hex_string = hex_string .. " "
            end
        end

        -- Verify signature
        if hex_string == expected_pattern then
            SCE_KERNEL_DLSYM = expected_addr
        else
            -- Signature doesn't match, search for it
            local search_start = base_addr - 0x600
            local search_buffer = read_buffer(search_start, 0x1000)

            local matches = find_pattern(search_buffer, expected_pattern)

            if #matches == 0 then
                send_notification("Warning : PS4 sceKernelDlsym offset not found")
                SCE_KERNEL_DLSYM = 0;
            else
                -- Use first match (offset is 1-based in Lua)
                SCE_KERNEL_DLSYM = search_start + matches[1] - 1
            end
        end
    elseif PLATFORM == "PS5" then
        -- PS5: sceKernelDlsym is at a fixed negative offset from
        -- sceKernelGetModuleInfoFromAddr in libkernel.sprx (data-driven, see DLSYM_DELTAS).
        local delta = get_dlsym_delta(FW_VERSION)
        if not delta then
            -- Fallback to the pre-13.60 heuristic for unknown firmwares.
            if major > 10 or major == 10 then
                delta = 0x450
            else
                delta = 0x480
            end
            send_notification(string.format(
                "Warning: no dlsym delta for FW %s, using fallback 0x%03X", FW_VERSION, delta))
        end

        SCE_KERNEL_DLSYM = read64(LIBC_OFFSETS.sceKernelGetModuleInfoFromAddr) - delta

        -- Cheap on-console sanity check: sceKernelDlsym must sit inside a mapped, code-ish
        -- region whose first bytes look like a function prologue. Log-only, never fatal.
        local head = read64(SCE_KERNEL_DLSYM)
        if (head & 0xFFFF) ~= 0x55 then
            send_notification(string.format(
                "WARN: sceKernelDlsym@%s head=%s looks wrong (delta 0x%03X?)",
                to_hex(SCE_KERNEL_DLSYM), to_hex(head), delta))
        end
    else
        error("Unknown platform: " .. tostring(PLATFORM))
    end

    -- Wrap the function for easier calling
    sceKernelDlsym = func_wrap(SCE_KERNEL_DLSYM)
end

function dlsym_test()

    sceKernelLoadStartModule = func_wrap(dlsym(LIBKERNEL_HANDLE, "sceKernelLoadStartModule"))

    local libSceNetCtl_HANDLE = sceKernelLoadStartModule("libSceNetCtl.sprx", 0, 0, 0, 0, 0)
    if libSceNetCtl_HANDLE <= 0 or libSceNetCtl_HANDLE >= 0x80000000 then
        error("Failed to load libSceNetCtl.sprx: " .. string.format("0x%08X", libSceNetCtl_HANDLE))
    end

    local libSceNet_HANDLE = sceKernelLoadStartModule("libSceNet.sprx", 0, 0, 0, 0, 0)
    if libSceNet_HANDLE <= 0 or libSceNet_HANDLE >= 0x80000000 then
        error("Failed to load libSceNet.sprx: " .. string.format("0x%08X", libSceNet_HANDLE))
    end

    sceNetCtlInit = func_wrap(dlsym(libSceNetCtl_HANDLE, "sceNetCtlInit"))
    sceNetInit = func_wrap(dlsym(libSceNet_HANDLE, "sceNetInit"))
    sceNetSocket = func_wrap(dlsym(libSceNet_HANDLE, "sceNetSocket"))

end

function init_native_functions()
    calloc                                = func_wrap(read64(EBOOT_OFFSETS.calloc))
    free                                  = func_wrap(read64(EBOOT_OFFSETS.free))
    sceKernelOpen                         = func_wrap(read64(EBOOT_OFFSETS.sceKernelOpen))
    sceKernelWrite                        = func_wrap(read64(EBOOT_OFFSETS.sceKernelWrite))
    sceKernelClose                        = func_wrap(read64(EBOOT_OFFSETS.sceKernelClose))
    sceKernelStat                         = func_wrap(read64(EBOOT_OFFSETS.sceKernelStat))
    sceKernelUsleep                       = func_wrap(read64(EBOOT_OFFSETS.sceKernelUsleep))
    sceMsgDialogInitialize                = func_wrap(read64(EBOOT_OFFSETS.sceMsgDialogInitialize))
    sceMsgDialogOpen                      = func_wrap(read64(EBOOT_OFFSETS.sceMsgDialogOpen))
    sceMsgDialogTerminate                 = func_wrap(read64(EBOOT_OFFSETS.sceMsgDialogTerminate))
    sceKernelGetModuleInfoFromAddr        = func_wrap(read64(LIBC_OFFSETS.sceKernelGetModuleInfoFromAddr))
    sceKernelRemoveExceptionHandler       = func_wrap(read64(EBOOT_OFFSETS.sceKernelRemoveExceptionHandler))
    scePthreadCreate                      = func_wrap(read64(EBOOT_OFFSETS.scePthreadCreate))
    scePthreadJoin                        = func_wrap(read64(EBOOT_OFFSETS.scePthreadJoin))
    scePthreadSelf                        = func_wrap(read64(EBOOT_OFFSETS.scePthreadSelf))
    scePthreadCancel                      = func_wrap(read64(EBOOT_OFFSETS.scePthreadSelf) + 0x10)
    sceKernelJitCreateSharedMemory        = func_wrap(read64(EBOOT_OFFSETS.sceKernelJitCreateSharedMemory))
    sceKernelJitCreateAliasOfSharedMemory = func_wrap(read64(EBOOT_OFFSETS.sceKernelJitCreateAliasOfSharedMemory))
    sceKernelJitMapSharedMemory           = func_wrap(read64(EBOOT_OFFSETS.sceKernelJitMapSharedMemory))
    recv_fd                               = func_wrap(EBOOT_OFFSETS.recv_fd)
    libc_strerror                         = func_wrap(LIBC_OFFSETS.libc_strerror)
    libc_error                            = func_wrap(read64(LIBC_OFFSETS.libc_error))

    memcpy                                = func_wrap(read64(EBOOT_OFFSETS.memcpy))
    memset                                = func_wrap(read64(EBOOT_OFFSETS.memset))

end
