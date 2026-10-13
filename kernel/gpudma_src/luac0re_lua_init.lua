-- Make init.lua minimal
-- masticore does not like big init.lua (?)

-- Global variables from masticore
-- FAKE_STRING
-- ADDROF_TABLE
-- WRITE_TABLE
-- ARRAY_ADDR
-- STRING_BASE
-- EBOOT_BASE
-- LIBC_BASE
-- FIOS_BASE
-- LUA_STATE
-- USER_ID
-- call_rop_internal()

-- Stop GC for sanity
collectgarbage("stop")

package.path = package.path .. ";/savedata0/lua/?.lua;/savedata0/lua/jit/?.lua"

old_error = error
require_old = require

function error(message)
    old_error("\n" .. message)
end

function write_error_log(error_msg)
    local log_file = "/av_contents/content_tmp/lua_log.txt"
    local file = io.open(log_file, "a")
    if file then
        file:write(error_msg)
        file:close()
    end
end

-- Add sanity check to require
require = function(modname)
    local modpath = modname:gsub("%.", "/")
    for template in package.path:gmatch("[^;]+") do
        local filepath = template:gsub("%?", modpath)
        local f = io.open(filepath, "rb")
        if f then
            local size = f:seek("end")
            f:close()
            if size == 0 then
                error("ERROR require : Lua script is empty (0 bytes)\n" .. filepath .."\nBad save resign?\n")
            end
            break
        end
    end
    return require_old(modname)
end

local status, err = xpcall(function()
    require "main"
end, debug.traceback)

if not status then
    write_error_log(err)
    error(err) -- Throw error to masticore
end

-- DO NOT RETURN TO MASTICORE WHEN JIT EXPLOIT IS ENABLED
while true do end
