-- Many codes reference from
-- https://github.com/shahrilnet/remote_lua_loader

require "global"
require "rop"
require "memory"
require "func"
require "misc"
require "syscall"
require "remotelualoader"
require "jit"

version_string = "Luac0re 2.4b by Gezine"

init_native_functions()
patch_malloc()
syscall.init()

-- Kill all other threads
scePthreadCancel(read64(THREAD_HANDLE_IOP_SPU2))
scePthreadCancel(read64(THREAD_HANDLE_GS))

sceKernelRemoveExceptionHandler(11)
FW_VERSION = get_fwversion()
TITLE_ID = get_title_id()
send_notification(string.format("%s\nPlatform: %s\nFW: %s\nTitle ID: %s",
                version_string, PLATFORM, FW_VERSION, TITLE_ID))

local status, errmsg = jit_init()
if not status then
    show_dialog("JIT exploit failed\n" .. errmsg)
    return
end

nid_luafile = "/" .. get_nidpath() .. "/common_temp/nid.lua"
auto_luafile = "/savedata0/lua/auto.lua"
if file_exists(nid_luafile) then
    run_lua_file(nid_luafile)
elseif file_exists(auto_luafile) then
    run_lua_file(auto_luafile)
else
    remote_lua_loader(9026)
end

