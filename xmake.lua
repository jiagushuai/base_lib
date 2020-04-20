
-- add modes: debug and release 
add_rules("mode.debug", "mode.release")
add_includedirs("include")

if(is_plat("windows")) then
    add_cxflags("/EHa")
    --适配XP 设置平台集+系统最低版本//xmake f --vs_toolset=14.0
    add_defines("_USING_V110_SDK71_")
    ---添加链接选项 隐藏控制台
    add_ldflags("/SUBSYSTEM:CONSOLE,5.01")
    --管理员权限
    add_ldflags("/MANIFEST", "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\"", {force = true})
    -- 如果是release模式
    if is_mode("release") then 
        add_cxflags("/MT")--修改了模式
    else
        add_cxflags("/MDd")
    end
end

-- add target
target("base_base64")
    -- set kind
    set_kind("binary")

    add_includedirs("base_base64")
    -- add files
    add_files("base_base64/base64.cpp") 
    add_files("base_base64/test.cpp") 

-- add target
target("base_log")

    -- set kind
    set_kind("binary")

    add_includedirs("base_log")
    -- add files
    add_files("base_log/zf_file_output.cpp") 
    add_files("base_log/zf_log.cpp") 
    add_files("base_log/test.cpp") 
-- add target
target("base_transcode")

    -- set kind
    set_kind("binary")

    add_includedirs("base_transcode")
    -- add files
    add_files("base_transcode/strnormalize.cpp") 
    add_files("base_transcode/test.cpp") 
-- add target
target("base_openssl")

    -- set kind
    set_kind("shared")

    if is_plat("windows") then
        add_linkdirs("lib/windows")
        if is_arch("x64") then 
            add_cxflags("_AMD64_")
            add_linkdirs("lib/windows/lib_x64")
        else
            add_cxflags("_X86_")
            add_linkdirs("lib/windows/lib_x86")
        end
    end
    if is_plat("macosx") then
        add_linkdirs("lib/macosx")
    end
    if is_plat("mingw") then
        add_linkdirs("lib/mingw")
        add_shflags("-static",{force = true})
    end

   if is_plat("macosx","mingw","linux") then
        add_links("ssl")
        add_links("crypto");--openssl
    end
    if is_plat("linux") then
        add_links("dl");
        add_links("pthread");
    end
    if is_plat("windows") then
        add_links("libssl")--这个没加也ok哦...
        add_links("libcrypto");--openssl
    end

    if is_plat("windows","mingw") then
        add_links("ws2_32")
        add_links("GDI32")
        add_links("ADVAPI32")
        add_links("CRYPT32")
        add_links("USER32")
    end

    -- add files
    add_includedirs("base_base64")
    add_files("base_base64/base64.cpp") 
    add_includedirs("base_transcode")
    add_files("base_transcode/strnormalize.cpp") 
    add_includedirs("base_log")
    add_files("base_log/zf_file_output.cpp") 
    add_files("base_log/zf_log.cpp") 

    -- add files
    add_files("src/rsaLib.cpp") 
    add_files("src/interface.cpp") 

-- add target
target("base_demo")

    -- set kind
    set_kind("binary")

    -- add deps
    add_deps("base_openssl")

    -- add files
    add_files("src/test.cpp") 



--
-- FAQ
--
-- You can enter the project directory firstly before building project.
--   
--   $ cd projectdir
-- 
-- 1. How to build project?
--   
--   $ xmake
--
-- 2. How to configure project?
--
--   $ xmake f -p [macosx|linux|iphoneos ..] -a [x86_64|i386|arm64 ..] -m [debug|release]
--
-- 3. Where is the build output directory?
--
--   The default output directory is `./build` and you can configure the output directory.
--
--   $ xmake f -o outputdir
--   $ xmake
--
-- 4. How to run and debug target after building project?
--
--   $ xmake run [targetname]
--   $ xmake run -d [targetname]
--
-- 5. How to install target to the system directory or other output directory?
--
--   $ xmake install 
--   $ xmake install -o installdir
--
-- 6. Add some frequently-used compilation flags in xmake.lua
--
-- @code 
--    -- add macro defination
--    add_defines("NDEBUG", "_GNU_SOURCE=1")
--
--    -- set warning all as error
--    set_warnings("all", "error")
--
--    -- set language: c99, c++11
--    set_languages("c99", "cxx11")
--
--    -- set optimization: none, faster, fastest, smallest 
--    set_optimize("fastest")
--    
--    -- add include search directories
--    add_includedirs("/usr/include", "/usr/local/include")
--
--    -- add link libraries and search directories
--    add_links("tbox", "z", "pthread")
--    add_linkdirs("/usr/local/lib", "/usr/lib")
--
--    -- add compilation and link flags
--    add_cxflags("-stdnolib", "-fno-strict-aliasing")
--    add_ldflags("-L/usr/local/lib", "-lpthread", {force = true})
--
-- @endcode
--
-- 7. If you want to known more usage about xmake, please see http://xmake.io/#/home
--
    
