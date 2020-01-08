# Mandatory to supress the huge warning
cmake_minimum_required(VERSION 2.6)

# Location of the lwip source checkout
set(lwip_root ../lwip)

# Name of the project
project(lwip_test)

file(GLOB_RECURSE
    core_files
    ${lwip_root}/src/core/*
    ${lwip_root}/src/api/*
    ${lwip_root}/src/netif/*
)

file(GLOB_RECURSE
    port_files
    ${lwip_root}/contrib/ports/unix/perf.c
    ${lwip_root}/contrib/ports/unix/lwip_chksum.c
    ${lwip_root}/contrib/ports/unix/sys_arch.c
    ${lwip_root}/contrib/ports/unix/netif/*
)

file(GLOB
    project_files
    serial_io.c
    sntp.c
    unittest.c
    timestamp.c
    tcpecho.c)

file(GLOB
     vpn_files
     vpnhook.c
     udp_backbone.c
     )

file(GLOB
     srv_files
     main.c
     )

file(GLOB
     mgr_files
     vpnmgr.c
     )

include_directories(./)
include_directories(${lwip_root}/src/include)
include_directories(${lwip_root}/src/include/ipv4)
include_directories(${lwip_root}/src/include/ipv6)
include_directories(${lwip_root}/src/contrib/ports/unix/include)
include_directories(${lwip_root}/contrib/ports/unix/port/include)

find_package (Threads)
add_library(
    vpnsock SHARED
    ${vpn_files}
    ${core_files}
    ${port_files}
)

set_target_properties(vpnsock PROPERTIES VERSION 1.0)
set_target_properties(vpnsock PROPERTIES SOVERSION 1)

# Executable source file definitions
add_executable(
    server
    ${srv_files}
)
add_executable(
    vpnmgr
    ${project_files}
    ${mgr_files}
)

target_link_libraries(vpnmgr PUBLIC vpnsock)
target_link_libraries(vpnmgr vpnsock ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(vpnmgr ${CMAKE_DL_LIBS})

target_link_libraries(server PUBLIC vpnsock)
target_link_libraries(server vpnsock ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(server ${CMAKE_DL_LIBS})
