cmake_minimum_required(VERSION 3.18.1)
set(CMAKE_CXX_STANDARD 11)
project(dromajo)
option(TRACEOS "TRACEOS" OFF)
option(SIMPOINT "SIMPOINT" OFF)

add_compile_options(
        -Wall
        -Wno-parentheses
        -MMD
        -D_FILE_OFFSET_BITS=64
        -D_LARGEFILE_SOURCE
        -D_GNU_SOURCE
        -D__STDC_FORMAT_MACROS
)

if (TRACEOS)
    message(STATUS "TRACEOS is on.")
    add_compile_options(
            -DDUMP_UART
            -DDUMP_CLINT
            -DDUMP_PLIC
            -DDUMP_INTERRUPTS
            -DDUMP_ILLEGAL_INSTRUCTIONS
    )
endif ()

if (SIMPOINT)
    add_compile_options(
            -DSIMPOINT_BB
    )
endif ()

# Set Version Header
set(CONFIG_VERSION "Dromajo-0.1")
configure_file(include/config.h.in config.h @ONLY)

# libdromajo_cosim
add_library(libdromajo_cosim STATIC
        src/virtio.cpp
        src/pci.cpp
        src/fs.cpp
        src/cutils.cpp
        src/iomem.cpp
        src/dw_apb_uart.cpp
        src/json.cpp
        src/machine.cpp
        src/elf64.cpp
        src/LiveCache.cpp
        src/fs_disk.cpp
        src/softfp.cpp
        src/riscv_machine.cpp
        src/dromajo_main.cpp
        src/dromajo_cosim.cpp
        src/riscv_cpu.cpp
        )

# add librt for Linux
if (${CMAKE_HOST_SYSTEM_NAME} MATCHES "Linux")
    target_link_libraries(libdromajo_cosim rt)
endif ()

include_directories(include ${CMAKE_CURRENT_BINARY_DIR})

add_executable(dromajo src/dromajo.cpp)
target_link_libraries(dromajo libdromajo_cosim)