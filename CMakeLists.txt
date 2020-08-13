#
# Dromajo, a RISC-V Emulator (based on Fabrice Bellard's RISCVEMU/TinyEMU)
#
# Copyright (c) 2016-2017 Fabrice Bellard
# Copyright (c) 2018,2019,2020 Esperanto Technology
#
# Licensed under the Apache License, Version 2.0 (the "License")
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# THIS FILE IS BASED ON RISCVEMU SOURCE CODE WHICH IS DISTRIBUTED UNDER
# THE FOLLOWING LICENSE:
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

cmake_minimum_required(VERSION 2.8)
set(CMAKE_CXX_STANDARD 11)
project(dromajo)
option(TRACEOS "TRACEOS" OFF)
option(SIMPOINT "SIMPOINT" OFF)

add_compile_options(
        -Ofast
        -std=c++11
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
