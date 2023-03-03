/*
 * RISCV machine
 *
 * Copyright (c) 2016 Fabrice Bellard
 * Copyright (C) 2018,2019, Esperanto Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * THIS FILE IS BASED ON THE RISCVEMU SOURCE CODE WHICH IS DISTRIBUTED
 * UNDER THE FOLLOWING LICENSE:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#ifndef RISCV_MACHINE_H
#define RISCV_MACHINE_H

#include "machine.h"
#include "riscv_cpu.h"
#include "virtio.h"

#ifdef LIVECACHE
#include "LiveCacheCore.h"
#endif

#define MAX_CPUS 8

/* Hooks */
typedef struct RISCVMachineHooks {
    /* Returns -1 if invalid CSR, 0 if OK. */
    int (*csr_read)(RISCVCPUState *s, uint32_t funct3, uint32_t csr, uint64_t *pval);
    int (*csr_write)(RISCVCPUState *s, uint32_t funct3, uint32_t csr, uint64_t val);
} RISCVMachineHooks;

struct RISCVMachine {
    VirtMachine       common;
    RISCVMachineHooks hooks;
    PhysMemoryMap *   mem_map;
#ifdef LIVECACHE
    LiveCache *llc;
#endif
    RISCVCPUState *cpu_state[MAX_CPUS];

    /*
     * Each write to memory increases the memseqno.  We use this to
     * enable SC to invalidate a load reservation if memory has been
     * written by an external agent (including another hart).
     */
    uint64_t memseqno;

    int            ncpus;
    uint64_t       ram_size;
    uint64_t       ram_base_addr;
    /* PLIC */
    uint32_t  plic_pending_irq;
    uint32_t  plic_served_irq;
    IRQSignal plic_irq[32]; /* IRQ 0 is not used */

    /* HTIF */
    uint64_t htif_tohost_addr;

    VIRTIODevice *keyboard_dev;
    VIRTIODevice *mouse_dev;

    int virtio_count;

    /* Reset vector */
    uint64_t reset_vector;

    /* Bootrom Params */
    bool compact_bootrom;
    bool bootrom_loaded;

    /* PLIC/CLINT Params */
    uint64_t plic_base_addr;
    uint64_t plic_size;
    uint64_t clint_base_addr;
    uint64_t clint_size;

    uint64_t initrd_start;

    /* Append to misa custom extensions */
    bool custom_extension;

    /* Clear mimpid, marchid, mvendorid */
    bool clear_ids;

    /* Extension state, not used by Dromajo itself */
    void *ext_state;
};

#define PLIC_BASE_ADDR 0x10000000
#define PLIC_SIZE      0x2000000

#define CLINT_BASE_ADDR 0x02000000
#define CLINT_SIZE      0x000c0000

// CPU_FREQUENCY is a u32, so less than 4GHz
#define CPU_FREQUENCY 2000000000
#define RTC_FREQ      1000000

#define RTC_FREQ_DIV (CPU_FREQUENCY / RTC_FREQ)

#define HTIF_BASE_ADDR        0x40008000
#define IDE_BASE_ADDR         0x40009000
#define VIRTIO_BASE_ADDR      0x40010000
#define VIRTIO_SIZE           0x1000
#define VIRTIO_IRQ            4
#define FRAMEBUFFER_BASE_ADDR 0x41000000

// sifive,uart, same as qemu UART0 (qemu has 2 sifive uarts)
#ifdef ARIANE_UART
#define UART0_BASE_ADDR 0x10000000
#define UART0_SIZE      0x1000
#else
#define UART0_BASE_ADDR 0x54000000
#define UART0_SIZE      32
#endif
#define UART0_IRQ       3

#endif
