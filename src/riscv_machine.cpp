/*
 * RISCV machine
 *
 * Copyright (c) 2016-2017 Fabrice Bellard
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

#include "riscv_machine.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <err.h>

#include "cutils.h"
#include "dromajo.h"
#include "dw_apb_uart.h"
#include "elf64.h"
#include "iomem.h"

/* RISCV machine */

//#define DUMP_UART
//#define DUMP_CLINT
//#define DUMP_HTIF
//#define DUMP_PLIC
//#define DUMP_DTB

//#define USE_SIFIVE_UART

enum {
    SIFIVE_UART_TXFIFO = 0,
    SIFIVE_UART_RXFIFO = 4,
    SIFIVE_UART_TXCTRL = 8,
    SIFIVE_UART_TXMARK = 10,
    SIFIVE_UART_RXCTRL = 12,
    SIFIVE_UART_RXMARK = 14,
    SIFIVE_UART_IE     = 16,
    SIFIVE_UART_IP     = 20,
    SIFIVE_UART_DIV    = 24,
    SIFIVE_UART_MAX    = 32
};

enum {
    SIFIVE_UART_IE_TXWM = 1, /* Transmit watermark interrupt enable */
    SIFIVE_UART_IE_RXWM = 2  /* Receive watermark interrupt enable */
};

enum {
    SIFIVE_UART_IP_TXWM = 1, /* Transmit watermark interrupt pending */
    SIFIVE_UART_IP_RXWM = 2  /* Receive watermark interrupt pending */
};

static uint64_t rtc_get_time(RISCVMachine *m) { return m->cpu_state[0]->mcycle / RTC_FREQ_DIV; }

void dromajo_default_error_log(int hartid, const char *fmt, ...) {
    va_list args;

    va_start(args, fmt);
    vfprintf(dromajo_stderr, fmt, args);
    va_end(args);
}

void dromajo_default_debug_log(int hartid, const char *fmt, ...) {
    va_list args;

    va_start(args, fmt);
    vfprintf(dromajo_stderr, fmt, args);
    va_end(args);
}

typedef struct SiFiveUARTState {
    CharacterDevice *cs;  // Console
    uint32_t         irq;
    uint8_t          rx_fifo[8];
    unsigned int     rx_fifo_len;
    uint32_t         ie;
    uint32_t         ip;
    uint32_t         txctrl;
    uint32_t         rxctrl;
    uint32_t         div;
} SiFiveUARTState;

static void uart_update_irq(SiFiveUARTState *s) {
    int cond = 0;
    if ((s->ie & SIFIVE_UART_IE_RXWM) && s->rx_fifo_len) {
        cond = 1;
    }
    if (cond) {
        vm_error("uart_update_irq: FIXME we should raise IRQ saying that there is new data\n");
    }
}

static uint32_t uart_read(void *opaque, uint32_t offset, int size_log2) {
    SiFiveUARTState *s = (SiFiveUARTState *)opaque;

#ifdef DUMP_UART
    vm_error("uart_read: offset=%x size_log2=%d\n", offset, size_log2);
#endif
    switch (offset) {
        case SIFIVE_UART_RXFIFO: {
            CharacterDevice *cs = s->cs;
            unsigned char    r;
            int              ret = cs->read_data(cs->opaque, &r, 1);
            if (ret) {
#ifdef DUMP_UART
                vm_error("uart_read: val=%x\n", r);
#endif
                return r;
            }
            return 0x80000000;
        }
        case SIFIVE_UART_TXFIFO: return 0; /* Should check tx fifo */
        case SIFIVE_UART_IE: return s->ie;
        case SIFIVE_UART_IP: return s->rx_fifo_len ? SIFIVE_UART_IP_RXWM : 0;
        case SIFIVE_UART_TXCTRL: return s->txctrl;
        case SIFIVE_UART_RXCTRL: return s->rxctrl;
        case SIFIVE_UART_DIV: return s->div;
    }

    vm_error("%s: bad read: offset=0x%x\n", __func__, (int)offset);
    return 0;
}

static void uart_write(void *opaque, uint32_t offset, uint32_t val, int size_log2) {
    SiFiveUARTState *s  = (SiFiveUARTState *)opaque;
    CharacterDevice *cs = s->cs;
    unsigned char    ch = val;

#ifdef DUMP_UART
    vm_error("uart_write: offset=%x val=%x size_log2=%d\n", offset, val, size_log2);
#endif

    switch (offset) {
        case SIFIVE_UART_TXFIFO: cs->write_data(cs->opaque, &ch, 1); return;
        case SIFIVE_UART_IE:
            s->ie = val;
            uart_update_irq(s);
            return;
        case SIFIVE_UART_TXCTRL: s->txctrl = val; return;
        case SIFIVE_UART_RXCTRL: s->rxctrl = val; return;
        case SIFIVE_UART_DIV: s->div = val; return;
    }

    vm_error("%s: bad write: addr=0x%x v=0x%x\n", __func__, (int)offset, (int)val);
}

/* CLINT registers
 * 0000 msip hart 0
 * 0004 msip hart 1
 * 4000 mtimecmp hart 0 lo
 * 4004 mtimecmp hart 0 hi
 * 4008 mtimecmp hart 1 lo
 * 400c mtimecmp hart 1 hi
 * bff8 mtime lo
 * bffc mtime hi
 */

static uint32_t clint_read(void *opaque, uint32_t offset, int size_log2) {
    RISCVMachine *m = (RISCVMachine *)opaque;
    uint32_t      val;

    if (0 <= offset && offset < 0x4000) {
        int hartid = offset >> 2;
        if (m->ncpus <= hartid) {
            vm_error("%s: MSIP access for hartid:%d which is beyond ncpus\n", __func__, hartid);
            val = 0;
        } else {
            val = (riscv_cpu_get_mip(m->cpu_state[hartid]) & MIP_MSIP) != 0;
        }
    } else if (offset == 0xbff8) {
        uint64_t mtime = m->cpu_state[0]->mcycle / RTC_FREQ_DIV;  // WARNING: mcycle may need to move to RISCVMachine
        val            = mtime;
    } else if (offset == 0xbffc) {
        uint64_t mtime = m->cpu_state[0]->mcycle / RTC_FREQ_DIV;
        val            = mtime >> 32;
    } else if (0x4000 <= offset && offset < 0xbff8) {
        int hartid = (offset - 0x4000) >> 3;
        if (m->ncpus <= hartid) {
            vm_error("%s: MSIP access for hartid:%d which is beyond ncpus\n", __func__, hartid);
            val = 0;
        } else if ((offset >> 2) & 1) {
            val = m->cpu_state[hartid]->timecmp >> 32;
        } else {
            val = m->cpu_state[hartid]->timecmp;
        }
    } else {
        vm_error("clint_read to unmanaged address CLINT_BASE+0x%x\n", offset);
        val = 0;
    }

#ifdef DUMP_CLINT
    vm_error("clint_read: offset=%x val=%x\n", offset, val);
#endif

    switch (size_log2) {
        case 1: val = val & 0xffff; break;
        case 2: val = val & 0xffffffff; break;
        case 3:
        default: break;
    }

    return val;
}

static void clint_write(void *opaque, uint32_t offset, uint32_t val, int size_log2) {
    RISCVMachine *m = (RISCVMachine *)opaque;

    switch (size_log2) {
        case 1: val = val & 0xffff; break;
        case 2: val = val & 0xffffffff; break;
        case 3:
        default: break;
    }

    if (0 <= offset && offset < 0x4000) {
        int hartid = offset >> 2;
        if (m->ncpus <= hartid) {
            vm_error("%s: MSIP access for hartid:%d which is beyond ncpus\n", __func__, hartid);
        } else if (val & 1)
            riscv_cpu_set_mip(m->cpu_state[hartid], MIP_MSIP);
        else
            riscv_cpu_reset_mip(m->cpu_state[hartid], MIP_MSIP);
    } else if (offset == 0xbff8) {
        uint64_t mtime          = m->cpu_state[0]->mcycle / RTC_FREQ_DIV;  // WARNING: move mcycle to RISCVMachine
        mtime                   = (mtime & 0xFFFFFFFF00000000L) + val;
        m->cpu_state[0]->mcycle = mtime * RTC_FREQ_DIV;
    } else if (offset == 0xbffc) {
        uint64_t mtime          = m->cpu_state[0]->mcycle / RTC_FREQ_DIV;
        mtime                   = (mtime & 0x00000000FFFFFFFFL) + ((uint64_t)val << 32);
        m->cpu_state[0]->mcycle = mtime * RTC_FREQ_DIV;
    } else if (0x4000 <= offset && offset < 0xbff8) {
        int hartid = (offset - 0x4000) >> 3;
        if (m->ncpus <= hartid) {
            vm_error("%s: MSIP access for hartid:%d which is beyond ncpus\n", __func__, hartid);
        } else if ((offset >> 2) & 1) {
            m->cpu_state[hartid]->timecmp = (m->cpu_state[hartid]->timecmp & 0xffffffff) | ((uint64_t)val << 32);
            riscv_cpu_reset_mip(m->cpu_state[hartid], MIP_MTIP);
        } else {
            m->cpu_state[hartid]->timecmp = (m->cpu_state[hartid]->timecmp & ~0xffffffff) | val;
            riscv_cpu_reset_mip(m->cpu_state[hartid], MIP_MTIP);
        }
    } else {
        vm_error("clint_write to unmanaged address CLINT_BASE+0x%x\n", offset);
        val = 0;
    }

#ifdef DUMP_CLINT
    vm_error("clint_write: offset=%x val=%x\n", offset, val);
#endif
}

static void plic_update_mip(RISCVMachine *s, int hartid) {
    uint32_t       mask = s->plic_pending_irq & ~s->plic_served_irq;
    RISCVCPUState *cpu  = s->cpu_state[hartid];

    for (int ctx = 0; ctx < 2; ++ctx) {
        unsigned mip_mask = ctx == 0 ? MIP_SEIP : MIP_MEIP;

        if (mask & cpu->plic_enable_irq[ctx]) {
            riscv_cpu_set_mip(cpu, mip_mask);
        } else {
            riscv_cpu_reset_mip(cpu, mip_mask);
        }
    }
}

static uint32_t plic_priority[PLIC_NUM_SOURCES + 1];  // XXX migrate to VirtMachine!

static uint32_t plic_read(void *opaque, uint32_t offset, int size_log2) {
    uint32_t      val = 0;
    RISCVMachine *s   = (RISCVMachine *)opaque;

    assert(size_log2 == 2);
    if (PLIC_PRIORITY_BASE <= offset && offset < PLIC_PRIORITY_BASE + (PLIC_NUM_SOURCES << 2)) {
        uint32_t irq = (offset - PLIC_PRIORITY_BASE) >> 2;
        assert(irq < PLIC_NUM_SOURCES);
        val = plic_priority[irq];
    } else if (PLIC_PENDING_BASE <= offset && offset < PLIC_PENDING_BASE + (PLIC_NUM_SOURCES >> 3)) {
        if (offset == PLIC_PENDING_BASE)
            val = s->plic_pending_irq;
        else
            val = 0;
    } else if (PLIC_ENABLE_BASE <= offset && offset < PLIC_ENABLE_BASE + (PLIC_ENABLE_STRIDE * MAX_CPUS)) {
        int addrid = (offset - PLIC_ENABLE_BASE) / PLIC_ENABLE_STRIDE;
        int hartid = addrid / 2;  // PLIC_HART_CONFIG is "MS"
        if (hartid < s->ncpus) {
            // uint32_t wordid = (offset & (PLIC_ENABLE_STRIDE-1)) >> 2;
            RISCVCPUState *cpu = s->cpu_state[hartid];
            val                = cpu->plic_enable_irq[addrid % 2];
        } else {
            val = 0;
        }
    } else if (PLIC_CONTEXT_BASE <= offset && offset < PLIC_CONTEXT_BASE + PLIC_CONTEXT_STRIDE * MAX_CPUS) {
        uint32_t hartid = (offset - PLIC_CONTEXT_BASE) / PLIC_CONTEXT_STRIDE;
        uint32_t wordid = (offset & (PLIC_CONTEXT_STRIDE - 1)) >> 2;
        if (wordid == 0) {
            val = 0;  // target_priority in qemu
        } else if (wordid == 1) {
            uint32_t mask = s->plic_pending_irq & ~s->plic_served_irq;
            if (mask != 0) {
                int i = ctz32(mask);
                s->plic_served_irq |= 1 << i;
                s->plic_pending_irq &= ~(1 << i);
                plic_update_mip(s, hartid);
                val = i;
            } else {
                val = 0;
            }
        }
    } else {
        vm_error("plic_read: unknown offset=%x\n", offset);
        val = 0;
    }
#ifdef DUMP_PLIC
    vm_error("plic_read: offset=%x val=%x\n", offset, val);
#endif

    return val;
}

static void plic_write(void *opaque, uint32_t offset, uint32_t val, int size_log2) {
    RISCVMachine *s = (RISCVMachine *)opaque;

    assert(size_log2 == 2);
    if (PLIC_PRIORITY_BASE <= offset && offset < PLIC_PRIORITY_BASE + (PLIC_NUM_SOURCES << 2)) {
        uint32_t irq = (offset - PLIC_PRIORITY_BASE) >> 2;
        assert(irq < PLIC_NUM_SOURCES);
        plic_priority[irq] = val & 7;

    } else if (PLIC_PENDING_BASE <= offset && offset < PLIC_PENDING_BASE + (PLIC_NUM_SOURCES >> 3)) {
        vm_error("plic_write: INVALID pending write to offset=0x%x\n", offset);
    } else if (PLIC_ENABLE_BASE <= offset && offset < PLIC_ENABLE_BASE + PLIC_ENABLE_STRIDE * MAX_CPUS) {
        int addrid = (offset - PLIC_ENABLE_BASE) / PLIC_ENABLE_STRIDE;
        int hartid = addrid / 2;  // PLIC_HART_CONFIG is "MS"
        if (hartid < s->ncpus) {
            // uint32_t wordid = (offset & (PLIC_ENABLE_STRIDE - 1)) >> 2;
            RISCVCPUState *cpu   = s->cpu_state[hartid];
            cpu->plic_enable_irq[addrid % 2] = val;
        }
    } else if (PLIC_CONTEXT_BASE <= offset && offset < PLIC_CONTEXT_BASE + PLIC_CONTEXT_STRIDE * MAX_CPUS) {
        uint32_t hartid = (offset - PLIC_CONTEXT_BASE) / PLIC_CONTEXT_STRIDE;
        uint32_t wordid = (offset & (PLIC_CONTEXT_STRIDE - 1)) >> 2;
        if (wordid == 0) {
            plic_priority[wordid] = val;
        } else if (wordid == 1) {
            int irq = val & 31;
            uint32_t mask = 1 << irq;
            s->plic_served_irq &= ~mask;
        } else {
            vm_error("plic_write: hartid=%d ERROR?? unexpected wordid=%d offset=%x val=%x\n", hartid, wordid, offset, val);
        }
    } else {
        vm_error("plic_write: ERROR: unexpected offset=%x val=%x\n", offset, val);
    }
#ifdef DUMP_PLIC
    vm_error("plic_write: offset=%x val=%x\n", offset, val);
#endif
}

static void plic_set_irq(void *opaque, int irq_num, int state) {
    RISCVMachine *m = (RISCVMachine *)opaque;

    uint32_t mask = 1 << irq_num;

    if (state)
        m->plic_pending_irq |= mask;
    else
        m->plic_pending_irq &= ~mask;

    for (int hartid = 0; hartid < m->ncpus; ++hartid) {
        plic_update_mip(m, hartid);
    }
}

static uint8_t *get_ram_ptr(RISCVMachine *s, uint64_t paddr) {
    PhysMemoryRange *pr = get_phys_mem_range(s->mem_map, paddr);
    if (!pr || !pr->is_ram)
        return NULL;
    return pr->phys_mem + (uintptr_t)(paddr - pr->addr);
}

void load_elf_image(RISCVMachine *s, const uint8_t *image, size_t image_len) {
    Elf64_Ehdr *      ehdr = (Elf64_Ehdr *)image;
    const Elf64_Phdr *ph   = (Elf64_Phdr *)(image + ehdr->e_phoff);

    for (int i = 0; i < ehdr->e_phnum; ++i, ++ph)
        if (ph->p_type == PT_LOAD) {
            size_t rounded_size = ph->p_memsz;
            rounded_size        = (rounded_size + DEVRAM_PAGE_SIZE - 1) & ~(DEVRAM_PAGE_SIZE - 1);
            if (ph->p_vaddr == BOOT_BASE_ADDR) {
                s->bootrom_loaded = true;
            } else if (ph->p_vaddr != s->ram_base_addr)
                /* XXX This is a kludge to taper over the fact that cpu_register_ram will
                   happily allocate mapping covering existing mappings.  Unfortunately we
                   can't fix this without a substantial rewrite as the handling of IO devices
                   depends on this. */
                cpu_register_ram(s->mem_map, ph->p_vaddr, rounded_size, 0);
            memcpy(get_ram_ptr(s, ph->p_vaddr), image + ph->p_offset, ph->p_filesz);
        }
}

void load_hex_image(RISCVMachine *s, uint8_t *image, size_t image_len) {
    char *p = (char *)image;

    for (;;) {
        long unsigned offset = 0;
        unsigned data = 0;
        if (p[0] == '0' && p[1] == 'x')
          p += 2;
        char *nl = strchr(p, '\n');
        if (nl)
            *nl = 0;
        int n = sscanf(p, "%lx %x", &offset, &data);
        if (n != 2)
            break;
        uint32_t *mem = (uint32_t *)get_ram_ptr(s, offset);
        if (!mem)
          errx(1, "dromajo: can't load hex file, no memory at 0x%lx", offset);

        *mem = data;

        if (offset == BOOT_BASE_ADDR) {
          s->bootrom_loaded = true;
        }

        if (!nl)
            break;
        p = nl + 1;
    }
}

/* Return non-zero on failure */
static int copy_kernel(RISCVMachine *s, uint8_t *fw_buf, size_t fw_buf_len, const uint8_t *kernel_buf, size_t kernel_buf_len,
                       const uint8_t *initrd_buf, size_t initrd_buf_len, const char *bootrom_name, const char *dtb_name,
                       const char *cmd_line) {
    uint64_t initrd_end = 0;
    s->initrd_start     = 0;

    if (fw_buf_len > s->ram_size) {
        vm_error("Firmware too big\n");
        return 1;
    }

    // load firmware into ram
    if (elf64_is_riscv64(fw_buf, fw_buf_len)) {
        // XXX if the ELF is given in the config file, then we don't get to set memory base based on that.

        load_elf_image(s, fw_buf, fw_buf_len);
        uint64_t fw_entrypoint = elf64_get_entrypoint(fw_buf);
        if (!s->bootrom_loaded && fw_entrypoint != s->ram_base_addr) {
            fprintf(dromajo_stderr,
                    "DROMAJO currently requires a 0x%" PRIx64 " starting address, image assumes 0x%0" PRIx64 "\n",
                    s->ram_base_addr,
                    fw_entrypoint);
            return 1;
        }

        load_elf_image(s, fw_buf, fw_buf_len);
    } else if (fw_buf_len > 2 && fw_buf[0] == '0' && fw_buf[0] == 'x') {
        load_hex_image(s, fw_buf, fw_buf_len);
    } else
        memcpy(get_ram_ptr(s, s->ram_base_addr), fw_buf, fw_buf_len);

    // load kernel into ram
    if (kernel_buf && kernel_buf_len) {
        if (s->ram_size <= KERNEL_OFFSET) {
            vm_error("Can't load kernel at ram offset 0x%x\n", KERNEL_OFFSET);
            return 1;
        }
        if (kernel_buf_len > (s->ram_size - KERNEL_OFFSET)) {
            vm_error("Kernel too big\n");
            return 1;
        }
        memcpy(get_ram_ptr(s, s->ram_base_addr + KERNEL_OFFSET), kernel_buf, kernel_buf_len);
    }

    // load initrd into ram
    if (initrd_buf && initrd_buf_len) {
        if (initrd_buf_len > s->ram_size) {
            vm_error("Initrd too big\n");
            return 1;
        }
        initrd_end      = s->ram_base_addr + s->ram_size;
        s->initrd_start = initrd_end - initrd_buf_len;
        s->initrd_start = (s->initrd_start >> 12) << 12;
        memcpy(get_ram_ptr(s, s->initrd_start), initrd_buf, initrd_buf_len);
    }

    for (int i = 0; i < s->ncpus; ++i) riscv_set_debug_mode(s->cpu_state[i], TRUE);

    return 0;
}

static void riscv_flush_tlb_write_range(void *opaque, uint8_t *ram_addr, size_t ram_size) {
    RISCVMachine *s = (RISCVMachine *)opaque;
    for (int i = 0; i < s->ncpus; ++i) riscv_cpu_flush_tlb_write_range_ram(s->cpu_state[i], ram_addr, ram_size);
}

void virt_machine_set_defaults(VirtMachineParams *p) {
    memset(p, 0, sizeof *p);
    p->physical_addr_len = PHYSICAL_ADDR_LEN_DEFAULT;
    p->ram_base_addr     = RAM_BASE_ADDR;
    p->reset_vector      = BOOT_BASE_ADDR;
    p->plic_base_addr    = PLIC_BASE_ADDR;
    p->plic_size         = PLIC_SIZE;
    p->clint_base_addr   = CLINT_BASE_ADDR;
    p->clint_size        = CLINT_SIZE;
}

RISCVMachine *global_virt_machine = 0;
uint8_t       dromajo_get_byte_direct(uint64_t paddr) {
    assert(global_virt_machine);  // needed to have a global map
    uint8_t *ptr = get_ram_ptr(global_virt_machine, paddr);
    if (ptr == NULL)
        return 0;

    return *ptr;
}

static void dump_dram(RISCVMachine *s, FILE *f[16], const char *region, uint64_t start, uint64_t len) {
    if (len == 0)
        return;

    assert(start % 1024 == 0);

    uint64_t end = start + len;

    fprintf(stderr, "Dumping %-10s [%016lx; %016lx) %6.2f MiB\n", region, start, end, len / (1024 * 1024.0));

    /*
      Bytes
      0 ..31   memImage_dwrow0_even.hex:0-7
      32..63   memImage_dwrow1_even.hex:0-7
               memImage_dwrow2_even.hex:0-7
               memImage_dwrow3_even.hex:0-7
               memImage_derow0_even.hex:0-7
               memImage_derow1_even.hex:0-7
               memImage_derow2_even.hex:0-7
               memImage_derow3_even.hex:0-7
               memImage_dwrow0_odd.hex:0-7

               memImage_dwrow0_even.hex:8-15? (Not verified, but that would be logical)

      IOW,  16 banks of 64-bit wide memories, striped in cache sized (64B) blocks.  16 * 64 = 1 KiB


      @00000000 0053c5634143b383
    */

    for (int line = (start - s->ram_base_addr) / 1024; start < end; ++line) {
        for (int bank = 0; bank < 16; ++bank) {
            for (int word = 0; word < 8; ++word) {
                fprintf(f[bank],
                        "@%08x %016lx\n",
                        // Yes, this is mental
                        (line % 8) * 0x01000000 + line / 8 * 8 + word,
                        *(uint64_t *)get_ram_ptr(s, start));
                start += sizeof(uint64_t);
            }
        }
    }
}

RISCVMachine *virt_machine_init(const VirtMachineParams *p) {
    VIRTIODevice *blk_dev;
    int           irq_num, i;
    VIRTIOBusDef  vbus_s, *vbus = &vbus_s;
    RISCVMachine *s = (RISCVMachine *)mallocz(sizeof *s);

    s->ram_size      = p->ram_size;
    s->ram_base_addr = p->ram_base_addr;

    s->mem_map = phys_mem_map_init();
    /* needed to handle the RAM dirty bits */
    s->mem_map->opaque                = s;
    s->mem_map->flush_tlb_write_range = riscv_flush_tlb_write_range;
    s->common.maxinsns                = p->maxinsns;
    s->common.snapshot_load_name      = p->snapshot_load_name;

    /* loggers are changed using install_new_loggers() in dromajo_cosim */
    s->common.debug_log = &dromajo_default_debug_log;
    s->common.error_log = &dromajo_default_error_log;

    s->ncpus = p->ncpus;

    /* setup reset vector for core
     * note: must be above riscv_cpu_init
     */
    s->reset_vector = p->reset_vector;

    /* have compact bootrom */
    s->compact_bootrom = p->compact_bootrom;

    /* add custom extension bit to misa */
    s->custom_extension = p->custom_extension;

    s->plic_base_addr  = p->plic_base_addr;
    s->plic_size       = p->plic_size;
    s->clint_base_addr = p->clint_base_addr;
    s->clint_size      = p->clint_size;
    /* clear mimpid, marchid, mvendorid */
    s->clear_ids = p->clear_ids;

    if (MAX_CPUS < s->ncpus) {
        vm_error("ERROR: ncpus:%d exceeds maximum MAX_CPU\n", s->ncpus);
        return NULL;
    }

    for (int i = 0; i < s->ncpus; ++i) {
        s->cpu_state[i] = riscv_cpu_init(s, i);
    }

    /* RAM */
    cpu_register_ram(s->mem_map, s->ram_base_addr, s->ram_size, 0);
    cpu_register_ram(s->mem_map, ROM_BASE_ADDR, ROM_SIZE, 0);

    for (int i = 0; i < s->ncpus; ++i) {
        s->cpu_state[i]->physical_addr_len = p->physical_addr_len;
    }

    SiFiveUARTState *uart = (SiFiveUARTState *)calloc(sizeof *uart, 1);
    uart->irq             = UART0_IRQ;
    uart->cs              = p->console;
    cpu_register_device(s->mem_map, UART0_BASE_ADDR, UART0_SIZE, uart, uart_read, uart_write, DEVIO_SIZE32);

    DW_apb_uart_state *dw_apb_uart = (DW_apb_uart_state *)calloc(sizeof *dw_apb_uart, 1);
    dw_apb_uart->irq               = &s->plic_irq[DW_APB_UART0_IRQ];
    dw_apb_uart->cs                = p->console;
    cpu_register_device(s->mem_map,
                        DW_APB_UART0_BASE_ADDR,
                        DW_APB_UART0_SIZE,
                        dw_apb_uart,
                        dw_apb_uart_read,
                        dw_apb_uart_write,
                        DEVIO_SIZE32 | DEVIO_SIZE16 | DEVIO_SIZE8);

    DW_apb_uart_state *dw_apb_uart1 = (DW_apb_uart_state *)calloc(sizeof *dw_apb_uart, 1);
    dw_apb_uart1->irq               = &s->plic_irq[DW_APB_UART1_IRQ];
    dw_apb_uart1->cs                = p->console;
    cpu_register_device(s->mem_map,
                        DW_APB_UART1_BASE_ADDR,
                        DW_APB_UART1_SIZE,
                        dw_apb_uart1,
                        dw_apb_uart_read,
                        dw_apb_uart_write,
                        DEVIO_SIZE32 | DEVIO_SIZE16 | DEVIO_SIZE8);

    cpu_register_device(s->mem_map,
                        p->clint_base_addr,
                        p->clint_size,
                        s,
                        clint_read,
                        clint_write,
                        DEVIO_SIZE32 | DEVIO_SIZE16 | DEVIO_SIZE8);
    cpu_register_device(s->mem_map, p->plic_base_addr, p->plic_size, s, plic_read, plic_write, DEVIO_SIZE32);

    for (int j = 1; j < 32; j++) {
        irq_init(&s->plic_irq[j], plic_set_irq, s, j);
    }

    s->htif_tohost_addr = p->htif_base_addr;

    s->common.console = p->console;

    memset(vbus, 0, sizeof(*vbus));
    vbus->mem_map = s->mem_map;
    vbus->addr    = VIRTIO_BASE_ADDR;
    irq_num       = VIRTIO_IRQ;

    /* virtio console */
    if (p->console && 0) {
        vbus->irq             = &s->plic_irq[irq_num];
        s->common.console_dev = virtio_console_init(vbus, p->console);
        vbus->addr += VIRTIO_SIZE;
        irq_num++;
        s->virtio_count++;
    }

    /* virtio net device */
    for (i = 0; i < p->eth_count; ++i) {
        vbus->irq = &s->plic_irq[irq_num];
        virtio_net_init(vbus, p->tab_eth[i].net);
        s->common.net = p->tab_eth[i].net;
        vbus->addr += VIRTIO_SIZE;
        irq_num++;
        s->virtio_count++;
    }

    /* virtio block device */
    for (i = 0; i < p->drive_count; ++i) {
        vbus->irq = &s->plic_irq[irq_num];
        blk_dev   = virtio_block_init(vbus, p->tab_drive[i].block_dev);
        (void)blk_dev;
        vbus->addr += VIRTIO_SIZE;
        irq_num++;
        s->virtio_count++;
        // virtio_set_debug(blk_dev, 1);
    }

    /* virtio filesystem */
    for (i = 0; i < p->fs_count; ++i) {
        VIRTIODevice *fs_dev;
        vbus->irq = &s->plic_irq[irq_num];
        fs_dev    = virtio_9p_init(vbus, p->tab_fs[i].fs_dev, p->tab_fs[i].tag);
        (void)fs_dev;
        vbus->addr += VIRTIO_SIZE;
        irq_num++;
        s->virtio_count++;
    }

    if (p->input_device) {
        if (!strcmp(p->input_device, "virtio")) {
            vbus->irq       = &s->plic_irq[irq_num];
            s->keyboard_dev = virtio_input_init(vbus, VIRTIO_INPUT_TYPE_KEYBOARD);
            vbus->addr += VIRTIO_SIZE;
            irq_num++;
            s->virtio_count++;

            vbus->irq    = &s->plic_irq[irq_num];
            s->mouse_dev = virtio_input_init(vbus, VIRTIO_INPUT_TYPE_TABLET);
            vbus->addr += VIRTIO_SIZE;
            irq_num++;
            s->virtio_count++;
        } else {
            vm_error("unsupported input device: %s\n", p->input_device);
            return NULL;
        }
    }

    if (!p->files[VM_FILE_BIOS].buf) {
        vm_error("No bios given\n");
        return NULL;
    } else if (copy_kernel(s,
                           p->files[VM_FILE_BIOS].buf,
                           p->files[VM_FILE_BIOS].len,
                           p->files[VM_FILE_KERNEL].buf,
                           p->files[VM_FILE_KERNEL].len,
                           p->files[VM_FILE_INITRD].buf,
                           p->files[VM_FILE_INITRD].len,
                           p->bootrom_name,
                           p->dtb_name,
                           p->cmdline))
        return NULL;

    /* interrupts and exception setup for cosim */
    s->common.cosim             = false;
    s->common.pending_exception = -1;
    s->common.pending_interrupt = -1;

    /* plic/clint setup */
    s->plic_base_addr  = p->plic_base_addr;
    s->plic_size       = p->plic_size;
    s->clint_base_addr = p->clint_base_addr;
    s->clint_size      = p->clint_size;

    return s;
}

RISCVMachine *virt_machine_load(const VirtMachineParams *p, RISCVMachine *s) {
    if (!p->files[VM_FILE_BIOS].buf) {
        vm_error("No bios given\n");
        return NULL;
    } else if (copy_kernel(s,
                           p->files[VM_FILE_BIOS].buf,
                           p->files[VM_FILE_BIOS].len,
                           p->files[VM_FILE_KERNEL].buf,
                           p->files[VM_FILE_KERNEL].len,
                           p->files[VM_FILE_INITRD].buf,
                           p->files[VM_FILE_INITRD].len,
                           p->bootrom_name,
                           p->dtb_name,
                           p->cmdline))
        return NULL;

    if (p->dump_memories) {
        FILE *f = fopen("BootRAM.hex", "w+");
        if (!f) {
            vm_error("dromajo: %s: %s\n", "BootRAM.hex", strerror(errno));
            return NULL;
        }

        uint8_t *ram_ptr = get_ram_ptr(s, ROM_BASE_ADDR);
        for (int i = 0; i < ROM_SIZE / 4; ++i) {
            uint32_t *q_base = (uint32_t *)(ram_ptr + (BOOT_BASE_ADDR - ROM_BASE_ADDR));
            fprintf(f, "@%06x %08x\n", i, q_base[i]);
        }

        fclose(f);

        {
            FILE *f[16] = {0};

            char hexname[60];
            for (int i = 0; i < 16; ++i) {
                snprintf(hexname, sizeof hexname, "memImage_d%crow%d_%s.hex", "we"[i / 4 % 2], i % 4, i / 8 == 0 ? "even" : "odd");
                f[i] = fopen(hexname, "w");
                if (!f[i]) {
                    vm_error("dromajo: %s: %s\n", hexname, strerror(errno));
                    return NULL;
                }
            }

            dump_dram(s, f, "firmware", s->ram_base_addr, p->files[VM_FILE_BIOS].len);
            dump_dram(s, f, "kernel", s->ram_base_addr + KERNEL_OFFSET, p->files[VM_FILE_KERNEL].len);
            dump_dram(s, f, "initrd", s->initrd_start, p->files[VM_FILE_INITRD].len);

            for (int i = 0; i < 16; ++i) {
                fclose(f[i]);
            }
        }
    }

    global_virt_machine = s;

    return s;
}

void virt_machine_end(RISCVMachine *s) {
    if (s->common.snapshot_save_name)
        virt_machine_serialize(s, s->common.snapshot_save_name);

    /* XXX: stop all */
    for (int i = 0; i < s->ncpus; ++i) {
        riscv_cpu_end(s->cpu_state[i]);
    }

    phys_mem_map_end(s->mem_map);
    free(s);
}

void virt_machine_serialize(RISCVMachine *m, const char *dump_name) {
    RISCVCPUState *s = m->cpu_state[0];  // FIXME: MULTICORE

    vm_error("plic: %x %x timecmp=%llx\n", m->plic_pending_irq, m->plic_served_irq, (unsigned long long)s->timecmp);

    assert(m->ncpus == 1);  // FIXME: riscv_cpu_serialize must be patched for multicore
    riscv_cpu_serialize(s, dump_name, m->clint_base_addr);
}

void virt_machine_deserialize(RISCVMachine *m, const char *dump_name) {
    RISCVCPUState *s = m->cpu_state[0];  // FIXME: MULTICORE

    assert(m->ncpus == 1);  // FIXME: riscv_cpu_serialize must be patched for multicore
    riscv_cpu_deserialize(s, dump_name);
}

int virt_machine_get_sleep_duration(RISCVMachine *m, int hartid, int ms_delay) {
    RISCVCPUState *s = m->cpu_state[hartid];
    int64_t        ms_delay1;

    /* wait for an event: the only asynchronous event is the RTC timer */
    if (!(riscv_cpu_get_mip(s) & MIP_MTIP) && rtc_get_time(m) > 0) {
        ms_delay1 = s->timecmp - rtc_get_time(m);
        if (ms_delay1 <= 0) {
            riscv_cpu_set_mip(s, MIP_MTIP);
            ms_delay = 0;
        } else {
            /* convert delay to ms */
            ms_delay1 = ms_delay1 / (RTC_FREQ / 1000);
            if (ms_delay1 < ms_delay)
                ms_delay = ms_delay1;
        }
    }

    if (!riscv_cpu_get_power_down(s))
        ms_delay = 0;

    return ms_delay;
}

uint64_t virt_machine_get_pc(RISCVMachine *s, int hartid) { return riscv_get_pc(s->cpu_state[hartid]); }

uint64_t virt_machine_get_reg(RISCVMachine *s, int hartid, int rn) { return riscv_get_reg(s->cpu_state[hartid], rn); }

uint64_t virt_machine_get_fpreg(RISCVMachine *s, int hartid, int rn) { return riscv_get_fpreg(s->cpu_state[hartid], rn); }

const char *virt_machine_get_name(void) { return "riscv64"; }

void vm_send_key_event(RISCVMachine *s, BOOL is_down, uint16_t key_code) {
    if (s->keyboard_dev) {
        virtio_input_send_key_event(s->keyboard_dev, is_down, key_code);
    }
}

BOOL vm_mouse_is_absolute(RISCVMachine *s) { return TRUE; }

void vm_send_mouse_event(RISCVMachine *s, int dx, int dy, int dz, unsigned buttons) {
    if (s->mouse_dev) {
        virtio_input_send_mouse_event(s->mouse_dev, dx, dy, dz, buttons);
    }
}
