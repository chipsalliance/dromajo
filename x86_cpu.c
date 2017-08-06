/*
 * x86 CPU emulator stub
 * 
 * Copyright (c) 2011-2017 Fabrice Bellard
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
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>

#include "cutils.h"
#include "x86_cpu.h"

X86CPUState *x86_cpu_init(PhysMemoryMap *mem_map)
{
    fprintf(stderr, "x86 emulator is not supported\n");
    exit(1);
}

void x86_cpu_end(X86CPUState *s)
{
}

void x86_cpu_interp(X86CPUState *s, int max_cycles1)
{
}

void x86_cpu_set_irq(X86CPUState *s, BOOL set)
{
}

void x86_cpu_set_reg(X86CPUState *s, int reg, uint32_t val)
{
}

uint32_t x86_cpu_get_reg(X86CPUState *s, int reg)
{
    return 0;
}

void x86_cpu_set_seg(X86CPUState *s, int seg, const X86CPUSeg *sd)
{
}

void x86_cpu_set_get_hard_intno(X86CPUState *s,
                                int (*get_hard_intno)(void *opaque),
                                void *opaque)
{
}

void x86_cpu_set_get_tsc(X86CPUState *s,
                         uint64_t (*get_tsc)(void *opaque),
                         void *opaque)
{
}

void x86_cpu_set_port_io(X86CPUState *s, 
                         DeviceReadFunc *port_read, DeviceWriteFunc *port_write,
                         void *opaque)
{
}

int64_t x86_cpu_get_cycles(X86CPUState *s)
{
    return 0;
}

BOOL x86_cpu_get_power_down(X86CPUState *s)
{
    return FALSE;
}

void x86_cpu_flush_tlb_write_range_ram(X86CPUState *s,
                                       uint8_t *ram_ptr, size_t ram_size)
{
}
