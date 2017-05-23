/*
 * IO memory handling
 * 
 * Copyright (c) 2016-2017 Fabrice Bellard
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
#include "iomem.h"

#define PHYS_MEM_RANGE_MAX 16

struct PhysMemoryMap {
    int n_phys_mem_range;
    PhysMemoryRange phys_mem_range[PHYS_MEM_RANGE_MAX];
};

PhysMemoryMap *phys_mem_map_init(void)
{
    PhysMemoryMap *s;
    s = mallocz(sizeof(*s));
    return s;
}

void phys_mem_map_end(PhysMemoryMap *s)
{
    free(s);
}

/* return NULL if not found */
/* XXX: optimize */
PhysMemoryRange *get_phys_mem_range(PhysMemoryMap *s, uint64_t paddr)
{
    PhysMemoryRange *pr;
    int i;
    for(i = 0; i < s->n_phys_mem_range; i++) {
        pr = &s->phys_mem_range[i];
        if (paddr >= pr->addr && paddr < pr->addr + pr->size)
            return pr;
    }
    return NULL;
}

void cpu_register_ram(PhysMemoryMap *s, uint64_t addr,
                      uint64_t size, uintptr_t phys_mem_offset)
{
    PhysMemoryRange *pr;
    assert(s->n_phys_mem_range < PHYS_MEM_RANGE_MAX);
    pr = &s->phys_mem_range[s->n_phys_mem_range++];
    pr->addr = addr;
    pr->size = size;
    pr->is_ram = TRUE;
    pr->phys_mem_offset = phys_mem_offset;
}

void cpu_register_device(PhysMemoryMap *s, uint64_t addr,
                         uint64_t size, void *opaque,
                         DeviceReadFunc *read_func, DeviceWriteFunc *write_func,
                         int devio_flags)
{
    PhysMemoryRange *pr;
    assert(s->n_phys_mem_range < PHYS_MEM_RANGE_MAX);
    pr = &s->phys_mem_range[s->n_phys_mem_range++];
    pr->addr = addr;
    pr->size = size;
    pr->is_ram = FALSE;
    pr->opaque = opaque;
    pr->read_func = read_func;
    pr->write_func = write_func;
    pr->devio_flags = devio_flags;
}

