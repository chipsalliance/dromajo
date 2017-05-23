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
#ifndef IOMEM_H
#define IOMEM_H

typedef void DeviceWriteFunc(void *opaque, uint64_t offset,
                             uint64_t val, int size_log2);
typedef uint64_t DeviceReadFunc(void *opaque, uint64_t offset, int size_log2);

/* not related but for convenience */
typedef void DeviceSetIRQFunc(void *opaque, int irq_num, int level);

#define DEVIO_SIZE8  (1 << 0)
#define DEVIO_SIZE16 (1 << 1)
#define DEVIO_SIZE32 (1 << 2)
#define DEVIO_SIZE64 (1 << 3)

typedef struct {
    uint64_t addr;
    uint64_t size;
    BOOL is_ram;
    uintptr_t phys_mem_offset;
    void *opaque;
    DeviceReadFunc *read_func;
    DeviceWriteFunc *write_func;
    int devio_flags;
} PhysMemoryRange;

typedef struct PhysMemoryMap PhysMemoryMap;

PhysMemoryMap *phys_mem_map_init(void);
void phys_mem_map_end(PhysMemoryMap *s);
void cpu_register_ram(PhysMemoryMap *s, uint64_t addr,
                      uint64_t size, uintptr_t phys_mem_offset);
void cpu_register_device(PhysMemoryMap *s, uint64_t addr,
                         uint64_t size, void *opaque,
                         DeviceReadFunc *read_func, DeviceWriteFunc *write_func,
                         int devio_flags);
PhysMemoryRange *get_phys_mem_range(PhysMemoryMap *s, uint64_t paddr);

#endif /* IOMEM_H */
