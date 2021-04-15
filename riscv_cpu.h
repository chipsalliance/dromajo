/*
 * RISCV CPU emulator
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
#ifndef RISCV_CPU_H
#define RISCV_CPU_H

#include <stdlib.h>
#include "cutils.h"
#include "iomem.h"

#define MIP_USIP (1 << 0)
#define MIP_SSIP (1 << 1)
#define MIP_HSIP (1 << 2)
#define MIP_MSIP (1 << 3)
#define MIP_UTIP (1 << 4)
#define MIP_STIP (1 << 5)
#define MIP_HTIP (1 << 6)
#define MIP_MTIP (1 << 7)
#define MIP_UEIP (1 << 8)
#define MIP_SEIP (1 << 9)
#define MIP_HEIP (1 << 10)
#define MIP_MEIP (1 << 11)

typedef struct RISCVCPUState RISCVCPUState;

typedef struct {
    RISCVCPUState *(*riscv_cpu_init)(PhysMemoryMap *mem_map);
    void (*riscv_cpu_end)(RISCVCPUState *s);
    void (*riscv_cpu_interp)(RISCVCPUState *s, int n_cycles);
    uint64_t (*riscv_cpu_get_cycles)(RISCVCPUState *s);
    void (*riscv_cpu_set_mip)(RISCVCPUState *s, uint32_t mask);
    void (*riscv_cpu_reset_mip)(RISCVCPUState *s, uint32_t mask);
    uint32_t (*riscv_cpu_get_mip)(RISCVCPUState *s);
    BOOL (*riscv_cpu_get_power_down)(RISCVCPUState *s);
    uint32_t (*riscv_cpu_get_misa)(RISCVCPUState *s);
    void (*riscv_cpu_flush_tlb_write_range_ram)(RISCVCPUState *s,
                                                uint8_t *ram_ptr, size_t ram_size);
} RISCVCPUClass;

typedef struct {
    const RISCVCPUClass *class_ptr;
} RISCVCPUCommonState;

int riscv_cpu_get_max_xlen(void);

extern const RISCVCPUClass riscv_cpu_class32;
extern const RISCVCPUClass riscv_cpu_class64;
extern const RISCVCPUClass riscv_cpu_class128;

RISCVCPUState *riscv_cpu_init(PhysMemoryMap *mem_map, int max_xlen);
static inline void riscv_cpu_end(RISCVCPUState *s)
{
    const RISCVCPUClass *c = ((RISCVCPUCommonState *)s)->class_ptr;
    c->riscv_cpu_end(s);
}
static inline void riscv_cpu_interp(RISCVCPUState *s, int n_cycles)
{
    const RISCVCPUClass *c = ((RISCVCPUCommonState *)s)->class_ptr;
    c->riscv_cpu_interp(s, n_cycles);
}
static inline uint64_t riscv_cpu_get_cycles(RISCVCPUState *s)
{
    const RISCVCPUClass *c = ((RISCVCPUCommonState *)s)->class_ptr;
    return c->riscv_cpu_get_cycles(s);
}
static inline void riscv_cpu_set_mip(RISCVCPUState *s, uint32_t mask)
{
    const RISCVCPUClass *c = ((RISCVCPUCommonState *)s)->class_ptr;
    c->riscv_cpu_set_mip(s, mask);
}
static inline void riscv_cpu_reset_mip(RISCVCPUState *s, uint32_t mask)
{
    const RISCVCPUClass *c = ((RISCVCPUCommonState *)s)->class_ptr;
    c->riscv_cpu_reset_mip(s, mask);
}
static inline uint32_t riscv_cpu_get_mip(RISCVCPUState *s)
{
    const RISCVCPUClass *c = ((RISCVCPUCommonState *)s)->class_ptr;
    return c->riscv_cpu_get_mip(s);
}
static inline BOOL riscv_cpu_get_power_down(RISCVCPUState *s)
{
    const RISCVCPUClass *c = ((RISCVCPUCommonState *)s)->class_ptr;
    return c->riscv_cpu_get_power_down(s);
}
static inline uint32_t riscv_cpu_get_misa(RISCVCPUState *s)
{
    const RISCVCPUClass *c = ((RISCVCPUCommonState *)s)->class_ptr;
    return c->riscv_cpu_get_misa(s);
}
static inline void riscv_cpu_flush_tlb_write_range_ram(RISCVCPUState *s,
                                                       uint8_t *ram_ptr, size_t ram_size)
{
    const RISCVCPUClass *c = ((RISCVCPUCommonState *)s)->class_ptr;
    c->riscv_cpu_flush_tlb_write_range_ram(s, ram_ptr, ram_size);
}

#endif /* RISCV_CPU_H */
