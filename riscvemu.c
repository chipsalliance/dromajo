/*
 * RISCV emulator
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
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#ifdef EMSCRIPTEN
#include <emscripten.h>
#else
#include <getopt.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/stat.h>
#endif

#include "cutils.h"
#include "virtio.h"

/*
  TODO:
  - fix 9p directory handling in fs_disk.c:fs_open()
  - fix memory leak of fs_wget()
  - add a /dev/rtc in Linux
  - various optimizations: cache PC page, optimize interrupt tests
*/

#ifndef MAX_XLEN
//#define MAX_XLEN 32
#define MAX_XLEN 64
//#define MAX_XLEN 128
#endif

#ifndef FLEN
#if MAX_XLEN == 128
#define FLEN 128
#else
#define FLEN 64
#endif
#endif /* !FLEN */

#ifndef DEFAULT_RAM_SIZE
#define DEFAULT_RAM_SIZE 256
#endif

#if MAX_XLEN >= 64
#define CONFIG_EXT_DYN_XLEN /* allow dynamic XLEN change */
#endif
#define CONFIG_EXT_C /* compressed instructions */

//#define DUMP_ADDR
//#define DUMP_INVALID_MEM_ACCESS
//#define DUMP_MMU_EXCEPTIONS
//#define DUMP_INTERRUPTS
//#define DUMP_INVALID_CSR
//#define DUMP_EXCEPTIONS
//#define DUMP_CSR
//#define CONFIG_LOGFILE

#if FLEN > 0
#include "softfp.h"
#endif

#define RTC_BASE_ADDR  0x40000000
#define RAM_BASE_ADDR  0x80000000
#define HTIF_BASE_ADDR 0x40008000
#define IDE_BASE_ADDR  0x40009000
#define PLIC_BASE_ADDR 0x40002000

#if MAX_XLEN == 32
typedef uint32_t target_ulong;
typedef int32_t target_long;
#define PR_target_ulong "08x"
#elif MAX_XLEN == 64
typedef uint64_t target_ulong;
typedef int64_t target_long;
#define PR_target_ulong "016" PRIx64
#elif MAX_XLEN == 128
typedef uint128_t target_ulong;
typedef int128_t target_long;
#define PR_target_ulong "016" PRIx64 /* XXX */
#else
#error unsupported MAX_XLEN
#endif

/* FLEN is the floating point register width */
#if FLEN > 0
#if FLEN == 32
typedef uint32_t fp_uint;
#elif FLEN == 64
typedef uint64_t fp_uint;
#elif FLEN == 128
typedef uint128_t fp_uint;
#else
#error unsupported FLEN
#endif
#endif

/* MLEN is the maximum memory access width */
#if MAX_XLEN <= 32 && FLEN <= 32
#define MLEN 32
#elif MAX_XLEN <= 64 && FLEN <= 64
#define MLEN 64
#else
#define MLEN 128
#endif

#if MLEN == 32
typedef uint32_t mem_uint_t;
#elif MLEN == 64
typedef uint64_t mem_uint_t;
#elif MLEN == 128
typedef uint128_t mem_uint_t;
#else
#unsupported MLEN
#endif

#define TLB_SIZE 256

#define CAUSE_MISALIGNED_FETCH    0x0
#define CAUSE_FAULT_FETCH         0x1
#define CAUSE_ILLEGAL_INSTRUCTION 0x2
#define CAUSE_BREAKPOINT          0x3
#define CAUSE_MISALIGNED_LOAD     0x4
#define CAUSE_FAULT_LOAD          0x5
#define CAUSE_MISALIGNED_STORE    0x6
#define CAUSE_FAULT_STORE         0x7
#define CAUSE_USER_ECALL          0x8
#define CAUSE_SUPERVISOR_ECALL    0x9
#define CAUSE_HYPERVISOR_ECALL    0xa
#define CAUSE_MACHINE_ECALL       0xb
/* Note: converted to correct bit position at runtime */
#define CAUSE_INTERRUPT  ((uint32_t)1 << 31) 

#define PRV_U 0
#define PRV_S 1
#define PRV_H 2
#define PRV_M 3

/* misa CSR */
#define MCPUID_SUPER   (1 << ('S' - 'A'))
#define MCPUID_USER    (1 << ('U' - 'A'))
#define MCPUID_I       (1 << ('I' - 'A'))
#define MCPUID_M       (1 << ('M' - 'A'))
#define MCPUID_A       (1 << ('A' - 'A'))
#define MCPUID_F       (1 << ('F' - 'A'))
#define MCPUID_D       (1 << ('D' - 'A'))
#define MCPUID_Q       (1 << ('Q' - 'A'))
#define MCPUID_C       (1 << ('C' - 'A'))

/* mstatus CSR */

#define MSTATUS_SPIE_SHIFT 5
#define MSTATUS_MPIE_SHIFT 7
#define MSTATUS_SPP_SHIFT 8
#define MSTATUS_MPP_SHIFT 11
#define MSTATUS_VM_SHIFT 24
#define MSTATUS_FS_SHIFT 13

#define MSTATUS_UIE (1 << 0)
#define MSTATUS_SIE (1 << 1)
#define MSTATUS_HIE (1 << 2)
#define MSTATUS_MIE (1 << 3)
#define MSTATUS_UPIE (1 << 4)
#define MSTATUS_SPIE (1 << MSTATUS_SPIE_SHIFT)
#define MSTATUS_HPIE (1 << 6)
#define MSTATUS_MPIE (1 << MSTATUS_MPIE_SHIFT)
#define MSTATUS_SPP (1 << MSTATUS_SPP_SHIFT)
#define MSTATUS_HPP (3 << 9)
#define MSTATUS_MPP (3 << MSTATUS_MPP_SHIFT)
#define MSTATUS_FS (3 << MSTATUS_FS_SHIFT)
#define MSTATUS_XS (3 << 15)
#define MSTATUS_MPRV (1 << 17)
#define MSTATUS_PUM (1 << 18)
#define MSTATUS_MXR (1 << 19)
#define MSTATUS_VM (0x1f << MSTATUS_VM_SHIFT)
#ifdef CONFIG_EXT_DYN_XLEN
/* Note: UB/SB/HB/MB could be moved to the 2 LSBs of
   utvec/stvec/htvec/mtvec */
#define MSTATUS_UB_SHIFT 32 
#define MSTATUS_SB_SHIFT 34
#define MSTATUS_HB_SHIFT 36
#define MSTATUS_MB_SHIFT 38
#define MSTATUS_UPB_SHIFT 40
#define MSTATUS_SPB_SHIFT 42
#define MSTATUS_HPB_SHIFT 44
#define MSTATUS_MPB_SHIFT 46
#define MSTATUS_UB ((uint64_t)1 << MSTATUS_UB_SHIFT)
#define MSTATUS_SB ((uint64_t)1 << MSTATUS_SB_SHIFT)
#define MSTATUS_HB ((uint64_t)1 << MSTATUS_HB_SHIFT)
#define MSTATUS_MB ((uint64_t)1 << MSTATUS_MB_SHIFT)
#define MSTATUS_UPB ((uint64_t)1 << MSTATUS_UPB_SHIFT)
#define MSTATUS_SPB ((uint64_t)1 << MSTATUS_SPB_SHIFT)
#define MSTATUS_HPB ((uint64_t)1 << MSTATUS_HPB_SHIFT)
#define MSTATUS_MPB ((uint64_t)1 << MSTATUS_MPB_SHIFT)
#else
#define MSTATUS_UB 0
#define MSTATUS_SB 0
#define MSTATUS_HB 0
#define MSTATUS_MB 0
#define MSTATUS_UPB 0
#define MSTATUS_SPB 0
#define MSTATUS_HPB 0
#define MSTATUS_MPB 0
#endif

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

#define PG_SHIFT 12
#define PG_MASK ((1 << PG_SHIFT) - 1)

typedef struct {
    target_ulong vaddr;
    uintptr_t mem_addend;
} TLBEntry;

typedef void DeviceWriteFunc(void *opaque, target_ulong offset,
                             target_ulong val, int size_log2);
typedef target_ulong DeviceReadFunc(void *opaque, target_ulong offset,
                                    int size_log2);

#define DEVIO_SIZE8  (1 << 0)
#define DEVIO_SIZE16 (1 << 1)
#define DEVIO_SIZE32 (1 << 2)
#define DEVIO_SIZE64 (1 << 3)

typedef struct {
    target_ulong addr;
    target_ulong size;
    BOOL is_ram;
    uintptr_t phys_mem_offset;
    void *opaque;
    DeviceReadFunc *read_func;
    DeviceWriteFunc *write_func;
    int devio_flags;
} PhysMemoryRange;

#define PHYS_MEM_RANGE_MAX 16

typedef struct RISCVMachine RISCVMachine;

typedef struct RISCVCPUState {
    target_ulong pc;
    target_ulong reg[32];

#if FLEN > 0
    fp_uint fp_reg[32];
    uint32_t fflags;
    uint8_t frm;
#endif
    
    uint8_t cur_xlen;  /* current XLEN value, <= MAX_XLEN */
    uint8_t priv; /* see PRV_x */
    uint8_t fs; /* MSTATUS_FS value */
    
    uint64_t insn_counter;
    uint64_t timecmp; /* for RTC */
    BOOL power_down_flag;
    
    /* CSRs */
    target_ulong mstatus;
    target_ulong mtvec;
    target_ulong mscratch;
    target_ulong mepc;
    target_ulong mcause;
    target_ulong mbadaddr;
    target_ulong mhartid; /* ro */
    target_ulong misa;
    uint32_t mie;
    uint32_t mip;
    uint32_t medeleg;
    uint32_t mideleg;
    
    target_ulong stvec;
    target_ulong sscratch;
    target_ulong sepc;
    target_ulong scause;
    target_ulong sbadaddr;
    target_ulong sptbr;

    target_ulong mcounteren[3];
    
    target_ulong load_res; /* for atomic LR/SC */
    
    uint8_t *phys_mem;
    target_ulong phys_mem_size; /* in bytes */

    int n_phys_mem_range;
    PhysMemoryRange phys_mem_range[PHYS_MEM_RANGE_MAX];

    RISCVMachine *machine_state;
    
    TLBEntry tlb_read[TLB_SIZE];
    TLBEntry tlb_write[TLB_SIZE];
    TLBEntry tlb_code[TLB_SIZE];
} RISCVCPUState;

void *mallocz(size_t size)
{
    void *ptr;
    ptr = malloc(size);
    if (!ptr)
        return NULL;
    memset(ptr, 0, size);
    return ptr;
}

static no_inline int target_read_slow(RISCVCPUState *s, mem_uint_t *pval,
                                      target_ulong addr, int size_log2);
static no_inline int target_write_slow(RISCVCPUState *s, target_ulong addr,
                                       mem_uint_t val, int size_log2);
static void raise_exception2(RISCVCPUState *s, uint32_t cause,
                             target_ulong badaddr);


#ifdef CONFIG_LOGFILE
static FILE *log_file;

void log_vprintf(const char *fmt, va_list ap)
{
    if (!log_file)
        log_file = fopen("/tmp/riscemu.log", "wb");
    vfprintf(log_file, fmt, ap);
}
#else
void log_vprintf(const char *fmt, va_list ap)
{
    vprintf(fmt, ap);
}
#endif

void __attribute__((format(printf, 1, 2))) log_printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    log_vprintf(fmt, ap);
    va_end(ap);
}

#if MAX_XLEN == 128
static void fprint_target_ulong(FILE *f, target_ulong a)
{
    fprintf(f, "%016" PRIx64 "%016" PRIx64, (uint64_t)(a >> 64), (uint64_t)a);
}
#else
static void fprint_target_ulong(FILE *f, target_ulong a)
{
    fprintf(f, "%" PR_target_ulong, a);
}
#endif

static void print_target_ulong(target_ulong a)
{
    fprint_target_ulong(stdout, a);
}

void cpu_register_ram(RISCVCPUState *s, target_ulong addr,
                      target_ulong size, 
                      uintptr_t phys_mem_offset)
{
    PhysMemoryRange *pr;
    assert(s->n_phys_mem_range < PHYS_MEM_RANGE_MAX);
    pr = &s->phys_mem_range[s->n_phys_mem_range++];
    pr->addr = addr;
    pr->size = size;
    pr->is_ram = TRUE;
    pr->phys_mem_offset = phys_mem_offset;
}

void cpu_register_device(RISCVCPUState *s, target_ulong addr,
                         target_ulong size, void *opaque,
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

static char *reg_name[32] = {
"zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
"s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5",
"a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
"s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"
};

static void dump_regs(RISCVCPUState *s)
{
    int i, cols;
    const char priv_str[4] = "USHM";
    cols = 256 / MAX_XLEN;
    printf("pc =");
    print_target_ulong(s->pc);
    printf(" ");
    for(i = 1; i < 32; i++) {
        printf("%-3s=", reg_name[i]);
        print_target_ulong(s->reg[i]);
        if ((i & (cols - 1)) == (cols - 1))
            printf("\n");
        else
            printf(" ");
    }
    printf("priv=%c", priv_str[s->priv]);
    printf(" mstatus=");
    print_target_ulong(s->mstatus);
    printf(" cycles=%" PRId64, s->insn_counter);
    printf("\n");
#if 1
    printf(" mideleg=");
    print_target_ulong(s->mideleg);
    printf(" mie=");
    print_target_ulong(s->mie);
    printf(" mip=");
    print_target_ulong(s->mip);
    printf("\n");
#endif
}

static __attribute__((unused)) void cpu_abort(RISCVCPUState *s)
{
    dump_regs(s);
    abort();
}

/* return NULL if not found */
static PhysMemoryRange *get_phys_mem_range(RISCVCPUState *s, target_ulong paddr)
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

/* addr must be aligned. Only RAM accesses are supported */
#define PHYS_MEM_READ_WRITE(size, uint_type) \
static inline void phys_write_u ## size(RISCVCPUState *s, target_ulong addr,\
                                        uint_type val)                   \
{\
    PhysMemoryRange *pr = get_phys_mem_range(s, addr);\
    if (!pr || !pr->is_ram)\
        return;\
    *(uint_type *)(s->phys_mem + pr->phys_mem_offset +\
                 (uintptr_t)(addr - pr->addr)) = val;\
}\
\
static inline uint_type phys_read_u ## size(RISCVCPUState *s, target_ulong addr) \
{\
    PhysMemoryRange *pr = get_phys_mem_range(s, addr);\
    if (!pr || !pr->is_ram)\
        return 0;\
    return *(uint_type *)(s->phys_mem + pr->phys_mem_offset +\
                          (uintptr_t)(addr - pr->addr));     \
}

PHYS_MEM_READ_WRITE(8, uint8_t)
PHYS_MEM_READ_WRITE(32, uint32_t)
PHYS_MEM_READ_WRITE(64, uint64_t)

/* return 0 if OK, != 0 if exception */
#define TARGET_READ_WRITE(size, uint_type, size_log2)                   \
static inline int target_read_u ## size(RISCVCPUState *s, uint_type *pval, target_ulong addr)                              \
{\
    uint32_t tlb_idx;\
    tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);\
    if (likely(s->tlb_read[tlb_idx].vaddr == (addr & ~(PG_MASK & ~((size / 8) - 1))))) { \
        *pval = *(uint_type *)(s->tlb_read[tlb_idx].mem_addend + (uintptr_t)addr);\
    } else {\
        mem_uint_t val;\
        int ret;\
        ret = target_read_slow(s, &val, addr, size_log2);\
        if (ret)\
            return ret;\
        *pval = val;\
    }\
    return 0;\
}\
\
static inline int target_write_u ## size(RISCVCPUState *s, target_ulong addr,\
                                          uint_type val)                \
{\
    uint32_t tlb_idx;\
    tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);\
    if (likely(s->tlb_write[tlb_idx].vaddr == (addr & ~(PG_MASK & ~((size / 8) - 1))))) { \
        *(uint_type *)(s->tlb_write[tlb_idx].mem_addend + (uintptr_t)addr) = val;\
        return 0;\
    } else {\
        return target_write_slow(s, addr, val, size_log2);\
    }\
}

TARGET_READ_WRITE(8, uint8_t, 0)
TARGET_READ_WRITE(16, uint16_t, 1)
TARGET_READ_WRITE(32, uint32_t, 2)
#if MLEN >= 64
TARGET_READ_WRITE(64, uint64_t, 3)
#endif
#if MLEN >= 128
TARGET_READ_WRITE(128, uint128_t, 4)
#endif

#define PTE_V_MASK (1 << 0)
#define PTE_U_MASK (1 << 4)
#define PTE_A_MASK (1 << 6)
#define PTE_D_MASK (1 << 7)

#define ACCESS_READ  0
#define ACCESS_WRITE 1
#define ACCESS_CODE  2

/* access = 0: read, 1 = write, 2 = code. Set the exception_pending
   field if necessary. return 0 if OK, -1 if translation error */
static int get_phys_addr(RISCVCPUState *s,
                         target_ulong *ppaddr, target_ulong vaddr,
                         int access)
{
    int vm, levels, pte_bits, pte_idx, pte_mask, pte_size_log2, xwr, priv;
    int need_write, vaddr_shift, i;
    target_ulong pte_addr, pte, vaddr_mask, paddr;

    if ((s->mstatus & MSTATUS_MPRV) && access != ACCESS_CODE) {
        /* use previous priviledge */
        priv = (s->mstatus >> MSTATUS_MPP_SHIFT) & 3;
    } else {
        priv = s->priv;
    }

    if (priv == PRV_M) {
        if (s->cur_xlen < MAX_XLEN) {
            /* truncate virtual address */
            *ppaddr = vaddr & (((target_ulong)1 << s->cur_xlen) - 1);
        } else {
            *ppaddr = vaddr;
        }
        return 0;
    }
    
    vm = (s->mstatus >> MSTATUS_VM_SHIFT) & 0x1f;
    switch(vm) {
    case 0: /* mbare */
    default:
        /* no translation */
        *ppaddr = vaddr;
        return 0;
    case 8: /* sv32 */
        levels = 2;
        pte_size_log2 = 2;
        break;
#if MAX_XLEN >= 64
    case 9: /* sv39 */
    case 10: /* sv48 */
        levels = vm - 9 + 3;
        pte_size_log2 = 3;
        vaddr_shift = MAX_XLEN - (PG_SHIFT + levels * 9);
        if ((((target_long)vaddr << vaddr_shift) >> vaddr_shift) != vaddr)
            return -1;
        break;
#endif
    }
    pte_bits = 12 - pte_size_log2;
    pte_addr = s->sptbr << PG_SHIFT;
    pte_mask = (1 << pte_bits) - 1;
    for(i = 0; i < levels; i++) {
        vaddr_shift = PG_SHIFT + pte_bits * (levels - 1 - i);
        pte_idx = (vaddr >> vaddr_shift) & pte_mask;
        pte_addr += pte_idx << pte_size_log2;
        if (pte_size_log2 == 2)
            pte = phys_read_u32(s, pte_addr);
        else
            pte = phys_read_u64(s, pte_addr);
        //printf("pte=0x%08" PRIx64 "\n", pte);
        if (!(pte & PTE_V_MASK))
            return -1; /* invalid PTE */
        paddr = (pte >> 10) << PG_SHIFT;
        xwr = (pte >> 1) & 7;
        if (xwr != 0) {
            if (xwr == 2 || xwr == 6)
                return -1;
            /* priviledge check */
            if (priv == PRV_S) {
                if ((pte & PTE_U_MASK) && (s->mstatus & MSTATUS_PUM))
                    return -1;
            } else {
                if (!(pte & PTE_U_MASK))
                    return -1;
            }
            /* protection check */
            /* MXR allows read access to execute-only pages */
            if (s->mstatus & MSTATUS_MXR)
                xwr |= (xwr >> 2);

            if (((xwr >> access) & 1) == 0)
                return -1;
            need_write = !(pte & PTE_A_MASK) ||
                (!(pte & PTE_D_MASK) && access == ACCESS_WRITE);
            pte |= PTE_A_MASK;
            if (access == ACCESS_WRITE)
                pte |= PTE_D_MASK;
            if (need_write) {
                if (pte_size_log2 == 2)
                    phys_write_u32(s, pte_addr, pte);
                else
                    phys_write_u64(s, pte_addr, pte);
            }
            vaddr_mask = ((target_ulong)1 << vaddr_shift) - 1;
            *ppaddr = (vaddr & vaddr_mask) | (paddr  & ~vaddr_mask);
            return 0;
        } else {
            pte_addr = paddr;
        }
    }
    return -1;
}

/* return 0 if OK, != 0 if exception */
static no_inline int target_read_slow(RISCVCPUState *s, mem_uint_t *pval,
                                      target_ulong addr, int size_log2)
{
    int size, tlb_idx, err, al;
    target_ulong paddr, offset;
    uint8_t *ptr;
    PhysMemoryRange *pr;
    mem_uint_t ret;

    /* first handle unaligned accesses */
    size = 1 << size_log2;
    al = addr & (size - 1);
    if (al != 0) {
        switch(size_log2) {
        case 1:
            {
                uint8_t v0, v1;
                err = target_read_u8(s, &v0, addr);
                if (err)
                    return err;
                err = target_read_u8(s, &v1, addr + 1);
                if (err)
                    return err;
                ret = v0 | (v1 << 8);
            }
            break;
        case 2:
            {
                uint32_t v0, v1;
                addr -= al;
                err = target_read_u32(s, &v0, addr);
                if (err)
                    return err;
                err = target_read_u32(s, &v1, addr + 4);
                if (err)
                    return err;
                ret = (v0 >> (al * 8)) | (v1 << (32 - al * 8));
            }
            break;
#if MLEN >= 64
        case 3:
            {
                uint64_t v0, v1;
                addr -= al;
                err = target_read_u64(s, &v0, addr);
                if (err)
                    return err;
                err = target_read_u64(s, &v1, addr + 8);
                if (err)
                    return err;
                ret = (v0 >> (al * 8)) | (v1 << (64 - al * 8));
            }
            break;
#endif
#if MLEN >= 128
        case 4:
            {
                uint128_t v0, v1;
                addr -= al;
                err = target_read_u128(s, &v0, addr);
                if (err)
                    return err;
                err = target_read_u128(s, &v1, addr + 8);
                if (err)
                    return err;
                ret = (v0 >> (al * 8)) | (v1 << (128 - al * 8));
            }
            break;
#endif
        default:
            abort();
        }
    } else {
        if (get_phys_addr(s, &paddr, addr, ACCESS_READ)) {
            raise_exception2(s, CAUSE_FAULT_LOAD, addr);
            return -1;
        }
        pr = get_phys_mem_range(s, paddr);
#ifdef DUMP_ADDR
        if (pr) {
            printf("addr:");
            print_target_ulong(paddr);
        }
#endif
        if (!pr) {
#ifdef DUMP_INVALID_MEM_ACCESS
            printf("target_read_slow: invalid physical address 0x");
            print_target_ulong(paddr);
            printf("\n");
#endif
            return 0;
        } else if (pr->is_ram) {
            tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
            ptr = s->phys_mem + pr->phys_mem_offset +
                (uintptr_t)(paddr - pr->addr);
            s->tlb_read[tlb_idx].vaddr = addr & ~PG_MASK;
            s->tlb_read[tlb_idx].mem_addend = (uintptr_t)ptr - addr;
            switch(size_log2) {
            case 0:
                ret = *(uint8_t *)ptr;
                break;
            case 1:
                ret = *(uint16_t *)ptr;
                break;
            case 2:
                ret = *(uint32_t *)ptr;
                break;
#if MLEN >= 64
            case 3:
                ret = *(uint64_t *)ptr;
                break;
#endif
#if MLEN >= 128
            case 4:
                ret = *(uint128_t *)ptr;
                break;
#endif
            default:
                abort();
            }
        } else {
            offset = paddr - pr->addr;
            if (((pr->devio_flags >> size_log2) & 1) != 0) {
                ret = pr->read_func(pr->opaque, offset, size_log2);
            }
#if MLEN >= 64
            else if ((pr->devio_flags & DEVIO_SIZE32) && size_log2 == 3) {
                /* emulate 64 bit access */
                ret = pr->read_func(pr->opaque, offset, 2);
                ret |= (uint64_t)pr->read_func(pr->opaque, offset + 4, 2) << 32;
                
            }
#endif
            else {
#ifdef DUMP_INVALID_MEM_ACCESS
                printf("unsupported device read access: addr=0x");
                print_target_ulong(paddr);
                printf(" width=%d bits\n", 1 << (3 + size_log2));
#endif
                ret = 0;
            }
        }
    }
    *pval = ret;
    return 0;
}

/* return 0 if OK, != 0 if exception */
static no_inline int target_write_slow(RISCVCPUState *s, target_ulong addr,
                                       mem_uint_t val, int size_log2)
{
    int size, i, tlb_idx, err;
    target_ulong paddr, offset;
    uint8_t *ptr;
    PhysMemoryRange *pr;
    
    /* first handle unaligned accesses */
    size = 1 << size_log2;
    if ((addr & (size - 1)) != 0) {
        /* XXX: should avoid modifying the memory in case of exception */
        for(i = 0; i < size; i++) {
            err = target_write_u8(s, addr + i, (val >> (8 * i)) & 0xff);
            if (err)
                return err;
        }
    } else {
        if (get_phys_addr(s, &paddr, addr, ACCESS_WRITE)) {
            raise_exception2(s, CAUSE_FAULT_STORE, addr);
            return -1;
        }
        pr = get_phys_mem_range(s, paddr);
        if (!pr) {
#ifdef DUMP_INVALID_MEM_ACCESS
            printf("target_write_slow: invalid physical address 0x");
            print_target_ulong(paddr);
            printf("\n");
#endif
        } else if (pr->is_ram) {
            tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
            ptr = s->phys_mem + pr->phys_mem_offset +
                (uintptr_t)(paddr - pr->addr);
            s->tlb_write[tlb_idx].vaddr = addr & ~PG_MASK;
            s->tlb_write[tlb_idx].mem_addend = (uintptr_t)ptr - addr;
            switch(size_log2) {
            case 0:
                *(uint8_t *)ptr = val;
                break;
            case 1:
                *(uint16_t *)ptr = val;
                break;
            case 2:
                *(uint32_t *)ptr = val;
                break;
#if MLEN >= 64
            case 3:
                *(uint64_t *)ptr = val;
                break;
#endif
#if MLEN >= 128
            case 4:
                *(uint128_t *)ptr = val;
                break;
#endif
            default:
                abort();
            }
        } else {
            offset = paddr - pr->addr;
            if (((pr->devio_flags >> size_log2) & 1) != 0) {
                pr->write_func(pr->opaque, offset, val, size_log2);
            }
#if MLEN >= 64
            else if ((pr->devio_flags & DEVIO_SIZE32) && size_log2 == 3) {
                /* emulate 64 bit access */
                pr->write_func(pr->opaque, offset,
                               val & 0xffffffff, 2);
                pr->write_func(pr->opaque, offset + 4,
                               (val >> 32) & 0xffffffff, 2);
            }
#endif
            else {
#ifdef DUMP_INVALID_MEM_ACCESS
                printf("unsupported device write access: addr=0x");
                print_target_ulong(paddr);
                printf(" width=%d bits\n", 1 << (3 + size_log2));
#endif
            }
        }
    }
    return 0;
}

struct __attribute__((packed)) unaligned_u32 {
    uint32_t u32;
};

/* unaligned access at an address known to be a multiple of 2 */
static uint32_t get_insn32(uint8_t *ptr)
{
#if defined(EMSCRIPTEN)
    return ((uint16_t *)ptr)[0] | (((uint16_t *)ptr)[1] << 16);
#else
    return ((struct unaligned_u32 *)ptr)->u32;
#endif
}

/* return 0 if OK, != 0 if exception */
static no_inline int target_read_insn_slow(RISCVCPUState *s,
                                           uint32_t *pinsn,
                                           target_ulong addr,
                                           BOOL short_insn)
{
    int tlb_idx, err;
    target_ulong paddr;
    uint8_t *ptr;
    PhysMemoryRange *pr;
    uint32_t insn, val;
    
    if ((addr & PG_MASK) == (PG_MASK - 1) && !short_insn) {
        /* instruction potentially between two pages */
        err = target_read_insn_slow(s, &insn, addr, TRUE);
        if (err)
            return err;
        if ((insn & 3) == 3) {
            err = target_read_insn_slow(s, &val, addr + 2, TRUE);
            if (err)
                return err;
            insn |= val << 16;
        }
    } else {
        if (get_phys_addr(s, &paddr, addr, ACCESS_CODE)) {
            raise_exception2(s, CAUSE_FAULT_FETCH, addr);
            return -1;
        }
        pr = get_phys_mem_range(s, paddr);
        if (!pr || !pr->is_ram) {
            /* we only access to execute code from RAM */
            raise_exception2(s, CAUSE_FAULT_FETCH, addr);
            return -1;
        }
        tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
        ptr = s->phys_mem + pr->phys_mem_offset +
            (uintptr_t)(paddr - pr->addr);
        s->tlb_code[tlb_idx].vaddr = addr & ~PG_MASK;
        s->tlb_code[tlb_idx].mem_addend = (uintptr_t)ptr - addr;
        if (short_insn) {
            insn = *(uint16_t *)ptr;
        } else {
            insn = get_insn32(ptr);
        }
    }
    *pinsn = insn;
    return 0;
}

/* it is assumed that addr is even */
/* return 0 if OK, != 0 if exception */
static inline int target_read_insn(RISCVCPUState *s, uint32_t *pinsn,
                                   target_ulong addr)
{
    uint32_t tlb_idx;
    tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
    if (likely(s->tlb_code[tlb_idx].vaddr == (addr & ~PG_MASK) &&
               (addr & PG_MASK) != (PG_MASK - 1))) {
        *pinsn = get_insn32((uint8_t *)(s->tlb_code[tlb_idx].mem_addend +
                                        (uintptr_t)addr));
        return 0;
    } else {
        return target_read_insn_slow(s, pinsn, addr, FALSE);
    }
}

static void tlb_init(RISCVCPUState *s)
{
    int i;
    
    for(i = 0; i < TLB_SIZE; i++) {
        s->tlb_read[i].vaddr = -1;
        s->tlb_write[i].vaddr = -1;
        s->tlb_code[i].vaddr = -1;
    }
}

static void tlb_flush_all(RISCVCPUState *s)
{
    tlb_init(s);
}

static void tlb_flush_vaddr(RISCVCPUState *s, target_ulong vaddr)
{
    tlb_flush_all(s);
}

#define SSTATUS_MASK (MSTATUS_UIE | MSTATUS_SIE |       \
                      MSTATUS_UPIE | MSTATUS_SPIE |     \
                      MSTATUS_SPP | \
                      MSTATUS_FS | MSTATUS_XS | \
                      MSTATUS_PUM | \
                      MSTATUS_SB | MSTATUS_SPB)

#define MSTATUS_MASK (MSTATUS_UIE | MSTATUS_SIE | MSTATUS_MIE |      \
                      MSTATUS_UPIE | MSTATUS_SPIE | MSTATUS_MPIE |    \
                      MSTATUS_SPP | MSTATUS_MPP | \
                      MSTATUS_FS | \
                      MSTATUS_MPRV | MSTATUS_PUM | MSTATUS_MXR | \
                      MSTATUS_VM | \
                      MSTATUS_SB | MSTATUS_MB | MSTATUS_SPB | MSTATUS_MPB)

static BOOL check_vm(RISCVCPUState *s, int vm)
{
    int vm_max;
    if (vm == 0)
        return TRUE;
    if (s->cur_xlen == 32)
        vm_max = 8;
    else
        vm_max = 10;
    return (vm >= 8 && vm <= vm_max);
}

/* return the complete mstatus with the SD bit */
static target_ulong get_mstatus(RISCVCPUState *s, target_ulong mask)
{
    target_ulong val;
    BOOL sd;
    val = s->mstatus | (s->fs << MSTATUS_FS_SHIFT);
    val &= mask;
    sd = ((val & MSTATUS_FS) == MSTATUS_FS) |
        ((val & MSTATUS_XS) == MSTATUS_XS);
    if (sd)
        val |= (target_ulong)1 << (s->cur_xlen - 1);
    return val;
}
                              
static void set_mstatus(RISCVCPUState *s, target_ulong val)
{
    int vm;
    target_ulong mod, mask;
    
    /* flush the TLBs if change of MMU config */
    mod = s->mstatus ^ val;
    if ((mod & (MSTATUS_MPRV | MSTATUS_PUM | MSTATUS_MXR | MSTATUS_VM)) != 0 ||
        ((s->mstatus & MSTATUS_MPRV) && (mod & MSTATUS_MPP) != 0)) {
        tlb_flush_all(s);
    }
    s->fs = (val >> MSTATUS_FS_SHIFT) & 3;

    mask = MSTATUS_MASK & ~MSTATUS_FS;
    vm = (val >> MSTATUS_VM_SHIFT) & 0x1f;
    if (!check_vm(s, vm))
        mask &= ~MSTATUS_VM;
    s->mstatus = (s->mstatus & ~mask) | (val & mask);
}

static int get_base_from_xlen(int xlen)
{
    if (xlen == 32)
        return 1;
    else if (xlen == 64)
        return 2;
    else
        return 3;
}

#ifdef CONFIG_EXT_DYN_XLEN
static int get_valid_base(int base)
{
    int base_max;
    if (MAX_XLEN == 64)
        base_max = 2;
    else if (MAX_XLEN == 128)
        base_max = 3;
    else
        base_max = 1;
    if (base < 1 || base > base_max) {
        base = base_max;
    }
    return base;
}
#endif

/* return -1 if invalid CSR. 0 if OK. 'will_write' indicate that the
   csr will be written after (used for CSR access check) */
static int csr_read(RISCVCPUState *s, target_ulong *pval, uint32_t csr,
                     BOOL will_write)
{
    target_ulong val;

    if (((csr & 0xc00) == 0xc00) && will_write)
        return -1; /* read-only CSR */
    if (s->priv < ((csr >> 8) & 3))
        return -1; /* not enough priviledge */
    
    switch(csr) {
#if FLEN > 0
    case 0x001: /* fflags */
        if (s->fs == 0)
            return -1;
        val = s->fflags;
        break;
    case 0x002: /* frm */
        if (s->fs == 0)
            return -1;
        val = s->frm;
        break;
    case 0x003:
        if (s->fs == 0)
            return -1;
        val = s->fflags | (s->frm << 5);
        break;
#endif
    case 0xc00: /* ucycle */
    case 0xc02: /* uinstret */
        if (s->priv <= PRV_H &&
            ((s->mcounteren[s->priv] >> (csr & 0x1f)) & 1) == 0)
            goto invalid_csr;
        val = (int64_t)s->insn_counter;
        break;
    case 0xc80: /* mcycleh */
    case 0xc82: /* minstreth */
        if (s->cur_xlen != 32)
            goto invalid_csr;
        if (s->priv <= PRV_H &&
            ((s->mcounteren[s->priv] >> (csr & 0x1f)) & 1) == 0)
            goto invalid_csr;
        val = s->insn_counter >> 32;
        break;
        
    case 0x100:
        val = get_mstatus(s, SSTATUS_MASK);
        break;
    case 0x104: /* sie */
        val = s->mie & s->mideleg;
        break;
    case 0x105:
        val = s->stvec;
        break;
    case 0x140:
        val = s->sscratch;
        break;
    case 0x141:
        val = s->sepc;
        break;
    case 0x142:
        val = s->scause;
        break;
    case 0x143:
        val = s->sbadaddr;
        break;
    case 0x144: /* sip */
        val = s->mip & s->mideleg;
        break;
    case 0x180:
        val = s->sptbr;
        break;
    case 0x300:
        val = get_mstatus(s, (target_ulong)-1);
        break;
    case 0x301:
        val = s->misa;
        val |= (target_ulong)get_base_from_xlen(s->cur_xlen) << 
            (s->cur_xlen - 2);
        break;
    case 0x302:
        val = s->medeleg;
        break;
    case 0x303:
        val = s->mideleg;
        break;
    case 0x304:
        val = s->mie;
        break;
    case 0x305:
        val = s->mtvec;
        break;
    case 0x320:
    case 0x321:
        val = s->mcounteren[csr & 3];
        break;
    case 0x340:
        val = s->mscratch;
        break;
    case 0x341:
        val = s->mepc;
        break;
    case 0x342:
        val = s->mcause;
        break;
    case 0x343:
        val = s->mbadaddr;
        break;
    case 0x344:
        val = s->mip;
        break;
    case 0xb00: /* mcycle */
    case 0xb02: /* minstret */
        val = (int64_t)s->insn_counter;
        break;
    case 0xb80: /* mcycleh */
    case 0xb82: /* minstreth */
        if (s->cur_xlen != 32)
            goto invalid_csr;
        val = s->insn_counter >> 32;
        break;
    case 0xf14:
        val = s->mhartid;
        break;
    default:
    invalid_csr:
#ifdef DUMP_INVALID_CSR
        printf("csr_read: invalid CSR=0x%x\n", csr);
#endif
        *pval = 0;
        return -1;
    }
    *pval = val;
    return 0;
}

#if FLEN > 0
static void set_frm(RISCVCPUState *s, unsigned int val)
{
    if (val >= 5)
        val = 0;
    s->frm = val;
}

/* return -1 if invalid roundind mode */
static int get_insn_rm(RISCVCPUState *s, unsigned int rm)
{
    if (rm == 7)
        return s->frm;
    if (rm >= 5)
        return -1;
    else
        return rm;
}
#endif

/* return -1 if invalid CSR, 0 if OK, 1 if the interpreter loop must be
   exited (e.g. XLEN was modified) */
static int csr_write(RISCVCPUState *s, uint32_t csr, target_ulong val)
{
    target_ulong mask;

#if defined(DUMP_CSR)
    printf("csr_write: csr=0x%03x val=0x", csr);
    print_target_ulong(val);
    printf("\n");
#endif
    switch(csr) {
#if FLEN > 0
    case 0x001: /* fflags */
        s->fflags = val & 0x1f;
        s->fs = 3;
        break;
    case 0x002: /* frm */
        set_frm(s, val & 7);
        s->fs = 3;
        break;
    case 0x003: /* fcsr */
        set_frm(s, (val >> 5) & 7);
        s->fflags = val & 0x1f;
        s->fs = 3;
        break;
#endif
    case 0x100: /* sstatus */
        set_mstatus(s, (s->mstatus & ~SSTATUS_MASK) | (val & SSTATUS_MASK));
        break;
    case 0x104: /* sie */
        mask = s->mideleg;
        s->mie = (s->mie & ~mask) | (val & mask);
        break;
    case 0x105:
        s->stvec = val & ~3;
        break;
    case 0x140:
        s->sscratch = val;
        break;
    case 0x141:
        s->sepc = val & ~1;
        break;
    case 0x142:
        s->scause = val;
        break;
    case 0x143:
        s->sbadaddr = val;
        break;
    case 0x144: /* sip */
        mask = s->mideleg;
        s->mip = (s->mip & ~mask) | (val & mask);
        break;
    case 0x180:
        /* no ASID */
        if (s->cur_xlen == 32) {
            s->sptbr = val & (((target_ulong)1 << 22) - 1);
        }
#if MAX_XLEN >= 64
        else {
            s->sptbr = val & (((target_ulong)1 << 38) - 1);
        }
#endif
        break;
        
    case 0x300:
        set_mstatus(s, val);
        break;
    case 0x301: /* misa */
#ifdef CONFIG_EXT_DYN_XLEN
        {
            int base, new_xlen;
            base = get_valid_base((val >> (s->cur_xlen - 2)) & 3);
            new_xlen  = 1 << (base + 4);
            if (s->cur_xlen != new_xlen) {
                s->cur_xlen = new_xlen;
                return 1;
            }
        }
#endif
        break;
    case 0x302:
        mask = (1 << (CAUSE_MACHINE_ECALL + 1)) - 1;
        s->medeleg = (s->medeleg & ~mask) | (val & mask);
        break;
    case 0x303:
        mask = MIP_SSIP | MIP_STIP | MIP_SEIP;
        s->mideleg = (s->mideleg & ~mask) | (val & mask);
        break;
    case 0x304:
        mask = MIP_MSIP | MIP_MTIP | MIP_SSIP | MIP_STIP | MIP_SEIP;
        s->mie = (s->mie & ~mask) | (val & mask);
        break;
    case 0x305:
        s->mtvec = val & ~3;
        break;
    case 0x340:
        s->mscratch = val;
        break;
    case 0x341:
        s->mepc = val & ~1;
        break;
    case 0x342:
        s->mcause = val;
        break;
    case 0x343:
        s->mbadaddr = val;
        break;
    case 0x344:
        mask = MIP_SSIP | MIP_STIP;
        s->mip = (s->mip & ~mask) | (val & mask);
        break;
    case 0x320:
    case 0x321:
        s->mcounteren[csr & 3] = val & 7; /* Note: RDTIME is handle in software */
        break;
    default:
#ifdef DUMP_INVALID_CSR
        printf("csr_write: invalid CSR=0x%x\n", csr);
#endif
        return -1;
    }
    return 0;
}

static void set_priv(RISCVCPUState *s, int priv)
{
    if (s->priv != priv) {
        tlb_flush_all(s);
        s->priv = priv;
    }
}

static void raise_exception2(RISCVCPUState *s, uint32_t cause,
                             target_ulong badaddr)
{
    BOOL has_badaddr, deleg;
    target_ulong causel;
    
    has_badaddr = (cause == CAUSE_MISALIGNED_FETCH ||
                   cause == CAUSE_FAULT_FETCH ||
                   cause == CAUSE_MISALIGNED_LOAD ||
                   cause == CAUSE_FAULT_LOAD ||
                   cause == CAUSE_MISALIGNED_STORE ||
                   cause == CAUSE_FAULT_STORE);
#if defined(DUMP_EXCEPTIONS) || defined(DUMP_MMU_EXCEPTIONS) || defined(DUMP_INTERRUPTS)
    {
        int flag;
        flag = 0;
#ifdef DUMP_MMU_EXCEPTIONS
        flag |= has_badaddr;
#endif
#ifdef DUMP_INTERRUPTS
        flag |= (cause & CAUSE_INTERRUPT) != 0;
#endif
#ifdef DUMP_EXCEPTIONS        
        flag = 1;
        flag = (cause & CAUSE_INTERRUPT) == 0;
#endif
        if (flag) {
            log_printf("raise_exception: cause=0x%08x", cause);
            if (has_badaddr) {
                log_printf(" badaddr=0x");
#ifdef CONFIG_LOGFILE
                fprint_target_ulong(log_file, badaddr);
#else
                print_target_ulong(badaddr);
#endif
            }
            log_printf("\n");
            //            dump_regs(s);
        }
    }
#endif

    if (s->priv <= PRV_S) {
        /* delegate the exception to the supervisor priviledge */
        if (cause & CAUSE_INTERRUPT)
            deleg = (s->mideleg >> (cause & (MAX_XLEN - 1))) & 1;
        else
            deleg = (s->medeleg >> cause) & 1;
    } else {
        deleg = 0;
    }
    
    causel = cause & 0x7fffffff;
    if (cause & CAUSE_INTERRUPT)
        causel |= (target_ulong)1 << (s->cur_xlen - 1);
    
    if (deleg) {
        s->scause = causel;
        s->sepc = s->pc;
        if (has_badaddr)
            s->sbadaddr = badaddr;
        s->mstatus = (s->mstatus & ~MSTATUS_SPIE) |
            (((s->mstatus >> s->priv) & 1) << MSTATUS_SPIE_SHIFT);
        s->mstatus = (s->mstatus & ~MSTATUS_SPP) |
            (s->priv << MSTATUS_SPP_SHIFT);
        s->mstatus &= ~MSTATUS_SIE;
#ifdef CONFIG_EXT_DYN_XLEN
        s->mstatus = (s->mstatus & ~MSTATUS_SPB) |
            ((uint64_t)get_base_from_xlen(s->cur_xlen) << MSTATUS_SPB_SHIFT);
        s->cur_xlen = 1 << 
            (4 + get_valid_base((s->mstatus >> MSTATUS_SB_SHIFT) & 3));
#endif
        set_priv(s, PRV_S);
        s->pc = s->stvec;
    } else {
        s->mcause = causel;
        s->mepc = s->pc;
        if (has_badaddr)
            s->mbadaddr = badaddr;
        s->mstatus = (s->mstatus & ~MSTATUS_MPIE) |
            (((s->mstatus >> s->priv) & 1) << MSTATUS_MPIE_SHIFT);
        s->mstatus = (s->mstatus & ~MSTATUS_MPP) |
            (s->priv << MSTATUS_MPP_SHIFT);
        s->mstatus &= ~MSTATUS_MIE;
#ifdef CONFIG_EXT_DYN_XLEN
        s->mstatus = (s->mstatus & ~MSTATUS_MPB) |
            ((uint64_t)get_base_from_xlen(s->cur_xlen) << MSTATUS_MPB_SHIFT);
        s->cur_xlen = 1 << 
            (4 + get_valid_base((s->mstatus >> MSTATUS_MB_SHIFT) & 3));
#endif
        set_priv(s, PRV_M);
        s->pc = s->mtvec;
    }
}

static void raise_exception(RISCVCPUState *s, uint32_t cause)
{
    raise_exception2(s, cause, 0);
}

static void handle_sret(RISCVCPUState *s)
{
    int spp, spie;
    spp = (s->mstatus >> MSTATUS_SPP_SHIFT) & 1;
    /* set the IE state to previous IE state */
    spie = (s->mstatus >> MSTATUS_SPIE_SHIFT) & 1;
    s->mstatus = (s->mstatus & ~(1 << spp)) |
        (spie << spp);
    /* set SPIE to 1 */
    s->mstatus |= MSTATUS_SPIE;
    /* set SPP to U */
    s->mstatus &= ~MSTATUS_SPP;
#ifdef CONFIG_EXT_DYN_XLEN
    {
        int spb;
        spb = get_valid_base((s->mstatus >> MSTATUS_SPB_SHIFT) & 3);
        s->cur_xlen = 1 << (4 + spb);
        s->mstatus &= ~MSTATUS_SPB;
    }
#endif
    set_priv(s, spp);
    s->pc = s->sepc;
}

static void handle_mret(RISCVCPUState *s)
{
    int mpp, mpie;
    mpp = (s->mstatus >> MSTATUS_MPP_SHIFT) & 3;
    /* set the IE state to previous IE state */
    mpie = (s->mstatus >> MSTATUS_MPIE_SHIFT) & 1;
    s->mstatus = (s->mstatus & ~(1 << mpp)) |
        (mpie << mpp);
    /* set MPIE to 1 */
    s->mstatus |= MSTATUS_MPIE;
    /* set MPP to U */
    s->mstatus &= ~MSTATUS_MPP;
#ifdef CONFIG_EXT_DYN_XLEN
    {
        int mpb;
        mpb = get_valid_base((s->mstatus >> MSTATUS_MPB_SHIFT) & 3);
        s->cur_xlen = 1 << (4 + mpb);
        s->mstatus &= ~MSTATUS_MPB;
    }
#endif
    set_priv(s, mpp);
    s->pc = s->mepc;
}

static uint32_t ctz32(uint32_t a)
{
    int i;
    if (a == 0)
        return 32;
    for(i = 0; i < 32; i++) {
        if ((a >> i) & 1)
            return i;
    }
    return 32;
}

static inline uint32_t get_pending_irq_mask(RISCVCPUState *s)
{
    uint32_t pending_ints, enabled_ints;

    pending_ints = s->mip & s->mie;
    if (pending_ints == 0)
        return 0;

    enabled_ints = 0;
    switch(s->priv) {
    case PRV_M:
        if (s->mstatus & MSTATUS_MIE)
            enabled_ints = ~s->mideleg;
        break;
    case PRV_S:
        enabled_ints = ~s->mideleg;
        if (s->mstatus & MSTATUS_SIE)
            enabled_ints |= s->mideleg;
        break;
    default:
    case PRV_U:
        enabled_ints = -1;
        break;
    }
    return pending_ints & enabled_ints;
}

static void raise_interrupt(RISCVCPUState *s)
{
    uint32_t mask;
    int irq_num;

    mask = get_pending_irq_mask(s);
    if (mask == 0)
        return;
    irq_num = ctz32(mask);
    raise_exception(s, irq_num | CAUSE_INTERRUPT);
}

static inline int32_t sext(int32_t val, int n)
{
    return (val << (32 - n)) >> (32 - n);
}

static inline uint32_t get_field1(uint32_t val, int src_pos, 
                                  int dst_pos, int dst_pos_max)
{
    int mask;
    assert(dst_pos_max >= dst_pos);
    mask = ((1 << (dst_pos_max - dst_pos + 1)) - 1) << dst_pos;
    if (dst_pos >= src_pos)
        return (val << (dst_pos - src_pos)) & mask;
    else
        return (val >> (src_pos - dst_pos)) & mask;
}

#define XLEN 32
#include "riscvemu_template.h"

#if MAX_XLEN >= 64
#define XLEN 64
#include "riscvemu_template.h"
#endif

#if MAX_XLEN >= 128
#define XLEN 128
#include "riscvemu_template.h"
#endif

static void no_inline riscv_cpu_interp(RISCVCPUState *s,
                                       int n_cycles)
{
    uint64_t timeout;

    timeout = s->insn_counter + n_cycles;
    while (!s->power_down_flag &&
           (int)(timeout - s->insn_counter) > 0) {
        n_cycles = timeout - s->insn_counter;
        switch(s->cur_xlen) {
        case 32:
            riscv_cpu_interp32(s, n_cycles);
            break;
#if MAX_XLEN >= 64
        case 64:
            riscv_cpu_interp64(s, n_cycles);
            break;
#endif
#if MAX_XLEN >= 128
        case 128:
            riscv_cpu_interp128(s, n_cycles);
            break;
#endif
        default:
            abort();
        }
    }
}

RISCVCPUState *riscv_cpu_init(RISCVMachine *machine_state,
                              unsigned int ram_size)
{
    RISCVCPUState *s;
    uint32_t low_ram_size;
    
    if (ram_size == 0 ||
        (ram_size & PG_MASK) != 0)
        return NULL;
    s = mallocz(sizeof(*s));
    s->machine_state = machine_state;
    
    s->phys_mem_size = 0;
    cpu_register_ram(s, RAM_BASE_ADDR, ram_size, s->phys_mem_size);
    s->phys_mem_size += ram_size;
    low_ram_size = 0x100000; /* 1MB should be enough */
    cpu_register_ram(s, 0x00000000, low_ram_size, s->phys_mem_size);
    s->phys_mem_size += low_ram_size;

    s->phys_mem = mallocz(s->phys_mem_size);
    s->pc = 0x1000;
    s->priv = PRV_M;
    s->cur_xlen = MAX_XLEN;
    s->misa |= MCPUID_SUPER | MCPUID_USER | MCPUID_I | MCPUID_M | MCPUID_A;
#if FLEN >= 32
    s->misa |= MCPUID_F;
#endif
#if FLEN >= 64
    s->misa |= MCPUID_D;
#endif
#if FLEN >= 128
    s->misa |= MCPUID_Q;
#endif
#ifdef CONFIG_EXT_C
    s->misa |= MCPUID_C;
#endif
    tlb_init(s);
    return s;
}

void riscv_cpu_end(RISCVCPUState *s)
{
    free(s->phys_mem);
    free(s);
}

/* RISCV machine */

struct RISCVMachine {
    RISCVCPUState *cpu_state;
    /* RTC */
    BOOL rtc_real_time;
    uint64_t rtc_start_time;
    /* PLIC */
    uint32_t plic_pending_irq, plic_served_irq;
    /* HTIF */
    uint64_t htif_tohost, htif_fromhost;
    /* network */
    VIRTIODevice *net_dev;
    EthernetDevice *net;
    /* console */
    CharacterDevice *console;
    VIRTIODevice *console_dev;
};

#define RTC_FREQ 10000000
#define RTC_FREQ_DIV 16 /* arbitrary, relative to CPU freq to have a
                           10 MHz frequency */

static uint64_t rtc_get_real_time(RISCVMachine *s)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * RTC_FREQ +
        (ts.tv_nsec / (1000000000 / RTC_FREQ));
}

static uint64_t rtc_get_time(RISCVCPUState *s)
{
    RISCVMachine *m = s->machine_state;
    uint64_t val;
    if (m->rtc_real_time) {
        val = rtc_get_real_time(m) - m->rtc_start_time;
    } else {
        val = s->insn_counter / RTC_FREQ_DIV;
    }
    //    printf("rtc_time=%" PRId64 "\n", val);
    return val;
}

static target_ulong htif_read(void *opaque, target_ulong offset,
                              int size_log2)
{
    RISCVMachine *s = opaque;
    uint32_t val;

    assert(size_log2 == 2);
    switch(offset) {
    case 0:
        val = s->htif_tohost;
        break;
    case 4:
        val = s->htif_tohost >> 32;
        break;
    case 8:
        val = s->htif_fromhost;
        break;
    case 12:
        val = s->htif_fromhost >> 32;
        break;
    default:
        val = 0;
        break;
    }
    return val;
}

static void htif_handle_cmd(RISCVMachine *s)
{
    uint32_t device, cmd;

    device = s->htif_tohost >> 56;
    cmd = (s->htif_tohost >> 48) & 0xff;
    if (s->htif_tohost == 1) {
        /* shuthost */
        printf("\nPower off.\n");
        exit(0);
    } else if (device == 1 && cmd == 1) {
        uint8_t buf[1];
        buf[0] = s->htif_tohost & 0xff;
        s->console->write_data(s->console->opaque, buf, 1);
        s->htif_tohost = 0;
        s->htif_fromhost = ((uint64_t)device << 56) | ((uint64_t)cmd << 48);
    } else if (device == 1 && cmd == 0) {
        /* request keyboard interrupt */
        s->htif_tohost = 0;
    } else {
        printf("HTIF: unsupported tohost=0x%016" PRIx64 "\n", s->htif_tohost);
    }
}

static void htif_write(void *opaque, target_ulong offset, target_ulong val,
                       int size_log2)
{
    RISCVMachine *s = opaque;

    assert(size_log2 == 2);
    switch(offset) {
    case 0:
        s->htif_tohost = (s->htif_tohost & ~0xffffffff) | val;
        break;
    case 4:
        s->htif_tohost = (s->htif_tohost & 0xffffffff) | ((uint64_t)val << 32);
        htif_handle_cmd(s);
        break;
    case 8:
        s->htif_fromhost = (s->htif_fromhost & ~0xffffffff) | val;
        break;
    case 12:
        s->htif_fromhost = (s->htif_fromhost & 0xffffffff) |
            (uint64_t)val << 32;
        break;
    default:
        break;
    }
}

#if 0
static void htif_poll(RISCVMachine *s)
{
    uint8_t buf[1];
    int ret;

    if (s->htif_fromhost == 0) {
        ret = s->console->read_data(s->console->opaque, buf, 1);
        if (ret == 1) {
            s->htif_fromhost = ((uint64_t)1 << 56) | ((uint64_t)0 << 48) |
                buf[0];
        }
    }
}
#endif

static target_ulong rtc_read(void *opaque, target_ulong offset, int size_log2)
{
    RISCVCPUState *s = opaque;
    uint32_t val;

    assert(size_log2 == 2);
    switch(offset) {
    case 0:
        val = rtc_get_time(s);
        break;
    case 4:
        val = rtc_get_time(s) >> 32;
        break;
    case 8:
        val = s->timecmp;
        break;
    case 12:
        val = s->timecmp >> 32;
        break;
    default:
        val = 0;
        break;
    }
    return val;
}
 
static void rtc_write(void *opaque, target_ulong offset, target_ulong val,
                      int size_log2)
{
    RISCVCPUState *s = opaque;

    assert(size_log2 == 2);
    switch(offset) {
    case 8:
        s->timecmp = (s->timecmp & ~0xffffffff) | val;
        s->mip &= ~MIP_MTIP;
        break;
    case 12:
        s->timecmp = (s->timecmp & 0xffffffff) | ((uint64_t)val << 32);
        s->mip &= ~MIP_MTIP;
        break;
    default:
        break;
    }
}

static void plic_update_mip(RISCVMachine *s)
{
    RISCVCPUState *cpu = s->cpu_state;
    uint32_t mask;
    mask = s->plic_pending_irq & ~s->plic_served_irq;
    if (mask)
        cpu->mip |= MIP_MEIP | MIP_SEIP;
    else
        cpu->mip &= ~(MIP_MEIP | MIP_SEIP);
    /* exit from power down if an interrupt is pending */
    if (cpu->power_down_flag && (cpu->mip & cpu->mie) != 0)
        cpu->power_down_flag = FALSE;
}

static target_ulong plic_read(void *opaque, target_ulong offset, int size_log2)
{
    RISCVMachine *s = opaque;
    uint32_t val, mask;
    int i;
    assert(size_log2 == 2);
    switch(offset) {
    case 0:
        val = 0;
        break;
    case 4:
        mask = s->plic_pending_irq & ~s->plic_served_irq;
        if (mask != 0) {
            i = ctz32(mask);
            s->plic_served_irq |= 1 << i;
            plic_update_mip(s);
            val = i + 1;
        } else {
            val = 0;
        }
        break;
    default:
        val = 0;
        break;
    }
    return val;
}

static void plic_write(void *opaque, target_ulong offset, target_ulong val,
                       int size_log2)
{
    RISCVMachine *s = opaque;
    
    assert(size_log2 == 2);
    switch(offset) {
    case 4:
        val--;
        if (val < 32) {
            s->plic_served_irq &= ~(1 << val);
            plic_update_mip(s);
        }
        break;
    default:
        break;
    }
}

static void plic_set_irq(RISCVMachine *s, int irq_num, int state)
{
    uint32_t mask;

    mask = 1 << irq_num;
    if (state) 
        s->plic_pending_irq |= mask;
    else
        s->plic_pending_irq &= ~mask;
    plic_update_mip(s);
}


static void setup_linux_config(RISCVCPUState *s, target_ulong ram_size)
{
    char buf[1024];
    uint32_t config_addr;
    int len, i;
    
    snprintf(buf, sizeof(buf),
             "platform {\n"
             "  vendor ucb;\n"
             "  arch spike;\n"
             "};\n"
             "rtc {\n"
             "  addr 0x%" PRIx64 ";\n"
             "};\n"
             "ram {\n"
             "  0 {\n"
             "    addr 0x%" PRIx64 ";\n"
             "    size 0x%" PRIx64 ";\n"
             "  };\n"
             "};\n"
             "core {\n"
             "  0" " {\n"
             "    " "0 {\n"
             "      isa " "rv64imafd" ";\n"
             "      timecmp 0x%" PRIx64 ";\n"
             "      ipi 0x" "40001000" ";\n"
             "    };\n"
             "  };\n"
             "};\n",
             (uint64_t)RTC_BASE_ADDR,
             (uint64_t)RAM_BASE_ADDR,
             (uint64_t)ram_size,
             (uint64_t)RTC_BASE_ADDR + 8);
    
    config_addr = 0x1000 + 8 * 4;
    /* jump to 0x80000000 */
    phys_write_u32(s, 0x1000, 0x297 + 0x80000000 - 0x1000);
    phys_write_u32(s, 0x1004, 0x00028067);
    phys_write_u32(s, 0x100c, config_addr);

    len = strlen(buf);
    for(i = 0; i < len; i++)
        phys_write_u8(s, config_addr + i, buf[i]);
}

static uint8_t *virtio_get_ram_ptr(void *opaque, virtio_phys_addr_t paddr)
{
    RISCVMachine *m = opaque;
    RISCVCPUState *s = m->cpu_state;
    PhysMemoryRange *pr = get_phys_mem_range(s, paddr);
    if (!pr)
        return NULL;
    return s->phys_mem + pr->phys_mem_offset + (uintptr_t)(paddr - pr->addr);
}

static void virtio_set_irq(void *opaque, int irq_num, int state)
{
    RISCVMachine *s = opaque;
    plic_set_irq(s, irq_num, state);
}

static target_ulong virtio_read(void *opaque, target_ulong offset,
                                int size_log2)
{
    VIRTIODevice *s = opaque;
    //    printf("read offset=0x%x\n", (int)offset);
    return virtio_mmio_read(s, offset, size_log2);
}
 
static void virtio_write(void *opaque, target_ulong offset, target_ulong val,
                      int size_log2)
{
    VIRTIODevice *s = opaque;
    //    printf("write offset=0x%x\n", (int)offset);
    virtio_mmio_write(s, offset, val, size_log2);
}

RISCVMachine *riscv_machine_init(uint64_t ram_size,
                                 BOOL rtc_real_time,
                                 CharacterDevice *console_dev,
                                 BlockDevice **tab_drive, int drive_count,
                                 EthernetDevice *net,
                                 FSDevice **tab_fs, int fs_count)
{
    RISCVMachine *s;
    VIRTIODevice *blk_dev, *net_dev;
    int irq_num, i;
    uint32_t virtio_addr;
        
    s = mallocz(sizeof(*s));

    s->cpu_state = riscv_cpu_init(s, ram_size);
    s->rtc_real_time = rtc_real_time;
    if (rtc_real_time) {
        s->rtc_start_time = rtc_get_real_time(s);
    }
    cpu_register_device(s->cpu_state, RTC_BASE_ADDR, 16, s->cpu_state,
                        rtc_read, rtc_write, DEVIO_SIZE32);
    cpu_register_device(s->cpu_state, PLIC_BASE_ADDR, 8, s,
                        plic_read, plic_write, DEVIO_SIZE32);
    cpu_register_device(s->cpu_state, HTIF_BASE_ADDR, 16,
                        s, htif_read, htif_write, DEVIO_SIZE32);
    s->console = console_dev;

    virtio_addr = 0x40010000;
    irq_num = 1;
    
    /* virtio console */
    s->console_dev = virtio_console_init(virtio_set_irq, irq_num, 
                                         virtio_get_ram_ptr, s,
                                         console_dev);
    cpu_register_device(s->cpu_state, virtio_addr, 0x1000,
                        s->console_dev, virtio_read, virtio_write,
                        DEVIO_SIZE8 | DEVIO_SIZE16 | DEVIO_SIZE32);
    virtio_addr += 0x1000;
    irq_num++;

    /* virtio net device */
    if (net) {
        net_dev = virtio_net_init(virtio_set_irq, irq_num,
                                  virtio_get_ram_ptr, s, net);
        cpu_register_device(s->cpu_state, virtio_addr, 0x1000,
                            net_dev, virtio_read, virtio_write,
                            DEVIO_SIZE8 | DEVIO_SIZE16 | DEVIO_SIZE32);
        s->net_dev = net_dev;
        s->net = net;
        virtio_addr += 0x1000;
        irq_num++;
    }

    /* virtio block device */
    for(i = 0; i < drive_count; i++) {
        blk_dev = virtio_block_init(virtio_set_irq, irq_num,
                                    virtio_get_ram_ptr, s, tab_drive[i]);
        cpu_register_device(s->cpu_state, virtio_addr, 0x1000,
                            blk_dev, virtio_read, virtio_write,
                            DEVIO_SIZE8 | DEVIO_SIZE16 | DEVIO_SIZE32);
        virtio_addr += 0x1000;
        irq_num++;
    }

    /* virtio filesystem */
    for(i = 0; i < fs_count; i++) {
        VIRTIODevice *fs_dev;
        char buf[64];

        if (i == 0)
            strcpy(buf, "/dev/root");
        else
            snprintf(buf, sizeof(buf), "/dev/root%d", i);
        fs_dev = virtio_9p_init(virtio_set_irq, irq_num, virtio_get_ram_ptr, s,
                                tab_fs[i], buf);
        cpu_register_device(s->cpu_state, virtio_addr, 0x1000,
                            fs_dev, virtio_read, virtio_write,
                            DEVIO_SIZE8 | DEVIO_SIZE16 | DEVIO_SIZE32);
        //        virtio_set_debug(fs_dev, VIRTIO_DEBUG_9P);
        virtio_addr += 0x1000;
        irq_num++;
    }

    return s;
}

void riscv_machine_end(RISCVMachine *s)
{
    /* XXX: stop all */
    riscv_cpu_end(s->cpu_state);
}

#ifdef EMSCRIPTEN

void riscv_machine_run(void *opaque);

static uint8_t console_fifo[64];
static int console_fifo_windex;
static int console_fifo_rindex;
static int console_fifo_count;

static void console_write(void *opaque, const uint8_t *buf, int len)
{
    int val, i;

    for(i = 0; i < len; i++) {
        val = buf[i];
        EM_ASM_({
                term.write(String.fromCharCode($0));
            }, val);
    }
}

static int console_read(void *opaque, uint8_t *buf, int len)
{
    if (console_fifo_count == 0)
        return 0;
    buf[0] = console_fifo[console_fifo_rindex];
    if (++console_fifo_rindex == sizeof(console_fifo))
        console_fifo_rindex = 0;
    console_fifo_count--;
    return 1;
}

void console_queue_char(int c)
{
    if (console_fifo_count < sizeof(console_fifo)) {
        console_fifo[console_fifo_windex] = c;
        if (++console_fifo_windex == sizeof(console_fifo))
            console_fifo_windex = 0;
        console_fifo_count++;
    }
}

CharacterDevice *console_init(void)
{
    CharacterDevice *dev;
    dev = mallocz(sizeof(*dev));
    dev->write_data = console_write;
    dev->read_data = console_read;
    return dev;
}

#define ROOT_URL "riscv-poky"

static void init_vm(void *arg);

static FSDevice *global_fs;

int main(int argc, char **argv)
{
    EM_ASM({
            var term_rx_fifo = "";
            console_write1 = cwrap('console_queue_char', null, ['number']);
            function term_handler(str)
            {
                var i;
                for(i = 0; i < str.length; i++) {
                    console_write1(str.charCodeAt(i));
                }
            }
            
            term = new Term(80, 30, term_handler);
            term.open();
            term.write("Loading image...\r\n");
        });

    global_fs = fs_net_init(ROOT_URL, init_vm, NULL);
    return 0;
}

static void init_vm(void *arg)
{
    RISCVMachine *s;
    BOOL rtc_real_time;
    CharacterDevice *console;
    uint8_t *kernel_buf;
    int kernel_size;
    uint32_t ram_size;
    
    console = console_init();
    
    rtc_real_time = TRUE;
    ram_size = DEFAULT_RAM_SIZE << 20;
    s = riscv_machine_init(ram_size, rtc_real_time, console, NULL, 0, NULL,
                           &global_fs, 1);

    /* load the kernel to memory */
    kernel_size = fs_net_get_kernel(global_fs, &kernel_buf);
    assert(kernel_size > 0 && kernel_size < ram_size);
    memcpy(s->cpu_state->phys_mem, kernel_buf, kernel_size);
    fs_net_free_kernel(global_fs);

    setup_linux_config(s->cpu_state, ram_size);

    emscripten_async_call(riscv_machine_run, s, 0);
}

#define MAX_EXEC_CYCLE 1000000

void riscv_machine_run(void *opaque)
{
    RISCVMachine *m = opaque;
    RISCVCPUState *s = m->cpu_state;
    int delay1;

    /* wait for an event: the only asynchronous event is the RTC timer */
    if (!(s->mip & MIP_MTIP)) {
        delay1 = s->timecmp - rtc_get_time(s);
        if (delay1 <= 0) {
            s->mip |= MIP_MTIP;
            s->power_down_flag = FALSE;
        }
    }

    if (virtio_console_can_write_data(m->console_dev)) {
        uint8_t buf[128];
        int ret, len;
        len = virtio_console_get_write_len(m->console_dev);
        len = min_int(len, sizeof(buf));
        ret = m->console->read_data(m->console->opaque, buf, len);
        if (ret > 0)
            virtio_console_write_data(m->console_dev, buf, ret);
    }

    if (!s->power_down_flag) {
        riscv_cpu_interp(s, MAX_EXEC_CYCLE);
        emscripten_async_call(riscv_machine_run, m, 0);
    } else {
        if (!m->rtc_real_time)
            s->insn_counter += MAX_EXEC_CYCLE;
        emscripten_async_call(riscv_machine_run, m, 10);
    }
}

#else

static struct termios oldtty;
static int old_fd0_flags;

static void term_exit(void)
{
    tcsetattr (0, TCSANOW, &oldtty);
    fcntl(0, F_SETFL, old_fd0_flags);
}

static void term_init(BOOL allow_ctrlc)
{
    struct termios tty;

    memset(&tty, 0, sizeof(tty));
    tcgetattr (0, &tty);
    oldtty = tty;
    old_fd0_flags = fcntl(0, F_GETFL);

    tty.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP
                          |INLCR|IGNCR|ICRNL|IXON);
    tty.c_oflag |= OPOST;
    tty.c_lflag &= ~(ECHO|ECHONL|ICANON|IEXTEN);
    if (!allow_ctrlc)
        tty.c_lflag &= ~ISIG;
    tty.c_cflag &= ~(CSIZE|PARENB);
    tty.c_cflag |= CS8;
    tty.c_cc[VMIN] = 1;
    tty.c_cc[VTIME] = 0;

    tcsetattr (0, TCSANOW, &tty);

    atexit(term_exit);

    fcntl(0, F_SETFL, O_NONBLOCK);
}

static void console_write(void *opaque, const uint8_t *buf, int len)
{
    fwrite(buf, 1, len, stdout);
    fflush(stdout);
}

int console_esc_state;

static int console_read(void *opaque, uint8_t *buf, int len)
{
    int ret, i, j;
    uint8_t ch;
    
    if (len <= 0)
        return 0;

    ret = read(0, buf, len);
    if (ret < 0)
        return 0;
    if (ret == 0) {
        /* EOF */
        exit(1);
    }

    j = 0;
    for(i = 0; i < ret; i++) {
        ch = buf[i];
        if (console_esc_state) {
            console_esc_state = 0;
            switch(ch) {
            case 'x':
                printf("Terminated\n");
                exit(0);
            case 'h':
                printf("\n"
                       "C-a h   print this help\n"
                       "C-a x   exit emulator\n"
                       "C-a C-a send C-a\n");
                break;
            case 1:
                goto output_char;
            default:
                break;
            }
        } else {
            if (ch == 1) {
                console_esc_state = 1;
            } else {
            output_char:
                buf[j++] = ch;
            }
        }
    }
    return j;
}

CharacterDevice *console_init(BOOL allow_ctrlc)
{
    CharacterDevice *dev;
    term_init(allow_ctrlc);
    dev = mallocz(sizeof(*dev));
    dev->write_data = console_write;
    dev->read_data = console_read;
    return dev;
}

static void load_image(RISCVCPUState *s, const char *filename)
{
    FILE *f;
    int size;
    
    f = fopen(filename, "rb");
    if (!f) {
        perror(filename);
        exit(1);
    }
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size > s->phys_mem_size) {
        fprintf(stderr, "%s: image too big\n", filename);
        exit(1);
    }
    if (fread(s->phys_mem, 1, size, f) != size) {
        fprintf(stderr, "%s: read error\n", filename);
        exit(1);
    }
    fclose(f);
}

typedef enum {
    BF_MODE_RO,
    BF_MODE_RW,
    BF_MODE_SNAPSHOT,
} BlockDeviceModeEnum;

#define SECTOR_SIZE 512

typedef struct BlockDeviceFile {
    FILE *f;
    int64_t nb_sectors;
    BlockDeviceModeEnum mode;
    uint8_t **sector_table;
} BlockDeviceFile;

static int64_t bf_get_sector_count(BlockDevice *bs)
{
    BlockDeviceFile *bf = bs->opaque;
    return bf->nb_sectors;
}

static int bf_read_async(BlockDevice *bs,
                         uint64_t sector_num, uint8_t *buf, int n,
                         BlockDeviceCompletionFunc *cb, void *opaque)
{
    BlockDeviceFile *bf = bs->opaque;
    //    printf("bf_read_async: sector_num=%" PRId64 " n=%d\n", sector_num, n);
    if (!bf->f)
        return -1;
    if (bf->mode == BF_MODE_SNAPSHOT) {
        int i;
        for(i = 0; i < n; i++) {
            if (!bf->sector_table[sector_num]) {
                fseek(bf->f, sector_num * SECTOR_SIZE, SEEK_SET);
                fread(buf, 1, SECTOR_SIZE, bf->f);
            } else {
                memcpy(buf, bf->sector_table[sector_num], SECTOR_SIZE);
            }
            sector_num++;
            buf += SECTOR_SIZE;
        }
    } else {
        fseek(bf->f, sector_num * SECTOR_SIZE, SEEK_SET);
        fread(buf, 1, n * SECTOR_SIZE, bf->f);
    }
    /* synchronous read */
    return 0;
}

static int bf_write_async(BlockDevice *bs,
                          uint64_t sector_num, const uint8_t *buf, int n,
                          BlockDeviceCompletionFunc *cb, void *opaque)
{
    BlockDeviceFile *bf = bs->opaque;
    int ret;

    switch(bf->mode) {
    case BF_MODE_RO:
        ret = -1; /* error */
        break;
    case BF_MODE_RW:
        fseek(bf->f, sector_num * SECTOR_SIZE, SEEK_SET);
        fwrite(buf, 1, n * SECTOR_SIZE, bf->f);
        ret = 0;
        break;
    case BF_MODE_SNAPSHOT:
        {
            int i;
            if ((sector_num + n) > bf->nb_sectors)
                return -1;
            for(i = 0; i < n; i++) {
                if (!bf->sector_table[sector_num]) {
                    bf->sector_table[sector_num] = malloc(SECTOR_SIZE);
                }
                memcpy(bf->sector_table[sector_num], buf, SECTOR_SIZE);
                sector_num++;
                buf += SECTOR_SIZE;
            }
            ret = 0;
        }
        break;
    default:
        abort();
    }

    return ret;
}

static BlockDevice *block_device_init(const char *filename,
                                      BlockDeviceModeEnum mode)
{
    BlockDevice *bs;
    BlockDeviceFile *bf;
    int64_t file_size;
    FILE *f;
    const char *mode_str;

    if (mode == BF_MODE_RW) {
        mode_str = "r+b";
    } else {
        mode_str = "rb";
    }
    
    f = fopen(filename, mode_str);
    if (!f) {
        perror(filename);
        exit(1);
    }
    fseek(f, 0, SEEK_END);
    file_size = ftello(f);

    bs = mallocz(sizeof(*bs));
    bf = mallocz(sizeof(*bf));

    bf->mode = mode;
    bf->nb_sectors = file_size / 512;
    bf->f = f;

    if (mode == BF_MODE_SNAPSHOT) {
        bf->sector_table = mallocz(sizeof(bf->sector_table[0]) *
                                   bf->nb_sectors);
    }
    
    bs->opaque = bf;
    bs->get_sector_count = bf_get_sector_count;
    bs->read_async = bf_read_async;
    bs->write_async = bf_write_async;
    return bs;
}

#define MAX_EXEC_CYCLE 500000
#define MAX_SLEEP_TIME (RTC_FREQ / 100) /* period of 1/RTC_FREQ seconds */

void riscv_machine_run(RISCVMachine *m)
{
    RISCVCPUState *s = m->cpu_state;
    int64_t delay1;
    fd_set rfds, wfds, efds;
    int fd_max, ret, delay, net_fd;
    struct timeval tv;
    
    /* wait for an event: the only asynchronous event is the RTC timer */
    if (s->power_down_flag) {
        delay = MAX_SLEEP_TIME;
    } else {
        delay = 0;
    }
    if (!(s->mip & MIP_MTIP)) {
        delay1 = s->timecmp - rtc_get_time(s);
        if (delay1 <= 0) {
            s->mip |= MIP_MTIP;
            s->power_down_flag = FALSE;
            delay = 0;
        } else {
            if (delay1 < delay)
                delay = delay1;
        }
    }
    /* wait for an event */
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&efds);
    fd_max = -1;
    if (virtio_console_can_write_data(m->console_dev)) {
        FD_SET(0, &rfds);
        fd_max = 0;
    }
    if (m->net_dev && virtio_net_can_write_packet(m->net_dev)) {
        net_fd = (intptr_t)m->net->opaque;
        FD_SET(net_fd, &rfds);
        fd_max = max_int(fd_max, net_fd);
    } else {
        net_fd = -1;
    }
#ifdef CONFIG_FS_NET
    fs_net_set_fdset(&fd_max, &rfds, &wfds, &efds, &delay);
#endif
    tv.tv_sec = 0;
    tv.tv_usec = delay / (RTC_FREQ / 1000000);
    ret = select(fd_max + 1, &rfds, &wfds, &efds, &tv);
    if (ret > 0) {
        if (FD_ISSET(0, &rfds)) {
            uint8_t buf[128];
            int ret, len;
            len = virtio_console_get_write_len(m->console_dev);
            len = min_int(len, sizeof(buf));
            ret = m->console->read_data(m->console->opaque, buf, len);
            if (ret > 0)
                virtio_console_write_data(m->console_dev, buf, ret);
        }
        if (net_fd >= 0 && FD_ISSET(net_fd, &rfds)) {
            uint8_t buf[2048];
            int ret;
            ret = read(net_fd, buf, sizeof(buf));
            if (ret > 0)
                virtio_net_write_packet(m->net_dev, buf, ret);
        }
    }

    if (!s->power_down_flag) {
        riscv_cpu_interp(s, MAX_EXEC_CYCLE);
    }
}

void pstrcpy(char *buf, int buf_size, const char *str)
{
    int c;
    char *q = buf;

    if (buf_size <= 0)
        return;

    for(;;) {
        c = *str++;
        if (c == 0 || q >= buf + buf_size - 1)
            break;
        *q++ = c;
    }
    *q = '\0';
}

int strstart(const char *str, const char *val, const char **ptr)
{
    const char *p, *q;
    p = str;
    q = val;
    while (*q != '\0') {
        if (*p != *q)
            return 0;
        p++;
        q++;
    }
    if (ptr)
        *ptr = p;
    return 1;
}

static void tun_write_packet(EthernetDevice *bs,
                             const uint8_t *buf, int len)
{
    int fd = (intptr_t)(bs->opaque);
    write(fd, buf, len);
}

/* configure with:
# bridge configuration (connect tap0 to bridge interface br0)
   ip link add br0 type bridge
   ip tuntap add dev tap0 mode tap [user x] [group x]
   ip link set tap0 master br0
   ip link set dev br0 up
   ip link set dev tap0 up

# NAT configuration (eth1 is the interface connected to internet)
   ifconfig br0 192.168.3.1
   echo 1 > /proc/sys/net/ipv4/ip_forward
   iptables -D FORWARD 1
   iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE

   In the VM:
   ifconfig eth0 192.168.3.2
   route add -net 0.0.0.0 netmask 0.0.0.0 gw 192.168.3.1
*/
static EthernetDevice *tun_open(const char *ifname)
{
    struct ifreq ifr;
    int fd, ret;
    EthernetDevice *net;

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Error: could not open /dev/net/tun\n");
        return NULL;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    pstrcpy(ifr.ifr_name, sizeof(ifr.ifr_name), ifname);
    ret = ioctl(fd, TUNSETIFF, (void *) &ifr);
    if (ret != 0) {
        fprintf(stderr, "Error: could not configure /dev/net/tun\n");
        close(fd);
        return NULL;
    }
    fcntl(fd, F_SETFL, O_NONBLOCK);

    net = mallocz(sizeof(*net));
    net->opaque = (void *)(intptr_t)fd;
    net->write_packet = tun_write_packet;
    return net;
}

static struct option options[] = {
    { "help", no_argument, NULL, 'h' },
    { "ctrlc", no_argument },
    { "rw", no_argument },
    { "ro", no_argument },
    { "net", required_argument },
    { NULL },
};

void help(void)
{
    printf("riscvemu version " CONFIG_VERSION ", Copyright (c) 2016-2017 Fabrice Bellard\n"
           "usage: riscvemu [options] [kernel.bin|url] [hdimage.bin|filesystem_path]...\n"
           "options are:\n"
           "-b [32|64|128]    set the integer register width in bits\n"
           "-m ram_size       set the RAM size in MB (default=%d)\n"
           "-rw               allow write access to the disk image (default=snapshot)\n"
           "-ctrlc            the C-c key stops the emulator instead of being sent to the\n"
           "                  emulated software\n"
           "-net ifname       set virtio network tap device\n"
           "\n"
           "Console keys:\n"
           "Press C-a x to exit the emulator, C-a h to get some help.\n",
           DEFAULT_RAM_SIZE);
    exit(1);
}

void launch_alternate_executable(char **argv, int xlen)
{
    char filename[1024];
    char new_exename[64];
    const char *p, *exename;
    int len;

    snprintf(new_exename, sizeof(new_exename), "riscvemu%d", xlen);
    exename = argv[0];
    p = strrchr(exename, '/');
    if (p) {
        len = p - exename + 1;
    } else {
        len = 0;
    }
    if (len + strlen(new_exename) > sizeof(filename) - 1) {
        fprintf(stderr, "%s: filename too long\n", exename);
        exit(1);
    }
    memcpy(filename, exename, len);
    filename[len] = '\0';
    strcat(filename, new_exename);
    argv[0] = filename;

    if (execvp(argv[0], argv) < 0) {
        perror(argv[0]);
        exit(1);
    }
}

#define MAX_DEVICE 4

int main(int argc, char **argv)
{
    RISCVMachine *s;
    uint64_t ram_size;
    BOOL rtc_real_time;
    CharacterDevice *console;
    const char *kernel_filename, *netif_name, *path;
    int c, option_index;
    BOOL allow_ctrlc;
    BlockDeviceModeEnum drive_mode;
    EthernetDevice *net;
    BlockDevice *drive, *tab_drive[MAX_DEVICE];
    int drive_count;
    FSDevice *fs, *tab_fs[MAX_DEVICE];
    int fs_count;
    BOOL has_kernel;
    
    ram_size = (uint64_t)DEFAULT_RAM_SIZE << 20;
    allow_ctrlc = FALSE;
    drive_mode = BF_MODE_SNAPSHOT;
    netif_name = NULL;
    for(;;) {
        c = getopt_long_only(argc, argv, "hb:m:", options, &option_index);
        if (c == -1)
            break;
        switch(c) {
        case 0:
            switch(option_index) {
            case 1: /* ctrlc */
                allow_ctrlc = TRUE;
                break;
            case 2: /* rw */
                drive_mode = BF_MODE_RW;
                break;
            case 3: /* ro */
                drive_mode = BF_MODE_RO;
                break;
            case 4: /* net */
                netif_name = optarg;
                break;
            default:
                fprintf(stderr, "unknown option index: %d\n", option_index);
                exit(1);
            }
            break;
        case 'h':
            help();
            break;
        case 'b':
            {
                int xlen;
                xlen = atoi(optarg);
                if (xlen != 32 && xlen != 64 && xlen != 128) {
                    fprintf(stderr, "Invalid integer register width\n");
                    exit(1);
                }
                if (xlen != MAX_XLEN) {
                    launch_alternate_executable(argv, xlen);
                }
            }
            break;
        case 'm':
            ram_size = (uint64_t)strtoul(optarg, NULL, 0) << 20;
            break;
        default:
            exit(1);
        }
    }

    if (optind >= argc) {
        help();
    }

    drive_count = 0;
    fs_count = 0;
    has_kernel = FALSE;
    kernel_filename = NULL;
    while (optind < argc) {
        path = argv[optind++];
#ifdef CONFIG_FS_NET
        if (strstart(path, "http:", NULL) ||
            strstart(path, "https:", NULL)) {
            uint8_t *kernel_buf;
            
            if (fs_count >= MAX_DEVICE) {
                fprintf(stderr, "too many filesystems\n");
                exit(1);
            }
            fs = fs_net_init(path, NULL, NULL);
            if (!fs)
                exit(1);
            fs_net_event_loop();
            if (fs_count == 0 && fs_net_get_kernel(fs, &kernel_buf) > 0)
                has_kernel = TRUE;
            tab_fs[fs_count++] = fs;
        } else
#endif
       {
            struct stat st;

            if (stat(path, &st) < 0) {
                perror(path);
                exit(1);
            }
            if (!has_kernel) {
                /* first file is the kernel filename */
                kernel_filename = path;
                has_kernel = TRUE;
            } else if (S_ISDIR(st.st_mode)) {
                /* directory: use a filesystem */
                fs = fs_init(path);
                if (!fs) {
                    fprintf(stderr, "%s: must be a directory\n", path);
                    exit(1);
                }
                tab_fs[fs_count++] = fs;
            } else {
                drive = block_device_init(path, drive_mode);
                tab_drive[drive_count++] = drive;
            }
        }
    }
    
    net = NULL;
    if (netif_name) {
        net = tun_open(netif_name);
        if (!net)
            exit(1);
    }

    console = console_init(allow_ctrlc);
    rtc_real_time = TRUE;
    s = riscv_machine_init(ram_size, rtc_real_time, console,
                           tab_drive, drive_count, net,
                           tab_fs, fs_count);

    if (has_kernel) {
#ifdef CONFIG_FS_NET
        if (!kernel_filename) {
            uint8_t *kernel_buf;
            int kernel_size;
            kernel_size = fs_net_get_kernel(tab_fs[0], &kernel_buf);
            if (kernel_size <= 0 || kernel_size > s->cpu_state->phys_mem_size)
                goto no_kernel_error;
            memcpy(s->cpu_state->phys_mem, kernel_buf, kernel_size);
            fs_net_free_kernel(tab_fs[0]);
        } else
#endif
        {
            load_image(s->cpu_state, kernel_filename);
        }
    } else {
    no_kernel_error:
        fprintf(stderr, "Kernel filename must be provided\n");
        exit(1);
    }
    setup_linux_config(s->cpu_state, ram_size);

    for(;;) {
        riscv_machine_run(s);
    }
    riscv_machine_end(s);
    return 0;
}

#endif
