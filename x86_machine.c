/*
 * PC emulator
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
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>

#include "cutils.h"
#include "iomem.h"
#include "virtio.h"
#include "x86_cpu.h"
#include "machine.h"

#if defined(__i386__) || defined(__x86_64__)
#define USE_KVM
#endif

#ifdef USE_KVM
#include <linux/kvm.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/time.h>
#endif

/***********************************************************/
/* cmos emulation */

#define RTC_SECONDS             0
#define RTC_SECONDS_ALARM       1
#define RTC_MINUTES             2
#define RTC_MINUTES_ALARM       3
#define RTC_HOURS               4
#define RTC_HOURS_ALARM         5
#define RTC_ALARM_DONT_CARE    0xC0

#define RTC_DAY_OF_WEEK         6
#define RTC_DAY_OF_MONTH        7
#define RTC_MONTH               8
#define RTC_YEAR                9

#define RTC_REG_A               10
#define RTC_REG_B               11
#define RTC_REG_C               12
#define RTC_REG_D               13

/* PC cmos mappings */
#define REG_EQUIPMENT_BYTE          0x14

static int to_bcd(unsigned int a)
{
    return ((a / 10) << 4) | (a % 10);
}
typedef struct {
    uint8_t cmos_index;
    uint8_t cmos_data[128];
} CMOSState;

static void cmos_write(void *opaque, uint64_t offset,
                       uint64_t data, int size_log2);
static uint64_t cmos_read(void *opaque, uint64_t offset, int size_log2);

CMOSState *cmos_init(PhysMemoryMap *port_map, int addr)
{
    CMOSState *s;
    struct tm tm;
    time_t ti;
    
    s = mallocz(sizeof(*s));
    
    s->cmos_index = 0;

    ti = time(NULL);
    gmtime_r(&ti, &tm);
    
    s->cmos_data[RTC_SECONDS] = to_bcd(tm.tm_sec);
    s->cmos_data[RTC_MINUTES] = to_bcd(tm.tm_min);
    s->cmos_data[RTC_HOURS] = to_bcd(tm.tm_hour);
    s->cmos_data[RTC_DAY_OF_WEEK] = to_bcd(tm.tm_wday);
    s->cmos_data[RTC_DAY_OF_MONTH] = to_bcd(tm.tm_mday);
    s->cmos_data[RTC_MONTH] = to_bcd(tm.tm_mon + 1);
    s->cmos_data[RTC_YEAR] = to_bcd(tm.tm_year % 100);

    s->cmos_data[RTC_REG_A] = 0x26;
    s->cmos_data[RTC_REG_B] = 0x02;
    s->cmos_data[RTC_REG_C] = 0x00;
    s->cmos_data[RTC_REG_D] = 0x80;

    s->cmos_data[REG_EQUIPMENT_BYTE] = 0x02; /* FPU is there */

    cpu_register_device(port_map, addr, 2, s, cmos_read, cmos_write, 
                        DEVIO_SIZE8);
    return s;
}

static void cmos_write(void *opaque, uint64_t offset,
                       uint64_t data, int size_log2)
{
    CMOSState *s = opaque;
    if (offset == 0) {
        s->cmos_index = data & 0x7f;
    }
}

static uint64_t cmos_read(void *opaque, uint64_t offset, int size_log2)
{
    CMOSState *s = opaque;
    int ret;

    if (offset == 0) {
        return 0xff;
    } else {
        /* toggle update-in-progress bit for Linux (same hack as
           plex86) */
        ret = s->cmos_data[s->cmos_index];
        if (s->cmos_index == RTC_REG_A)
            s->cmos_data[RTC_REG_A] ^= 0x80; 
        else if (s->cmos_index == RTC_REG_C)
            s->cmos_data[RTC_REG_C] = 0x00; 
        return ret;
    }
}

/***********************************************************/
/* 8259 pic emulation */

//#define DEBUG_PIC

typedef void PICUpdateIRQFunc(void *opaque);

typedef struct {
    uint8_t last_irr; /* edge detection */
    uint8_t irr; /* interrupt request register */
    uint8_t imr; /* interrupt mask register */
    uint8_t isr; /* interrupt service register */
    uint8_t priority_add; /* used to compute irq priority */
    uint8_t irq_base;
    uint8_t read_reg_select;
    uint8_t special_mask;
    uint8_t init_state;
    uint8_t auto_eoi;
    uint8_t rotate_on_autoeoi;
    uint8_t init4; /* true if 4 byte init */
    uint8_t elcr; /* PIIX edge/trigger selection*/
    uint8_t elcr_mask;
    PICUpdateIRQFunc *update_irq;
    void *opaque;
} PICState;

static void pic_reset(PICState *s);
static void pic_write(void *opaque, uint64_t offset,
                      uint64_t val64, int size_log2);
static uint64_t pic_read(void *opaque, uint64_t offset, int size_log2);

PICState *pic_init(PhysMemoryMap *port_map, int port, int elcr_mask,
                   PICUpdateIRQFunc *update_irq, void *opaque)
{
    PICState *s;

    s = mallocz(sizeof(*s));
    s->elcr_mask = elcr_mask;
    s->update_irq = update_irq;
    s->opaque = opaque;
    cpu_register_device(port_map, port, 2, s, pic_read, pic_write, 
                        DEVIO_SIZE8);
    pic_reset(s);
    return s;
}

static void pic_reset(PICState *s)
{
    /* all 8 bit registers */
    s->last_irr = 0; /* edge detection */
    s->irr = 0; /* interrupt request register */
    s->imr = 0; /* interrupt mask register */
    s->isr = 0; /* interrupt service register */
    s->priority_add = 0; /* used to compute irq priority */
    s->irq_base = 0;
    s->read_reg_select = 0;
    s->special_mask = 0;
    s->init_state = 0;
    s->auto_eoi = 0;
    s->rotate_on_autoeoi = 0;
    s->init4 = 0; /* true if 4 byte init */
}

/* set irq level. If an edge is detected, then the IRR is set to 1 */
static void pic_set_irq1(PICState *s, int irq, int level)
{
    int mask;
    mask = 1 << irq;
    if (level) {
        if ((s->last_irr & mask) == 0)
            s->irr |= mask;
        s->last_irr |= mask;
    } else {
        s->last_irr &= ~mask;
    }
}
    
static int pic_get_priority(PICState *s, int mask)
{
    int priority;
    if (mask == 0)
        return -1;
    priority = 7;
    while ((mask & (1 << ((priority + s->priority_add) & 7))) == 0)
        priority--;
    return priority;
}

/* return the pic wanted interrupt. return -1 if none */
static int pic_get_irq(PICState *s)
{
    int mask, cur_priority, priority;

    mask = s->irr & ~s->imr;
    priority = pic_get_priority(s, mask);
    if (priority < 0)
        return -1;
    /* compute current priority */
    cur_priority = pic_get_priority(s, s->isr);
    if (priority > cur_priority) {
        /* higher priority found: an irq should be generated */
        return priority;
    } else {
        return -1;
    }
}
    
/* acknowledge interrupt 'irq' */
static void pic_intack(PICState *s, int irq)
{
    if (s->auto_eoi) {
        if (s->rotate_on_autoeoi)
            s->priority_add = (irq + 1) & 7;
    } else {
        s->isr |= (1 << irq);
    }
    /* We don't clear a level sensitive interrupt here */
    if (!(s->elcr & (1 << irq)))
        s->irr &= ~(1 << irq);
}

static void pic_write(void *opaque, uint64_t offset,
                      uint64_t val64, int size_log2)
{
    PICState *s = opaque;
    int priority, addr, val;
    
    val = val64;
    addr = offset & 1;
#ifdef DEBUG_PIC
    console.log("pic_write: addr=" + toHex2(addr) + " val=" + toHex2(val));
#endif
    if (addr == 0) {
        if (val & 0x10) {
            /* init */
            pic_reset(s);
            s->init_state = 1;
            s->init4 = val & 1;
            if (val & 0x02)
                abort(); /* "single mode not supported" */
            if (val & 0x08)
                abort(); /* "level sensitive irq not supported" */
        } else if (val & 0x08) {
            if (val & 0x02)
                s->read_reg_select = val & 1;
            if (val & 0x40)
                s->special_mask = (val >> 5) & 1;
        } else {
            switch(val) {
            case 0x00:
            case 0x80:
                s->rotate_on_autoeoi = val >> 7;
                break;
            case 0x20: /* end of interrupt */
            case 0xa0:
                priority = pic_get_priority(s, s->isr);
                if (priority >= 0) {
                    s->isr &= ~(1 << ((priority + s->priority_add) & 7));
                }
                if (val == 0xa0)
                    s->priority_add = (s->priority_add + 1) & 7;
                break;
            case 0x60:
            case 0x61:
            case 0x62:
            case 0x63:
            case 0x64:
            case 0x65:
            case 0x66:
            case 0x67:
                priority = val & 7;
                s->isr &= ~(1 << priority);
                break;
            case 0xc0:
            case 0xc1:
            case 0xc2:
            case 0xc3:
            case 0xc4:
            case 0xc5:
            case 0xc6:
            case 0xc7:
                s->priority_add = (val + 1) & 7;
                break;
            case 0xe0:
            case 0xe1:
            case 0xe2:
            case 0xe3:
            case 0xe4:
            case 0xe5:
            case 0xe6:
            case 0xe7:
                priority = val & 7;
                s->isr &= ~(1 << priority);
                s->priority_add = (priority + 1) & 7;
                break;
            }
        }
    } else {
        switch(s->init_state) {
        case 0:
            /* normal mode */
            s->imr = val;
            s->update_irq(s->opaque);
            break;
        case 1:
            s->irq_base = val & 0xf8;
            s->init_state = 2;
            break;
        case 2:
            if (s->init4) {
                s->init_state = 3;
            } else {
                s->init_state = 0;
            }
            break;
        case 3:
            s->auto_eoi = (val >> 1) & 1;
            s->init_state = 0;
            break;
        }
    }
}

static uint64_t pic_read(void *opaque, uint64_t offset, int size_log2)
{
    PICState *s = opaque;
    int addr, ret;

    addr = offset & 1;
    if (addr == 0) {
        if (s->read_reg_select)
            ret = s->isr;
        else
            ret = s->irr;
    } else {
        ret = s->imr;
    }
#ifdef DEBUG_PIC
    console.log("pic_read: addr=" + toHex2(addr1) + " val=" + toHex2(ret));
#endif
    return ret;
}

typedef struct {
    PICState *pics[2];
    int irq_requested;
    void (*cpu_set_irq)(void *opaque, int level);
    void *opaque;
#if defined(DEBUG_PIC)
    uint8_t irq_level[16];
#endif
} PIC2State;

static void pic2_update_irq(void *opaque);

PIC2State *pic2_init(PhysMemoryMap *port_map, int addr0, int addr1,
                     void (*cpu_set_irq)(void *opaque, int level),
                     void *opaque)
{
    PIC2State *s;
    s = mallocz(sizeof(*s));
    s->cpu_set_irq = cpu_set_irq;
    s->opaque = opaque;
    s->pics[0] = pic_init(port_map, addr0, 0xf8, pic2_update_irq, s);
    s->pics[1] = pic_init(port_map, addr1, 0xde, pic2_update_irq, s);
    s->irq_requested = 0;
    return s;
}

/* raise irq to CPU if necessary. must be called every time the active
   irq may change */
static void pic2_update_irq(void *opaque)
{
    PIC2State *s = opaque;
    int irq2, irq;

    /* first look at slave pic */
    irq2 = pic_get_irq(s->pics[1]);
    if (irq2 >= 0) {
        /* if irq request by slave pic, signal master PIC */
        pic_set_irq1(s->pics[0], 2, 1);
        pic_set_irq1(s->pics[0], 2, 0);
    }
    /* look at requested irq */
    irq = pic_get_irq(s->pics[0]);
#if 0
    console.log("irr=" + toHex2(s->pics[0].irr) + " imr=" + toHex2(s->pics[0].imr) + " isr=" + toHex2(s->pics[0].isr) + " irq="+ irq);
#endif
    if (irq >= 0) {
        /* raise IRQ request on the CPU */
        s->cpu_set_irq(s->opaque, 1);
    } else {
        /* lower irq */
        s->cpu_set_irq(s->opaque, 0);
    }
}

static void pic2_set_irq(PIC2State *s, int irq, int level)
{
#if defined(DEBUG_PIC)
    if (irq != 0 && level != s->irq_level[irq]) {
        console.log("pic_set_irq: irq=" + irq + " level=" + level);
        s->irq_level[irq] = level;
    }
#endif
    pic_set_irq1(s->pics[irq >> 3], irq & 7, level);
    pic2_update_irq(s);
}

/* called from the CPU to get the hardware interrupt number */
static int pic2_get_hard_intno(PIC2State *s)
{
    int irq, irq2, intno;

    irq = pic_get_irq(s->pics[0]);
    if (irq >= 0) {
        pic_intack(s->pics[0], irq);
        if (irq == 2) {
            irq2 = pic_get_irq(s->pics[1]);
            if (irq2 >= 0) {
                pic_intack(s->pics[1], irq2);
            } else {
                /* spurious IRQ on slave controller */
                irq2 = 7;
            }
            intno = s->pics[1]->irq_base + irq2;
            irq = irq2 + 8;
        } else {
            intno = s->pics[0]->irq_base + irq;
        }
    } else {
        /* spurious IRQ on host controller */
        irq = 7;
        intno = s->pics[0]->irq_base + irq;
    }
    pic2_update_irq(s);

#if defined(DEBUG_PIC)
    console.log("get_hard_intno: irq=" + irq + " intno=" + intno);
#endif
    return intno;
}

/***********************************************************/
/* 8253 PIT emulation */

#define PIT_FREQ 1193182

#define RW_STATE_LSB 0
#define RW_STATE_MSB 1
#define RW_STATE_WORD0 2
#define RW_STATE_WORD1 3
#define RW_STATE_LATCHED_WORD0 4
#define RW_STATE_LATCHED_WORD1 5

//#define DEBUG_PIT

typedef int64_t PITGetTicksFunc(void *opaque);

typedef struct PITState PITState;

typedef struct {
    PITState *pit_state;
    uint32_t count;
    uint32_t latched_count;
    uint8_t rw_state;
    uint8_t mode;
    uint8_t bcd;
    uint8_t gate;
    int64_t count_load_time;
    int64_t last_irq_time;
} PITChannel;

struct PITState {
    PITChannel pit_channels[3];
    uint8_t speaker_data_on;
    PITGetTicksFunc *get_ticks;
    DeviceSetIRQFunc *set_irq;
    int irq_num;
    void *opaque;
};

static void pit_load_count(PITChannel *pc, int val);
static void pit_write(void *opaque, uint64_t offset,
                      uint64_t val64, int size_log2);
static uint64_t pit_read(void *opaque, uint64_t offset, int size_log2);
static void speaker_write(void *opaque, uint64_t offset,
                          uint64_t val, int size_log2);
static uint64_t speaker_read(void *opaque, uint64_t offset, int size_log2);

PITState *pit_init(PhysMemoryMap *port_map, int addr0, int addr1,
                   DeviceSetIRQFunc *set_irq, int irq_num,
                   PITGetTicksFunc *get_ticks, void *opaque)
{
    PITState *s;
    PITChannel *pc;
    int i;

    s = mallocz(sizeof(*s));

    s->set_irq = set_irq;
    s->irq_num = irq_num;
    s->get_ticks = get_ticks;
    s->opaque = opaque;
    
    for(i = 0; i < 3; i++) {
        pc = &s->pit_channels[i];
        pc->pit_state = s;
        pc->mode = 3;
        pc->gate = (i != 2) >> 0;
        pit_load_count(pc, 0);
    }
    s->speaker_data_on = 0;

    cpu_register_device(port_map, addr0, 4, s, pit_read, pit_write, 
                        DEVIO_SIZE8);

    cpu_register_device(port_map, addr1, 1, s, speaker_read, speaker_write, 
                        DEVIO_SIZE8);
    return s;
}

/* unit = PIT frequency  */
static int64_t pit_get_time(PITChannel *pc)
{
    PITState *s = pc->pit_state;
    return s->get_ticks(s->opaque);
}

static uint32_t pit_get_count(PITChannel *pc)
{
    uint32_t counter;
    uint64_t d;
    
    d = pit_get_time(pc) - pc->count_load_time;
    switch(pc->mode) {
    case 0:
    case 1:
    case 4:
    case 5:
        counter = (pc->count - d) & 0xffff;
        break;
    default:
        counter = pc->count - (d % pc->count);
        break;
    }
    return counter;
}

/* get pit output bit */
static int pit_get_out(PITChannel *pc)
{
    int out;
    int64_t d;
    
    d = pit_get_time(pc) - pc->count_load_time;
    switch(pc->mode) {
    default:
    case 0:
        out = (d >= pc->count) >> 0;
        break;
    case 1:
        out = (d < pc->count) >> 0;
        break;
    case 2:
        /* mode used by Linux */
        if ((d % pc->count) == 0 && d != 0)
            out = 1;
        else
            out = 0;
        break;
    case 3:
        out = ((d % pc->count) < (pc->count >> 1)) >> 0;
        break;
    case 4:
    case 5:
        out = (d == pc->count) >> 0;
        break;
    }
    return out;
}

static void pit_load_count(PITChannel *s, int val)
{
    if (val == 0)
        val = 0x10000;
    s->count_load_time = pit_get_time(s);
    s->last_irq_time = 0;
    s->count = val;
}

static void pit_write(void *opaque, uint64_t offset,
                      uint64_t val64, int size_log2)
{
    PITState *pit = opaque;
    int channel, access, val, addr;
    PITChannel *s;

    val = val64;
    addr = offset & 3;
#ifdef DEBUG_PIT
    console.log("pit_write: addr=" + toHex2(addr) + " val=" + toHex2(val));
#endif
    if (addr == 3) {
        channel = val >> 6;
        if (channel == 3)
            return;
        s = &pit->pit_channels[channel];
        access = (val >> 4) & 3;
        switch(access) {
        case 0:
            s->latched_count = pit_get_count(s);
            s->rw_state = RW_STATE_LATCHED_WORD0;
            break;
        default:
            s->mode = (val >> 1) & 7;
            s->bcd = val & 1;
            s->rw_state = access - 1 +  RW_STATE_LSB;
            break;
        }
    } else {
        s = &pit->pit_channels[addr];
        switch(s->rw_state) {
        case RW_STATE_LSB:
            pit_load_count(s, val);
            break;
        case RW_STATE_MSB:
            pit_load_count(s, val << 8);
            break;
        case RW_STATE_WORD0:
        case RW_STATE_WORD1:
            if (s->rw_state & 1) {
                pit_load_count(s, (s->latched_count & 0xff) | (val << 8));
            } else {
                s->latched_count = val;
            }
            s->rw_state ^= 1;
            break;
        }
    }
}

static uint64_t pit_read(void *opaque, uint64_t offset, int size_log2)
{
    PITState *pit = opaque;
    PITChannel *s;
    int ret, count, addr;
    
    addr = offset & 3;
    if (addr == 3)
        return 0xff;

    s = &pit->pit_channels[addr];
    switch(s->rw_state) {
    case RW_STATE_LSB:
    case RW_STATE_MSB:
    case RW_STATE_WORD0:
    case RW_STATE_WORD1:
        count = pit_get_count(s);
        if (s->rw_state & 1)
            ret = (count >> 8) & 0xff;
        else
            ret = count & 0xff;
        if (s->rw_state & 2)
            s->rw_state ^= 1;
        break;
    default:
    case RW_STATE_LATCHED_WORD0:
    case RW_STATE_LATCHED_WORD1:
        if (s->rw_state & 1)
            ret = s->latched_count >> 8;
        else
            ret = s->latched_count & 0xff;
        s->rw_state ^= 1;
        break;
    }
#ifdef DEBUG_PIT
    console.log("pit_read: offset=" + toHex2(addr) + " val=" + toHex2(ret));
#endif
    return ret;
}

static void speaker_write(void *opaque, uint64_t offset,
                          uint64_t val, int size_log2)
{
    PITState *pit = opaque;
    pit->speaker_data_on = (val >> 1) & 1;
    pit->pit_channels[2].gate = val & 1;
}

static uint64_t speaker_read(void *opaque, uint64_t offset, int size_log2)
{
    PITState *pit = opaque;
    PITChannel *s;
    int out, val;

    s = &pit->pit_channels[2];
    out = pit_get_out(s);
    val = (pit->speaker_data_on << 1) | s->gate | (out << 5);
#ifdef DEBUG_PIT
    //    console.log("speaker_read: addr=" + toHex2(addr) + " val=" + toHex2(val));
#endif
    return val;
}

/* set the IRQ if necessary and return the delay in ms until the next
   IRQ. Note: The code does not handle all the PIT configurations. */
static int pit_update_irq(PITState *pit)
{
    PITChannel *s;
    int64_t d, delay;
    
    s = &pit->pit_channels[0];
    
    delay = PIT_FREQ; /* could be infinity delay */
    
    d = pit_get_time(s) - s->count_load_time;
    switch(s->mode) {
    default:
    case 0:
    case 1:
    case 4:
    case 5:
        if (s->last_irq_time == 0) {
            delay = s->count - d;
            if (delay <= 0) {
                pit->set_irq(pit->opaque, pit->irq_num, 1);
                pit->set_irq(pit->opaque, pit->irq_num, 0);
                s->last_irq_time = d;
            }
        }
        break;
    case 2: /* mode used by Linux */
    case 3:
        delay = s->last_irq_time + s->count - d;
        if (delay <= 0) {
            pit->set_irq(pit->opaque, pit->irq_num, 1);
            pit->set_irq(pit->opaque, pit->irq_num, 0);
            s->last_irq_time += s->count;
        }
        break;
    }

    if (delay <= 0)
        return 0;
    else
        return delay / (PIT_FREQ / 1000);
}
    
/***********************************************************/
/* serial port emulation */

#define UART_LCR_DLAB	0x80	/* Divisor latch access bit */

#define UART_IER_MSI	0x08	/* Enable Modem status interrupt */
#define UART_IER_RLSI	0x04	/* Enable receiver line status interrupt */
#define UART_IER_THRI	0x02	/* Enable Transmitter holding register int. */
#define UART_IER_RDI	0x01	/* Enable receiver data interrupt */

#define UART_IIR_NO_INT	0x01	/* No interrupts pending */
#define UART_IIR_ID	0x06	/* Mask for the interrupt ID */

#define UART_IIR_MSI	0x00	/* Modem status interrupt */
#define UART_IIR_THRI	0x02	/* Transmitter holding register empty */
#define UART_IIR_RDI	0x04	/* Receiver data interrupt */
#define UART_IIR_RLSI	0x06	/* Receiver line status interrupt */
#define UART_IIR_FE     0xC0    /* Fifo enabled */

#define UART_LSR_TEMT	0x40	/* Transmitter empty */
#define UART_LSR_THRE	0x20	/* Transmit-hold-register empty */
#define UART_LSR_BI	0x10	/* Break interrupt indicator */
#define UART_LSR_FE	0x08	/* Frame error indicator */
#define UART_LSR_PE	0x04	/* Parity error indicator */
#define UART_LSR_OE	0x02	/* Overrun error indicator */
#define UART_LSR_DR	0x01	/* Receiver data ready */

#define UART_FCR_XFR        0x04    /* XMIT Fifo Reset */
#define UART_FCR_RFR        0x02    /* RCVR Fifo Reset */
#define UART_FCR_FE         0x01    /* FIFO Enable */

#define UART_FIFO_LENGTH    16      /* 16550A Fifo Length */

typedef struct {
    uint8_t divider; 
    uint8_t rbr; /* receive register */
    uint8_t ier;
    uint8_t iir; /* read only */
    uint8_t lcr;
    uint8_t mcr;
    uint8_t lsr; /* read only */
    uint8_t msr;
    uint8_t scr;
    uint8_t fcr;
    DeviceSetIRQFunc *set_irq_func;
    int irq_num;
    void (*write_func)(void *opaque, const uint8_t *buf, int buf_len);
    void *opaque;
} SerialState;

static void serial_write(void *opaque, uint64_t offset,
                         uint64_t val64, int size_log2);
static uint64_t serial_read(void *opaque, uint64_t offset, int size_log2);

SerialState *serial_init(PhysMemoryMap *port_map, int addr,
                         DeviceSetIRQFunc *set_irq_func, int irq_num,
                         void (*write_func)(void *opaque, const uint8_t *buf, int buf_len), void *opaque)
{
    SerialState *s;
    s = mallocz(sizeof(*s));
    
    /* all 8 bit registers */
    s->divider = 0; 
    s->rbr = 0; /* receive register */
    s->ier = 0;
    s->iir = UART_IIR_NO_INT; /* read only */
    s->lcr = 0;
    s->mcr = 0;
    s->lsr = UART_LSR_TEMT | UART_LSR_THRE; /* read only */
    s->msr = 0;
    s->scr = 0;
    s->fcr = 0;

    s->set_irq_func = set_irq_func;
    s->irq_num = irq_num;
    s->write_func = write_func;
    s->opaque = opaque;

    cpu_register_device(port_map, addr, 8, s, serial_read, serial_write, 
                        DEVIO_SIZE8);
    return s;
}

static void serial_update_irq(SerialState *s)
{
    if ((s->lsr & UART_LSR_DR) && (s->ier & UART_IER_RDI)) {
        s->iir = UART_IIR_RDI;
    } else if ((s->lsr & UART_LSR_THRE) && (s->ier & UART_IER_THRI)) {
        s->iir = UART_IIR_THRI;
    } else {
        s->iir = UART_IIR_NO_INT;
    }
    if (s->iir != UART_IIR_NO_INT) {
        s->set_irq_func(s->opaque, s->irq_num, 1);
    } else {
        s->set_irq_func(s->opaque, s->irq_num, 0);
    }
}

#if 0
/* send remainining chars in fifo */
Serial.prototype.write_tx_fifo = function()
{
    if (s->tx_fifo != "") {
        s->write_func(s->tx_fifo);
        s->tx_fifo = "";
        
        s->lsr |= UART_LSR_THRE;
        s->lsr |= UART_LSR_TEMT;
        s->update_irq();
    }
}
#endif
    
static void serial_write(void *opaque, uint64_t offset,
                         uint64_t val64, int size_log2)
{
    SerialState *s = opaque;
    int addr, val;

    val = val64;
    addr = offset & 7;
    switch(addr) {
    default:
    case 0:
        if (s->lcr & UART_LCR_DLAB) {
            s->divider = (s->divider & 0xff00) | val;
        } else {
#if 0
            if (s->fcr & UART_FCR_FE) {
                s->tx_fifo += String.fromCharCode(val);
                s->lsr &= ~UART_LSR_THRE;
                serial_update_irq(s);
                if (s->tx_fifo.length >= UART_FIFO_LENGTH) {
                    /* write to the terminal */
                    s->write_tx_fifo();
                }
            } else
#endif
            {
                uint8_t ch;
                s->lsr &= ~UART_LSR_THRE;
                serial_update_irq(s);
                
                /* write to the terminal */
                ch = val;
                s->write_func(s->opaque, &ch, 1);
                
                s->lsr |= UART_LSR_THRE;
                s->lsr |= UART_LSR_TEMT;
                serial_update_irq(s);
            }
        }
        break;
    case 1:
        if (s->lcr & UART_LCR_DLAB) {
            s->divider = (s->divider & 0x00ff) | (val << 8);
        } else {
            s->ier = val;
            serial_update_irq(s);
        }
        break;
    case 2:
#if 0
        if ((s->fcr ^ val) & UART_FCR_FE) {
            /* clear fifos */
            val |= UART_FCR_XFR | UART_FCR_RFR;
        }
        if (val & UART_FCR_XFR)
            s->tx_fifo = "";
        if (val & UART_FCR_RFR)
            s->rx_fifo = "";
        s->fcr = val & UART_FCR_FE;
#endif
        break;
    case 3:
        s->lcr = val;
        break;
    case 4:
        s->mcr = val;
        break;
    case 5:
        break;
    case 6:
        s->msr = val;
        break;
    case 7:
        s->scr = val;
        break;
    }
}

static uint64_t serial_read(void *opaque, uint64_t offset, int size_log2)
{
    SerialState *s = opaque;
    int ret, addr;

    addr = offset & 7;
    switch(addr) {
    default:
    case 0:
        if (s->lcr & UART_LCR_DLAB) {
            ret = s->divider & 0xff; 
        } else {
            ret = s->rbr;
            s->lsr &= ~(UART_LSR_DR | UART_LSR_BI);
            serial_update_irq(s);
#if 0
            /* try to receive next chars */
            s->send_char_from_fifo();
#endif
        }
        break;
    case 1:
        if (s->lcr & UART_LCR_DLAB) {
            ret = (s->divider >> 8) & 0xff;
        } else {
            ret = s->ier;
        }
        break;
    case 2:
        ret = s->iir;
        if (s->fcr & UART_FCR_FE)
            ret |= UART_IIR_FE;
        break;
    case 3:
        ret = s->lcr;
        break;
    case 4:
        ret = s->mcr;
        break;
    case 5:
        ret = s->lsr;
        break;
    case 6:
        ret = s->msr;
        break;
    case 7:
        ret = s->scr;
        break;
    }
    return ret;
}

void serial_send_break(SerialState *s)
{
    s->rbr = 0;
    s->lsr |= UART_LSR_BI | UART_LSR_DR;
    serial_update_irq(s);
}

#if 0
static void serial_send_char(SerialState *s, int ch)
{
    s->rbr = ch;
    s->lsr |= UART_LSR_DR;
    serial_update_irq(s);
}

Serial.prototype.send_char_from_fifo = function()
{
    var fifo;

    fifo = s->rx_fifo;
    if (fifo != "" && !(s->lsr & UART_LSR_DR)) {
        s->send_char(fifo.charCodeAt(0));
        s->rx_fifo = fifo.substr(1, fifo.length - 1);
    }
}

/* queue the string in the UART receive fifo and send it ASAP */
Serial.prototype.send_chars = function(str)
{
    s->rx_fifo += str;
    s->send_char_from_fifo();
}
    
/***********************************************************/
/* simulate reset */

function KBD(pc, reset_request)
{
    pc.register_ioport_read(0x64, 1, 1, s->read_status.bind(this));
    pc.register_ioport_write(0x64, 1, 1, s->write_command.bind(this));
    s->reset_request = reset_request;
}

KBD.prototype.read_status = function(addr)
{
    return 0;
}

KBD.prototype.write_command = function(addr, val)
{
    switch(val) {
    case 0xfe:
        s->reset_request();
        break;
    default:
        break;
    }
}
#endif

typedef struct PCMachine {
    VirtMachine common;
    uint64_t ram_size;
    size_t phys_mem_size;
    uint8_t *phys_mem;
    PhysMemoryMap *mem_map;
    PhysMemoryMap *port_map;
    
    X86CPUState *cpu_state;
    PIC2State *pic_state;
    PITState *pit_state;
    CMOSState *cmos_state;
    SerialState *serial_state;
    char cmd_line[512];
#ifdef USE_KVM
    BOOL kvm_enabled;
    int kvm_fd;
    int vm_fd;
    int vcpu_fd;
    int kvm_run_size;
    struct kvm_run *kvm_run;
#endif
} PCMachine;

static void port80_write(void *opaque, uint64_t offset,
                         uint64_t val64, int size_log2)
{
}

static uint64_t port80_read(void *opaque, uint64_t offset, int size_log2)
{
    return 0xff;
}

static void pic_set_irq_cb(void *opaque, int level)
{
    PCMachine *s = opaque;
    x86_cpu_set_irq(s->cpu_state, level);
}

static void pc_set_irq_cb(void *opaque, int irq_num, int level)
{
    PCMachine *s = opaque;
#ifdef USE_KVM
    if (s->kvm_enabled) {
	struct kvm_irq_level irq_level;
        irq_level.irq = irq_num;
        irq_level.level = level;
        if (ioctl(s->vm_fd, KVM_IRQ_LINE, &irq_level) < 0) {
            perror("KVM_IRQ_LINE");
            exit(1);
        }
    } else
#endif
    {
        pic2_set_irq(s->pic_state, irq_num, level);
    }
}

static void serial_write_cb(void *opaque, const uint8_t *buf, int buf_len)
{
    PCMachine *s = opaque;
    s->common.console->write_data(s->common.console->opaque, buf, buf_len);
}

static int get_hard_intno_cb(void *opaque)
{
    PCMachine *s = opaque;
    return pic2_get_hard_intno(s->pic_state);
}

static int64_t pit_get_ticks_cb(void *opaque)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * PIT_FREQ +
        ((uint64_t)ts.tv_nsec * PIT_FREQ / 1000000000);
}

#define VIRTIO_START_ADDR 0xf0000000
#define VIRTIO_START_IRQ  8

static uint8_t *virtio_get_ram_ptr(void *opaque, virtio_phys_addr_t paddr)
{
    PCMachine *s = opaque;
    if (paddr >= s->ram_size)
        return 0;
    return s->phys_mem + paddr;
}

static uint64_t virtio_read(void *opaque, uint64_t offset,
                            int size_log2)
{
    VIRTIODevice *s = opaque;
    //    printf("read offset=0x%x\n", (int)offset);
    return virtio_mmio_read(s, offset, size_log2);
}
 
static void virtio_write(void *opaque, uint64_t offset, uint64_t val,
                         int size_log2)
{
    VIRTIODevice *s = opaque;
    //    printf("write offset=0x%x\n", (int)offset);
    virtio_mmio_write(s, offset, val, size_log2);
}

void virt_machine_set_defaults(VirtMachineParams *p)
{
    memset(p, 0, sizeof(*p));
    p->accel_enable = TRUE;
}

#ifdef USE_KVM

static void sigalrm_handler(int sig)
{
}

static void kvm_init(PCMachine *s)
{
    int ret;
    struct kvm_userspace_memory_region region;
    struct sigaction act;
    struct kvm_pit_config pit_config;
    
    s->kvm_enabled = FALSE;
    s->kvm_fd = open("/dev/kvm", O_RDWR);
    if (s->kvm_fd < 0) {
        fprintf(stderr, "KVM not available\n");
        return;
    }
    ret = ioctl(s->kvm_fd, KVM_GET_API_VERSION, 0);
    if (ret < 0) {
        perror("KVM_GET_API_VERSION");
        exit(1);
    }
    if (ret != 12) {
        fprintf(stderr, "Unsupported KVM version\n");
        close(s->kvm_fd);
        s->kvm_fd = -1;
        return;
    }
    s->vm_fd = ioctl(s->kvm_fd, KVM_CREATE_VM, 0);
    if (s->vm_fd < 0) {
        perror("KVM_CREATE_VM");
        exit(1);
    }

    if (ioctl(s->vm_fd, KVM_SET_TSS_ADDR, 0xfffbd000) < 0) {
        perror("KVM_SET_TSS_ADDR");
        exit(1);
    }
    
    memset(&pit_config, 0, sizeof(pit_config));
    pit_config.flags = 0;
    if (ioctl(s->vm_fd, KVM_CREATE_PIT2, &pit_config)) {
        perror("KVM_CREATE_PIT2");
        exit(1);
    }
    
    if (ioctl(s->vm_fd, KVM_CREATE_IRQCHIP, 0) < 0) {
        perror("KVM_CREATE_IRQCHIP");
        exit(1);
    }

    s->phys_mem = mmap(NULL, s->phys_mem_size, PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (!s->phys_mem) {
        fprintf(stderr, "Could not allocate VM memory\n");
        exit(1);
    }

    region.slot = 0;
    region.flags = 0;
    region.guest_phys_addr = 0;
    region.memory_size = s->phys_mem_size;
    region.userspace_addr = (uintptr_t)s->phys_mem;
    if (ioctl(s->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
        perror("KVM_SET_USER_MEMORY_REGION");
        exit(1);
    }

    s->vcpu_fd = ioctl(s->vm_fd, KVM_CREATE_VCPU, 0);
    if (s->vcpu_fd < 0) {
        perror("KVM_CREATE_VCPU");
        exit(1);
    }

    /* map the kvm_run structure */
    s->kvm_run_size = ioctl(s->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, NULL);
    if (s->kvm_run_size < 0) {
        perror("KVM_GET_VCPU_MMAP_SIZE");
        exit(1);
    }

    s->kvm_run = mmap(NULL, s->kvm_run_size, PROT_READ | PROT_WRITE,
                      MAP_SHARED, s->vcpu_fd, 0);
    if (!s->kvm_run) {
        perror("mmap kvm_run");
        exit(1);
    }

    act.sa_handler = sigalrm_handler;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    sigaction(SIGALRM, &act, NULL);

    s->kvm_enabled = TRUE;
}

static void st_port(PCMachine *s, int port, int val, int size_log2)
{
    PhysMemoryRange *pr;
    pr = get_phys_mem_range(s->port_map, port);
    if (!pr)
        return;
    port -= pr->addr;
    if ((pr->devio_flags >> size_log2) & 1) {
        pr->write_func(pr->opaque, port, (uint32_t)val, size_log2);
    } else if (size_log2 == 1 && (pr->devio_flags & DEVIO_SIZE8)) {
        pr->write_func(pr->opaque, port, val & 0xff, 0);
        pr->write_func(pr->opaque, port + 1, (val >> 8) & 0xff, 0);
    }
}

static int ld_port(PCMachine *s, int port, int size_log2)
{
    PhysMemoryRange *pr;
    int val;
    
    pr = get_phys_mem_range(s->port_map, port);
    if (!pr) {
        val = -1;
    } else {
        port -= pr->addr;
        if ((pr->devio_flags >> size_log2) & 1) {
            val = pr->read_func(pr->opaque, port, size_log2);
        } else if (size_log2 == 1 && (pr->devio_flags & DEVIO_SIZE8)) {
            val = pr->read_func(pr->opaque, port, 0) & 0xff;
            val |= (pr->read_func(pr->opaque, port + 1, 0) & 0xff) << 8;
        } else {
            val = -1;
        }
    }
    return val;
}

static void kvm_exit_io(PCMachine *s, struct kvm_run *run)
{
    uint8_t *ptr;
    int i;
    
    ptr = (uint8_t *)run + run->io.data_offset;
    //    printf("port: addr=%04x\n", run->io.port);
    
    for(i = 0; i < run->io.count; i++) {
        if (run->io.direction == KVM_EXIT_IO_OUT) {
            switch(run->io.size) {
            case 1:
                st_port(s, run->io.port, *(uint8_t *)ptr, 0);
                break;
            case 2:
                st_port(s, run->io.port, *(uint16_t *)ptr, 1);
                break;
            case 4:
                st_port(s, run->io.port, *(uint32_t *)ptr, 2);
                break;
            default:
                abort();
            }
        } else {
            switch(run->io.size) {
            case 1:
                *(uint8_t *)ptr = ld_port(s, run->io.port, 0);
                break;
            case 2:
                *(uint16_t *)ptr = ld_port(s, run->io.port, 1);
                break;
            case 4:
                *(uint32_t *)ptr = ld_port(s, run->io.port, 2);
                break;
            default:
                abort();
            }
        }
        ptr += run->io.size;
    }
}

static void kvm_exit_mmio(PCMachine *s, struct kvm_run *run)
{
    uint8_t *data = run->mmio.data;
    PhysMemoryRange *pr;
    uint64_t addr;
    
    pr = get_phys_mem_range(s->mem_map, run->mmio.phys_addr);
    if (run->mmio.is_write) {
        if (!pr || pr->is_ram)
            return;
        addr = run->mmio.phys_addr - pr->addr;
        switch(run->mmio.len) {
        case 1:
            if (pr->devio_flags & DEVIO_SIZE8) {
                pr->write_func(pr->opaque, addr, *(uint8_t *)data, 0);
            }
            break;
        case 2:
            if (pr->devio_flags & DEVIO_SIZE16) {
                pr->write_func(pr->opaque, addr, *(uint16_t *)data, 1);
            }
            break;
        case 4:
            if (pr->devio_flags & DEVIO_SIZE32) {
                pr->write_func(pr->opaque, addr, *(uint32_t *)data, 2);
            }
            break;
        case 8:
            if (pr->devio_flags & DEVIO_SIZE64) {
                pr->write_func(pr->opaque, addr, *(uint64_t *)data, 3);
            } else if (pr->devio_flags & DEVIO_SIZE32) {
                pr->write_func(pr->opaque, addr, *(uint32_t *)data, 2);
                pr->write_func(pr->opaque, addr + 4, *(uint32_t *)(data + 4), 2);
            }
            break;
        default:
            abort();
        }
    } else {
        if (!pr || pr->is_ram)
            goto no_dev;
        addr = run->mmio.phys_addr - pr->addr;
        switch(run->mmio.len) {
        case 1:
            if (!(pr->devio_flags & DEVIO_SIZE8))
                goto no_dev;
            *(uint8_t *)data = pr->read_func(pr->opaque, addr, 0);
            break;
        case 2:
            if (!(pr->devio_flags & DEVIO_SIZE16))
                goto no_dev;
            *(uint16_t *)data = pr->read_func(pr->opaque, addr, 1);
            break;
        case 4:
            if (!(pr->devio_flags & DEVIO_SIZE32))
                goto no_dev;
            *(uint32_t *)data = pr->read_func(pr->opaque, addr, 2);
            break;
        case 8:
            if (pr->devio_flags & DEVIO_SIZE64) {
                *(uint64_t *)data = pr->read_func(pr->opaque, addr, 3);
            } else if (pr->devio_flags & DEVIO_SIZE32) {
                *(uint32_t *)data =
                    pr->read_func(pr->opaque, addr, 2);
                *(uint32_t *)(data + 4) =
                    pr->read_func(pr->opaque, addr + 4, 2);
            } else {
            no_dev:
                memset(run->mmio.data, 0, run->mmio.len);
            }
            break;
        default:
            abort();
        }
            
    }
}

static void kvm_exec(PCMachine *s)
{
    struct kvm_run *run = s->kvm_run;
    struct itimerval ival;
    int ret;
    
    /* Not efficient but simple: we use a timer to interrupt the
       execution after a given time */
    ival.it_interval.tv_sec = 0;
    ival.it_interval.tv_usec = 0;
    ival.it_value.tv_sec = 0;
    ival.it_value.tv_usec = 10 * 1000; /* 10 ms max */
    setitimer(ITIMER_REAL, &ival, NULL);

    ret = ioctl(s->vcpu_fd, KVM_RUN, 0);
    if (ret < 0) {
        if (errno == EINTR || errno == EAGAIN) {
            /* timeout */
            return;
        }
        perror("KVM_RUN");
        exit(1);
    }
    //    printf("exit=%d\n", run->exit_reason);
    switch(run->exit_reason) {
    case KVM_EXIT_HLT:
        break;
    case KVM_EXIT_IO:
        kvm_exit_io(s, run);
        break;
    case KVM_EXIT_MMIO:
        kvm_exit_mmio(s, run);
        break;
    case KVM_EXIT_FAIL_ENTRY:
        fprintf(stderr, "KVM_EXIT_FAIL_ENTRY: reason=0x%" PRIx64 "\n",
                (uint64_t)run->fail_entry.hardware_entry_failure_reason);
#if 0
        {
            struct kvm_regs regs;
            if (ioctl(s->vcpu_fd, KVM_GET_REGS, &regs) < 0) {
                perror("KVM_SET_REGS");
                exit(1);
            }
            printf("RIP=%016" PRIx64 "\n", (uint64_t)regs.rip);
        }
#endif
        exit(1);
    case KVM_EXIT_INTERNAL_ERROR:
        fprintf(stderr, "KVM_EXIT_INTERNAL_ERROR: suberror=0x%x\n",
                (uint32_t)run->internal.suberror);
        exit(1);
    default:
        fprintf(stderr, "KVM: unsupported exit_reason=%d\n", run->exit_reason);
        exit(1);
    }
}
#endif

VirtMachine *virt_machine_init(const VirtMachineParams *p)
{
    PCMachine *s;
    uint64_t virtio_addr;
    VIRTIODevice *blk_dev, *net_dev;
    int irq_num, i;
    char buf1[128];
    
    s = mallocz(sizeof(*s));
    s->ram_size = p->ram_size;
    s->phys_mem_size = p->ram_size;
    
#ifdef USE_KVM
    if (p->accel_enable) {
        kvm_init(s);
    }
#endif

#ifdef USE_KVM
    if (!s->kvm_enabled)
#endif
    {
        s->phys_mem = mallocz(s->phys_mem_size);
        if (!s->phys_mem) {
            fprintf(stderr, "Could not allocate VM memory\n");
            exit(1);
        }
    }
    
    s->mem_map = phys_mem_map_init();
    s->port_map = phys_mem_map_init();

#ifdef USE_KVM
    if (!s->kvm_enabled)
#endif
    {
        s->cpu_state = x86_cpu_init(s->mem_map, s->phys_mem, s->port_map);
    }

    /* set the RAM mapping */
    cpu_register_ram(s->mem_map, 0, p->ram_size, 0);
    
    /* devices */
    cpu_register_device(s->port_map, 0x80, 2, s, port80_read, port80_write, 
                        DEVIO_SIZE8);
    
#ifdef USE_KVM
    if (!s->kvm_enabled)
#endif
    {
        s->pic_state = pic2_init(s->port_map, 0x20, 0xa0, pic_set_irq_cb, s);
        x86_cpu_set_get_hard_intno(s->cpu_state, get_hard_intno_cb, s);
        s->pit_state = pit_init(s->port_map, 0x40, 0x61, pc_set_irq_cb, 0,
                                pit_get_ticks_cb, s);
    }

    s->cmos_state = cmos_init(s->port_map, 0x70);

    s->common.console = p->console;
    s->serial_state = serial_init(s->port_map, 0x3f8, pc_set_irq_cb, 4,
                                  serial_write_cb, s);
    
    virtio_addr = VIRTIO_START_ADDR;
    irq_num = VIRTIO_START_IRQ;
    
    pstrcpy(s->cmd_line, sizeof(s->cmd_line), "notsc=1 console=hvc0 loglevel=3");

    /* virtio console */
    s->common.console_dev = virtio_console_init(pc_set_irq_cb, irq_num, 
                                         virtio_get_ram_ptr, s,
                                         p->console);
    cpu_register_device(s->mem_map, virtio_addr, 0x1000,
                        s->common.console_dev, virtio_read, virtio_write,
                        DEVIO_SIZE8 | DEVIO_SIZE16 | DEVIO_SIZE32);

    snprintf(buf1, sizeof(buf1), " virtio_mmio.device=4K@0x%" PRIx64 ":%d",
             virtio_addr, irq_num);
    pstrcat(s->cmd_line, sizeof(s->cmd_line), buf1);

    virtio_addr += 0x1000;
    irq_num++;

    /* virtio net device */
    if (p->net) {
        net_dev = virtio_net_init(pc_set_irq_cb, irq_num,
                                  virtio_get_ram_ptr, s, p->net);
        cpu_register_device(s->mem_map, virtio_addr, 0x1000,
                            net_dev, virtio_read, virtio_write,
                            DEVIO_SIZE8 | DEVIO_SIZE16 | DEVIO_SIZE32);
        s->common.net_dev = net_dev;
        s->common.net = p->net;

        snprintf(buf1, sizeof(buf1), " virtio_mmio.device=4K@0x%" PRIx64 ":%d",
                 virtio_addr, irq_num);
        pstrcat(s->cmd_line, sizeof(s->cmd_line), buf1);

        virtio_addr += 0x1000;
        irq_num++;
    }

    /* virtio block device */
    for(i = 0; i < p->drive_count; i++) {
        blk_dev = virtio_block_init(pc_set_irq_cb, irq_num,
                                    virtio_get_ram_ptr, s, p->tab_drive[i]);
        cpu_register_device(s->mem_map, virtio_addr, 0x1000,
                            blk_dev, virtio_read, virtio_write,
                            DEVIO_SIZE8 | DEVIO_SIZE16 | DEVIO_SIZE32);

        snprintf(buf1, sizeof(buf1), " virtio_mmio.device=4K@0x%" PRIx64 ":%d",
                 virtio_addr, irq_num);
        pstrcat(s->cmd_line, sizeof(s->cmd_line), buf1);

        virtio_addr += 0x1000;
        irq_num++;
    }

    /* virtio filesystem */
    for(i = 0; i < p->fs_count; i++) {
        VIRTIODevice *fs_dev;
        char buf[64];

        if (i == 0)
            strcpy(buf, "/dev/root");
        else
            snprintf(buf, sizeof(buf), "/dev/root%d", i);
        fs_dev = virtio_9p_init(pc_set_irq_cb, irq_num, virtio_get_ram_ptr, s,
                                p->tab_fs[i], buf);
        cpu_register_device(s->mem_map, virtio_addr, 0x1000,
                            fs_dev, virtio_read, virtio_write,
                            DEVIO_SIZE8 | DEVIO_SIZE16 | DEVIO_SIZE32);
        //        virtio_set_debug(fs_dev, VIRTIO_DEBUG_9P);

        snprintf(buf1, sizeof(buf1), " virtio_mmio.device=4K@0x%" PRIx64 ":%d",
                 virtio_addr, irq_num);
        pstrcat(s->cmd_line, sizeof(s->cmd_line), buf1);

        virtio_addr += 0x1000;
        irq_num++;
    }

    if (p->drive_count == 0) {
        pstrcat(s->cmd_line, sizeof(s->cmd_line), " root=root rootfstype=9p rootflags=trans=virtio ro");
    } else {
        pstrcat(s->cmd_line, sizeof(s->cmd_line), " root=/dev/vda ro");
    }

    if (p->cmdline) {
        pstrcat(s->cmd_line, sizeof(s->cmd_line), " ");
        pstrcat(s->cmd_line, sizeof(s->cmd_line), p->cmdline);
    }
    
    return (VirtMachine *)s;
}

void virt_machine_end(VirtMachine *s1)
{
    PCMachine *s = (PCMachine *)s1;
    /* XXX: free all */
    if (s->cpu_state) {
        x86_cpu_end(s->cpu_state);
        free(s->phys_mem);
    }
    phys_mem_map_end(s->mem_map);
    phys_mem_map_end(s->port_map);
    free(s);
}

#define KERNEL_LOAD_ADDR 0x00200000
#define KERNEL_PARAMS_ADDR 0x00090000

void copy_kernel(VirtMachine *s1, const uint8_t *buf, int buf_len)
{
    PCMachine *s = (PCMachine *)s1;
    uint8_t *ram_ptr;
    assert(buf_len < (s->ram_size - KERNEL_LOAD_ADDR));
    ram_ptr = s->phys_mem + KERNEL_LOAD_ADDR;
    memcpy(ram_ptr, buf, buf_len);
}

/* from plex86 (BSD license) */
struct  __attribute__ ((packed)) linux_params {
  // For 0x00..0x3f, see 'struct screen_info' in linux/include/linux/tty.h.
  // I just padded out the VESA parts, rather than define them.

  /* 0x000 */ uint8_t   orig_x;
  /* 0x001 */ uint8_t   orig_y;
  /* 0x002 */ uint16_t  ext_mem_k;
  /* 0x004 */ uint16_t  orig_video_page;
  /* 0x006 */ uint8_t   orig_video_mode;
  /* 0x007 */ uint8_t   orig_video_cols;
  /* 0x008 */ uint16_t  unused1;
  /* 0x00a */ uint16_t  orig_video_ega_bx;
  /* 0x00c */ uint16_t  unused2;
  /* 0x00e */ uint8_t   orig_video_lines;
  /* 0x00f */ uint8_t   orig_video_isVGA;
  /* 0x010 */ uint16_t  orig_video_points;
  /* 0x012 */ uint8_t   pad0[0x20 - 0x12]; // VESA info.
  /* 0x020 */ uint16_t  cl_magic;  // Commandline magic number (0xA33F)
  /* 0x022 */ uint16_t  cl_offset; // Commandline offset.  Address of commandline
                                 // is calculated as 0x90000 + cl_offset, bu
                                 // only if cl_magic == 0xA33F.
  /* 0x024 */ uint8_t   pad1[0x40 - 0x24]; // VESA info.

  /* 0x040 */ uint8_t   apm_bios_info[20]; // struct apm_bios_info
  /* 0x054 */ uint8_t   pad2[0x80 - 0x54];

  // Following 2 from 'struct drive_info_struct' in drivers/block/cciss.h.
  // Might be truncated?
  /* 0x080 */ uint8_t   hd0_info[16]; // hd0-disk-parameter from intvector 0x41
  /* 0x090 */ uint8_t   hd1_info[16]; // hd1-disk-parameter from intvector 0x46

  // System description table truncated to 16 bytes
  // From 'struct sys_desc_table_struct' in linux/arch/i386/kernel/setup.c.
  /* 0x0a0 */ uint16_t  sys_description_len;
  /* 0x0a2 */ uint8_t   sys_description_table[14];
                        // [0] machine id
                        // [1] machine submodel id
                        // [2] BIOS revision
                        // [3] bit1: MCA bus

  /* 0x0b0 */ uint8_t   pad3[0x1e0 - 0xb0];
  /* 0x1e0 */ uint32_t  alt_mem_k;
  /* 0x1e4 */ uint8_t   pad4[4];
  /* 0x1e8 */ uint8_t   e820map_entries;
  /* 0x1e9 */ uint8_t   eddbuf_entries; // EDD_NR
  /* 0x1ea */ uint8_t   pad5[0x1f1 - 0x1ea];
  /* 0x1f1 */ uint8_t   setup_sects; // size of setup.S, number of sectors
  /* 0x1f2 */ uint16_t  mount_root_rdonly; // MOUNT_ROOT_RDONLY (if !=0)
  /* 0x1f4 */ uint16_t  sys_size; // size of compressed kernel-part in the
                                // (b)zImage-file (in 16 byte units, rounded up)
  /* 0x1f6 */ uint16_t  swap_dev; // (unused AFAIK)
  /* 0x1f8 */ uint16_t  ramdisk_flags;
  /* 0x1fa */ uint16_t  vga_mode; // (old one)
  /* 0x1fc */ uint16_t  orig_root_dev; // (high=Major, low=minor)
  /* 0x1fe */ uint8_t   pad6[1];
  /* 0x1ff */ uint8_t   aux_device_info;
  /* 0x200 */ uint16_t  jump_setup; // Jump to start of setup code,
                                  // aka "reserved" field.
  /* 0x202 */ uint8_t   setup_signature[4]; // Signature for SETUP-header, ="HdrS"
  /* 0x206 */ uint16_t  header_format_version; // Version number of header format;
  /* 0x208 */ uint8_t   setup_S_temp0[8]; // Used by setup.S for communication with
                                        // boot loaders, look there.
  /* 0x210 */ uint8_t   loader_type;
                        // 0 for old one.
                        // else 0xTV:
                        //   T=0: LILO
                        //   T=1: Loadlin
                        //   T=2: bootsect-loader
                        //   T=3: SYSLINUX
                        //   T=4: ETHERBOOT
                        //   V=version
  /* 0x211 */ uint8_t   loadflags;
                        // bit0 = 1: kernel is loaded high (bzImage)
                        // bit7 = 1: Heap and pointer (see below) set by boot
                        //   loader.
  /* 0x212 */ uint16_t  setup_S_temp1;
  /* 0x214 */ uint32_t  kernel_start;
  /* 0x218 */ uint32_t  initrd_start;
  /* 0x21c */ uint32_t  initrd_size;
  /* 0x220 */ uint8_t   setup_S_temp2[4];
  /* 0x224 */ uint16_t  setup_S_heap_end_pointer;
  /* 0x226 */ uint16_t  pad70;
  /* 0x228 */ uint32_t  cmd_line_ptr;
  /* 0x22c */ uint8_t   pad7[0x2d0 - 0x22c];

  /* 0x2d0 : Int 15, ax=e820 memory map. */
  // (linux/include/asm-i386/e820.h, 'struct e820entry')
#define E820MAX  32
#define E820_RAM  1
#define E820_RESERVED 2
#define E820_ACPI 3 /* usable as RAM once ACPI tables have been read */
#define E820_NVS  4
  struct {
    uint64_t addr;
    uint64_t size;
    uint32_t type;
    } e820map[E820MAX];

  /* 0x550 */ uint8_t   pad8[0x600 - 0x550];

  // BIOS Enhanced Disk Drive Services.
  // (From linux/include/asm-i386/edd.h, 'struct edd_info')
  // Each 'struct edd_info is 78 bytes, times a max of 6 structs in array.
  /* 0x600 */ uint8_t   eddbuf[0x7d4 - 0x600];

  /* 0x7d4 */ uint8_t   pad9[0x800 - 0x7d4];
  /* 0x800 */ uint8_t   commandline[0x800];

  uint64_t gdt_table[3];
};

void setup_linux_config(VirtMachine *s1)
{
    PCMachine *s = (PCMachine *)s1;
    struct linux_params *params;
    
    params = (void *)(s->phys_mem + KERNEL_PARAMS_ADDR);
    
    memset(params, 0, sizeof(struct linux_params));

    strcpy((char *)params->commandline, s->cmd_line);

    params->mount_root_rdonly = 0;
    params->cmd_line_ptr = KERNEL_PARAMS_ADDR +
        offsetof(struct linux_params, commandline);
    params->alt_mem_k = (s->ram_size / 1024) - 1024;
    params->loader_type = 0x01;
#if 0
    if (initrd_size > 0) {
        params->initrd_start = INITRD_LOAD_ADDR;
        params->initrd_size = initrd_size;
    }
#endif
    params->orig_video_lines = 25;
    params->orig_video_cols = 80;
#ifdef USE_KVM
    if (s->kvm_enabled) {
        struct kvm_sregs sregs;
        struct kvm_segment seg;
        struct kvm_regs regs;
        
        /* init flat protected mode */

        if (ioctl(s->vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
            perror("KVM_GET_SREGS");
            exit(1);
        }

        sregs.cr0 |= (1 << 0); /* CR0_PE */
        sregs.gdt.base = KERNEL_PARAMS_ADDR +
            offsetof(struct linux_params, gdt_table);
        sregs.gdt.limit = sizeof(params->gdt_table) - 1;
        
        params->gdt_table[1] = 0x00cf9b000000ffffLL; /* CS */
        params->gdt_table[2] = 0x00cf93000000ffffLL; /* DS */
        
        memset(&seg, 0, sizeof(seg));
        seg.limit = 0xffffffff;
        seg.present = 1;
        seg.db = 1;
        seg.s = 1; /* code/data */
        seg.g = 1; /* 4KB granularity */

        seg.type = 0xb; /* code */
        seg.selector = 1 << 3;
        sregs.cs = seg;

        seg.type = 0x3; /* data */
        seg.selector = 2 << 3;
        sregs.ds = seg;
        sregs.es = seg;
        sregs.fs = seg;
        sregs.gs = seg;
        
        if (ioctl(s->vcpu_fd, KVM_SET_SREGS, &sregs) < 0) {
            perror("KVM_SET_SREGS");
            exit(1);
        }
        
        memset(&regs, 0, sizeof(regs));
        regs.rip = KERNEL_LOAD_ADDR;
        regs.rsi = KERNEL_PARAMS_ADDR;
        regs.rflags = 0x2;
        if (ioctl(s->vcpu_fd, KVM_SET_REGS, &regs) < 0) {
            perror("KVM_SET_REGS");
            exit(1);
        }
    } else
#endif
    {
        x86_cpu_set_reg(s->cpu_state, X86_CPU_REG_EIP, KERNEL_LOAD_ADDR);
        x86_cpu_set_reg(s->cpu_state, 6, KERNEL_PARAMS_ADDR); /* esi */
    }
}

/* in ms */
int virt_machine_get_sleep_duration(VirtMachine *s1, int delay)
{
    PCMachine *s = (PCMachine *)s1;

#ifdef USE_KVM
    if (s->kvm_enabled) {
        /* XXX: improve */
        delay = 0;
    } else
#endif
    {
        delay = min_int(delay, pit_update_irq(s->pit_state));
        if (!x86_cpu_get_power_down(s->cpu_state))
            delay = 0;
    }
    return delay;
}

void virt_machine_interp(VirtMachine *s1, int max_exec_cycles)
{
    PCMachine *s = (PCMachine *)s1;
#ifdef USE_KVM
    if (s->kvm_enabled) {
        kvm_exec(s);
    } else 
#endif
    {
        x86_cpu_interp(s->cpu_state, max_exec_cycles);
    }
}
