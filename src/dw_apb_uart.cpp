/*
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
 */
#include "dw_apb_uart.h"

#include <assert.h>
#include <stdio.h>

enum {
    uart_reg_rhr = 0,  // R: Receiver / W: Transmitter Holding Register
    uart_reg_ier = 1,  // Interrupt Enable Register
    uart_reg_isr = 2,  // R: Interrupt Status Register / W: FIFO Control
    uart_reg_lcr = 3,
    uart_reg_mcr = 4,
    uart_reg_lsr = 5,  // R: Line Status Register
    uart_reg_msr = 6,
    uart_reg_spr = 7,
};

const char *reg_name_r[10] = {
    "RHR", "IER", "ISR", "LCR", "MCR", "LSR", "MSR", "SPR", "DLL", "DLM"};
const char *reg_name_w[10] = {
    "THR", "IER", "FCR", "LCR", "MCR", "?ls", "?ms", "SPR", "DLL", "DLM"};

/* Configuration parameters at hardware instantiation time (only includes features relevant to sim) */
#define FEATURE_FIFO_MODE                  64
#define FEATURE_REG_TIMEOUT_WIDTH          4
#define FEATURE_HC_REG_TIMEOUT_VALUE       0
#define FEATURE_REG_TIMEOUT_VALUE          8
#define FEATURE_UART_RS485_INTERFACE_EN    0
#define FEATURE_UART_9BIT_DATA_EN          0
#define FEATURE_APB_DATA_WIDTH             32
#define FEATURE_MEM_SELECT_USER            1  // == internal
#define FEATURE_SIR_MODE                   0  // disabled
#define FEATURE_AFCE_MODE                  0
#define FEATURE_THRE_MODE_USER             1  // enabled
#define FEATURE_FIFO_ACCESS                1  // programmable FIFOQ access mode enabled
#define FEATURE_ADDITIONAL_FEATURES        1
#define FEATURE_FIFO_STAT                  1
#define FEATURE_SHADOW                     1
#define FEATURE_UART_ADD_ENCODED_PARAMS    1
#define FEATURE_UART_16550_COMPATIBLE      0
#define FEATURE_FRACTIONAL_BAUD_DIVISOR_EN 1
#define FEATURE_DLF_SIZE                   4
#define FEATURE_LSR_STATUS_CLEAR           0  // Both RBR Read and LSR Read clears OE, PE, FE, and BI

//#define DEBUG(fmt...) fprintf(stderr, fmt)
#define DEBUG(fmt...) (void)0

#define UART_IER_RDI  1  // Enable receiver data interrupt
#define UART_IER_THRI 2  // Enable Transmitter holding register int
#define UART_IER_RLSI 4  // Enable receiver line status interrupt
#define UART_IER_MSI  8  // Enable Modem status interrupt

#define UART_LSR_RXRDY     0x01
#define UART_LSR_RXOVERE   0x02
#define UART_LSR_RXPARITYE 0x04
#define UART_LSR_RXFRAMEE  0x08
#define UART_LSR_RXBREAK   0x10
#define UART_LSR_THREMPTY  0x20
#define UART_LSR_TXEMPTY   0x40
#define UART_LSR_FIFOE     0x80

void dw_apb_uart_poll(void *opaque);

static void update_isr(DW_apb_uart_state *s) {
    /*
      Level 1 (max.)   - Receiver Line Status
      Level 2          - Received Data Ready
                       - Reception Timeout
      Level 3          - Transmitter Holding Reg. Empty
      Level 4          - Modem Status
      Level 5          - DMA Reception End of Transfer
      Level 6 (min.)   - DMA Transmission End of Trans.
    */

    int isr_nibble;

    /* Priority 1 Receiver Line Status */
    if ((s->ier & 4) && (s->lsr & 30))  // BrkInt + FrameEr + ParityEr + OverrunEr
        isr_nibble = 6;

    /* Priority 2 Received Data Ready */
    else if ((s->ier & 1) && (s->lsr & 1))
        isr_nibble = 4;

    /* Priority 2 Received Timeout (Can't happen w/o a FIFO?) */
    // else if (0)
    //    isr_nibble = 12;

    /* Priority 3 Transmitter Holding Register Empty */
    else if ((s->ier & 2) && (s->lsr & 32))
        isr_nibble = 2;

    /* Priority 4 Modem Status */
    else if ((s->ier & 8) && (s->msr & 15) != 15)
        isr_nibble = 0;

    else
        isr_nibble = 1;  // No Interrupt

    /* Priority 5 DMA Reception End of Transfer XXX Not implemented */
    /* Priority 6 DMA Transmission End of Transfer  XXX Not implemented */

    s->isr = (s->isr & 0xF0) + isr_nibble;

    unsigned irq_level = !(s->isr & 1);

    /* set_irq is a non-trivial call and there's no need to call it
       again unless the state changed. */
    if (s->last_irq_level != irq_level) {
        DEBUG("##ISR %02x, irq level %d\n", s->isr, irq_level);
        s->last_irq_level = irq_level;
        set_irq(s->irq, irq_level);
    }
}

/* Read the Receiver Holding Register (0) */
static uint8_t read_rhr(DW_apb_uart_state *s) {
    if (s->lcr & (1 << 7)) {
        return s->div_latch & 255;
    }

    uint8_t res = s->rhr;
    s->lsr &= ~(1 << 0);
    if (FEATURE_LSR_STATUS_CLEAR == 0)
        s->lsr &= ~30;  // Reading clears BI, FE, PE, OE
    update_isr(s);
    return res;
}

/* Write the Transmitter Holding Register (0) */
static void write_thr(DW_apb_uart_state *s, uint8_t val) {
    if (s->lcr & (1 << 7)) {
        s->div_latch = (s->div_latch & ~255) + val;
    } else {
        CharacterDevice *cs = s->cs;
        unsigned char    ch = val;
        // DEBUG("{<   TRANSMIT '%c' (0x%02x)>}", val, val);
        cs->write_data(cs->opaque, &ch, 1);
        s->lsr &= ~((1 << 5) | (1 << 6));
        update_isr(s);
        dw_apb_uart_poll(s);
    }
}

/* Read the Interrupt Enable Register (1) */
static uint8_t read_ier(DW_apb_uart_state *s) {
    if (s->lcr & (1 << 7)) {
        return s->div_latch >> 8;
    }
    return s->ier;
}

/* Write the Interrupt Enable Register (1) */
static void write_ier(DW_apb_uart_state *s, uint8_t val) {
    if (s->lcr & (1 << 7)) {
        s->div_latch = (s->div_latch & 255) + val * 256;
    } else {
        s->ier = val & (FEATURE_THRE_MODE_USER ? 0xFF : 0x7F);
        update_isr(s);
    }
}

/* Read the Interrupt Status Register (2) */
static uint8_t read_isr(DW_apb_uart_state *s) {
    uint8_t res = s->isr;
    // XXX Side effects?
    return res;
}

/* Write the FIFO Control Register (2) */
static void write_fcr(DW_apb_uart_state *s, uint8_t val) {
    // s->fcr = val; Not implemented
}

/* Read the Line Control Register (3) */
static uint8_t read_lcr(DW_apb_uart_state *s) {
    uint8_t res = s->lcr;
    // XXX Side effects?
    return res;
}

/* Write the Line Control Register (3) */
static void write_lcr(DW_apb_uart_state *s, uint8_t val) { s->lcr = val; }

/* Read the Modem Control Register (4) */
static uint8_t read_mcr(DW_apb_uart_state *s) {
    uint8_t res = s->mcr;
    // XXX Side effects?
    return res;
}

/* Write the Modem Control Register (4) */
static void write_mcr(DW_apb_uart_state *s, uint8_t val) { s->mcr = val; }

/* Read the Line Control Register (5) and clear some bits */
static uint8_t read_lsr(DW_apb_uart_state *s) {
    s->lsr |= (1 << 6) | (1 << 5);  // TX empty, Holding Empty
    // uint8_t res = s->lsr;
    // b0 cleared by reading RHR
    // b5 and b6 cleared by writing THR (but we cheat and set them always)
    s->lsr &= ~((1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 7));
    dw_apb_uart_poll(s);
    update_isr(s);

    return s->lsr;
}

/* No write of the Line Control Register (5) */

/* Read the Modem Status Register (6) and clear some bits */
static uint8_t read_msr(DW_apb_uart_state *s) {
    uint8_t res = s->msr;

    s->msr &= ~15;
    update_isr(s);

    return res;
}

/* No write of the Modem Status Register (6) */

/* Read the Scratch Pad Register (7) */
static uint8_t read_spr(DW_apb_uart_state *s) { return s->spr; }

/* Write the Scratch Pad Register (7) */
static void write_spr(DW_apb_uart_state *s, uint8_t val) { s->spr = val; }

void dw_apb_uart_poll(void *opaque) {
    DW_apb_uart_state *s = (DW_apb_uart_state *)opaque;

    if (!(s->lsr & 1)) {
        CharacterDevice *cs = s->cs;
        s->lsr |= cs->read_data(cs->opaque, &s->rhr, 1) != 0;
        update_isr(s);
    }
}

uint32_t dw_apb_uart_read(void *opaque, uint32_t offset, int size_log2) {
    DW_apb_uart_state *s   = (DW_apb_uart_state *)opaque;
    int                res = 0;

    if (offset % 4 != 0 || 256 < offset)
        DEBUG("##R offset = %d\n", offset);

    assert(offset % 4 == 0);
    assert(offset < 256);

    offset /= 4;

    switch (offset) {
        case uart_reg_rhr: res = read_rhr(s); break;
        case uart_reg_ier: res = read_ier(s); break;
        case uart_reg_isr: res = read_isr(s); break;
        case uart_reg_lcr: res = read_lcr(s); break;
        case uart_reg_mcr: res = read_mcr(s); break;
        case uart_reg_lsr: res = read_lsr(s); break;
        case uart_reg_msr: res = read_msr(s); break;
        case uart_reg_spr: res = read_spr(s); break;
        default:;
    }

    static uint32_t last_offset = 0xAAAA5555;
    static int      last_res    = 0x5555AAAA;

    if (offset != last_offset || res != last_res) {
        if (offset < 8) {
            int i = offset + ((offset < 2) && ((s->lcr >> 7) & 1)) * 8;
            (void)i;
            //if (offset != uart_reg_lsr)
            DEBUG("##%s->%02x\n", reg_name_r[i], res);
        } else {
            DEBUG("##0x%x->%02x\n", offset, res);
        }

        last_offset = offset;
        last_res    = res;
    }



    return res;
}

void dw_apb_uart_write(void *opaque, uint32_t offset, uint32_t val, int size_log2) {
    DW_apb_uart_state *s = (DW_apb_uart_state *)opaque;

    val &= 255;

    if (offset % 4 != 0 || 256 < offset)
        DEBUG("##W offset = %d\n", offset);

    assert(offset % 4 == 0);
    assert(offset < 256);

    offset /= 4;

    static uint32_t last = 0xAAAA5555;

    if (offset != last) {
        if (offset < 8) {
            int i = offset + ((offset < 2) && ((s->lcr >> 7) & 1)) * 8;
            (void)i;
            DEBUG("##%s<-%02x\n", reg_name_w[i], val);
        } else {
            DEBUG("##0x%x<-%02x\n", offset, val);
        }
        last = offset;
    }

    switch (offset) {
        case uart_reg_rhr: write_thr(s, val); break;
        case uart_reg_ier: write_ier(s, val); break;
        case uart_reg_isr: write_fcr(s, val); break;
        case uart_reg_lcr: write_lcr(s, val); break;
        case uart_reg_mcr: write_mcr(s, val); break;
        // case uart_reg_lsr: write_lsr(s, val); break;
        // case uart_reg_msr: write_msr(s, val); break;
        case uart_reg_spr: write_spr(s, val); break;
        default:; DEBUG("##ignored write\n"); break;
    }
}
