/*
 * VM mouse emulation
 * 
 * Copyright (c) 2017 Fabrice Bellard
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
#include <string.h>
#include <inttypes.h>
#include <assert.h>

#include "cutils.h"
#include "iomem.h"
#include "ps2.h"

#define VMPORT_MAGIC   0x564D5868

#define REG_EAX 0
#define REG_EBX 1
#define REG_ECX 2
#define REG_EDX 3
#define REG_ESI 4
#define REG_EDI 5

#define FIFO_SIZE (4 * 16)

struct VMMouseState {
    PS2MouseState *ps2_mouse;
    int fifo_count, fifo_rindex, fifo_windex;
    BOOL enabled;
    BOOL absolute;
    uint32_t fifo_buf[FIFO_SIZE];
};

static void put_queue(VMMouseState *s, uint32_t val)
{
    if (s->fifo_count >= FIFO_SIZE)
        return;
    s->fifo_buf[s->fifo_windex] = val;
    if (++s->fifo_windex == FIFO_SIZE)
        s->fifo_windex = 0;
    s->fifo_count++;
}

static void read_data(VMMouseState *s, uint32_t *regs, int size)
{
    int i;
    if (size > 6 || size > s->fifo_count) {
        //        printf("vmmouse: read error req=%d count=%d\n", size, s->fifo_count);
        s->enabled = FALSE;
        return;
    }
    for(i = 0; i < size; i++) {
        regs[i] = s->fifo_buf[s->fifo_rindex];
        if (++s->fifo_rindex == FIFO_SIZE)
            s->fifo_rindex = 0;
    }
    s->fifo_count -= size;
}

void vmmouse_send_mouse_event(VMMouseState *s, int x, int y, int dz,
                              int buttons)
{
    int state;

    if (!s->enabled) {
        ps2_mouse_event(s->ps2_mouse, x, y, dz, buttons);
        return;
    }

    if ((s->fifo_count + 4) > FIFO_SIZE)
        return;

    state = 0;
    if (buttons & 1)
        state |= 0x20;
    if (buttons & 2)
        state |= 0x10;
    if (buttons & 4)
        state |= 0x08;
    if (s->absolute) {
        /* range = 0 ... 65535 */
        x *= 2; 
        y *= 2;
    }

    put_queue(s, state);
    put_queue(s, x);
    put_queue(s, y);
    put_queue(s, -dz);

    /* send PS/2 mouse event */
    ps2_mouse_event(s->ps2_mouse, 1, 0, 0, 0);
}

void vmmouse_handler(VMMouseState *s, uint32_t *regs)
{
    uint32_t cmd;
    
    cmd = regs[REG_ECX] & 0xff;
    switch(cmd) {
    case 10: /* get version */
        regs[REG_EBX] = VMPORT_MAGIC;
        break;
    case 39: /* VMMOUSE_DATA */
        read_data(s, regs, regs[REG_EBX]);
        break;
    case 40: /* VMMOUSE_STATUS */
        regs[REG_EAX] = ((s->enabled ? 0 : 0xffff) << 16) | s->fifo_count;
        break;
    case 41: /* VMMOUSE_COMMAND */
        switch(regs[REG_EBX]) {
        case 0x45414552: /* read id */
            if (s->fifo_count < FIFO_SIZE) {
                put_queue(s, 0x3442554a);
                s->enabled = TRUE;
            }
            break;
        case 0x000000f5: /* disable */
            s->enabled = FALSE;
            break;
        case 0x4c455252: /* set relative */
            s->absolute = 0;
            break;
        case 0x53424152: /* set absolute */
            s->absolute = 1;
            break;
        }
        break;
    }
}

BOOL vmmouse_is_absolute(VMMouseState *s)
{
    return s->absolute;
}

VMMouseState *vmmouse_init(PS2MouseState *ps2_mouse)
{
    VMMouseState *s;
    s = mallocz(sizeof(*s));
    s->ps2_mouse = ps2_mouse;
    return s;
}
