/*
 * JS emulator main
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
#include <emscripten.h>

#include "cutils.h"
#include "iomem.h"
#include "virtio.h"
#include "machine.h"
#include "list.h"
#include "fbuf.h"

void virt_machine_run(void *opaque);

/* provided in lib.js */
extern void console_write(void *opaque, const uint8_t *buf, int len);
extern void console_get_size(int *pw, int *ph);
extern void fb_refresh(void *opaque, void *data,
                       int x, int y, int w, int h, int stride);
extern void net_recv_packet(EthernetDevice *bs,
                            const uint8_t *buf, int len);

static uint8_t console_fifo[1024];
static int console_fifo_windex;
static int console_fifo_rindex;
static int console_fifo_count;
static BOOL console_resize_pending;

static int global_width;
static int global_height;
static VirtMachine *global_vm;
static BOOL global_carrier_state;

static int console_read(void *opaque, uint8_t *buf, int len)
{
    int out_len, l;
    len = min_int(len, console_fifo_count);
    console_fifo_count -= len;
    out_len = 0;
    while (len != 0) {
        l = min_int(len, sizeof(console_fifo) - console_fifo_rindex);
        memcpy(buf + out_len, console_fifo + console_fifo_rindex, l);
        len -= l;
        out_len += l;
        console_fifo_rindex += l;
        if (console_fifo_rindex == sizeof(console_fifo))
            console_fifo_rindex = 0;
    }
    return out_len;
}

/* called from JS */
void console_queue_char(int c)
{
    if (console_fifo_count < sizeof(console_fifo)) {
        console_fifo[console_fifo_windex] = c;
        if (++console_fifo_windex == sizeof(console_fifo))
            console_fifo_windex = 0;
        console_fifo_count++;
    }
}

/* called from JS */
void display_key_event(int is_down, int key_code)
{
    if (global_vm) {
        vm_send_key_event(global_vm, is_down, key_code);
    }
}

/* called from JS */
static int mouse_last_x, mouse_last_y, mouse_last_buttons;

void display_mouse_event(int dx, int dy, int buttons)
{
    if (global_vm) {
        if (vm_mouse_is_absolute(global_vm) || 1) {
            dx = min_int(dx, global_width - 1);
            dy = min_int(dy, global_height - 1);
            dx = (dx * VIRTIO_INPUT_ABS_SCALE) / global_width;
            dy = (dy * VIRTIO_INPUT_ABS_SCALE) / global_height;
        } else {
            /* relative mouse is not supported */
            dx = 0;
            dy = 0;
        }
        mouse_last_x = dx;
        mouse_last_y = dy;
        mouse_last_buttons = buttons;
        vm_send_mouse_event(global_vm, dx, dy, 0, buttons);
    }
}

/* called from JS */
void display_wheel_event(int dz)
{
    if (global_vm) {
        vm_send_mouse_event(global_vm, mouse_last_x, mouse_last_y, dz,
                            mouse_last_buttons);
    }
}

/* called from JS */
void net_write_packet(const uint8_t *buf, int buf_len)
{
    EthernetDevice *net = global_vm->net;
    if (net) {
        net->device_write_packet(net, buf, buf_len);
    }
}

/* called from JS */
void net_set_carrier(BOOL carrier_state)
{
    EthernetDevice *net;
    global_carrier_state = carrier_state;
    if (global_vm && global_vm->net) {
        net = global_vm->net;
        net->device_set_carrier(net, carrier_state);
    }
}

static void fb_refresh1(FBDevice *fb_dev, void *opaque,
                        int x, int y, int w, int h)
{
    int stride = fb_dev->stride;
    fb_refresh(opaque, fb_dev->fb_data + y * stride + x * 4, x, y, w, h,
               stride);
}

static CharacterDevice *console_init(void)
{
    CharacterDevice *dev;
    console_resize_pending = TRUE;
    dev = mallocz(sizeof(*dev));
    dev->write_data = console_write;
    dev->read_data = console_read;
    return dev;
}

typedef struct {
    VirtMachineParams *p;
    int ram_size;
    char *cmdline;
    BOOL has_network;
    char *pwd;
} VMStartState;

static void init_vm(void *arg);
static void init_vm_fs(void *arg);
static void init_vm_drive(void *arg);

void vm_start(const char *url, int ram_size, const char *cmdline,
              const char *pwd, int width, int height, BOOL has_network)
{
    VMStartState *s;

    s = mallocz(sizeof(*s));
    s->ram_size = ram_size;
    s->cmdline = strdup(cmdline);
    if (pwd)
        s->pwd = strdup(pwd);
    global_width = width;
    global_height = height;
    s->has_network = has_network;
    s->p = mallocz(sizeof(VirtMachineParams));
    virt_machine_set_defaults(s->p);
    virt_machine_load_config_file(s->p, url, init_vm_fs, s);
}

static void init_vm_fs(void *arg)
{
    VMStartState *s = arg;
    VirtMachineParams *p = s->p;

    if (p->fs_count > 0) {
        assert(p->fs_count == 1);
        p->tab_fs[0].fs_dev = fs_net_init(p->tab_fs[0].filename,
                                          init_vm_drive, s);
        if (s->pwd) {
            fs_net_set_pwd(p->tab_fs[0].fs_dev, s->pwd);
        }
    } else {
        init_vm_drive(s);
    }
}

static void init_vm_drive(void *arg)
{
    VMStartState *s = arg;
    VirtMachineParams *p = s->p;

    if (p->drive_count > 0) {
        assert(p->drive_count == 1);
        p->tab_drive[0].block_dev =
            block_device_init_http(p->tab_drive[0].filename,
                                   131072,
                                   init_vm, s);
    } else {
        init_vm(s);
    }
}

static void init_vm(void *arg)
{
    VMStartState *s = arg;
    VirtMachine *m;
    VirtMachineParams *p = s->p;
    int i;
    
    p->rtc_real_time = TRUE;
    p->ram_size = s->ram_size << 20;
    if (s->cmdline && s->cmdline[0] != '\0') {
        vm_add_cmdline(s->p, s->cmdline);
    }

    if (global_width > 0 && global_height > 0) {
        /* enable graphic output if needed */
        if (!p->display_device)
            p->display_device = strdup("simplefb");
        p->width = global_width;
        p->height = global_height;
    } else {
        p->console = console_init();
    }
    
    if (p->eth_count > 0 && !s->has_network) {
        /* remove the interfaces */
        for(i = 0; i < p->eth_count; i++) {
            free(p->tab_eth[i].ifname);
            free(p->tab_eth[i].driver);
        }
        p->eth_count = 0;
    }

    if (p->eth_count > 0) {
        EthernetDevice *net;
        int i;
        assert(p->eth_count == 1);
        net = mallocz(sizeof(EthernetDevice));
        net->mac_addr[0] = 0x02;
        for(i = 1; i < 6; i++)
            net->mac_addr[i] = (int)(emscripten_random() * 256);
        net->write_packet = net_recv_packet;
        net->opaque = NULL;
        p->tab_eth[0].net = net;
    }

    m = virt_machine_init(p);
    global_vm = m;

    virt_machine_free_config(s->p);

    if (m->net) {
        m->net->device_set_carrier(m->net, global_carrier_state);
    }
    
    free(s->p);
    free(s->cmdline);
    if (s->pwd) {
        memset(s->pwd, 0, strlen(s->pwd));
        free(s->pwd);
    }
    free(s);
    
    emscripten_async_call(virt_machine_run, m, 0);
}

/* need to be long enough to hide the non zero delay of setTimeout(_, 0) */
#define MAX_EXEC_TOTAL_CYCLE 3000000
#define MAX_EXEC_CYCLE        200000

#define MAX_SLEEP_TIME 10 /* in ms */

void virt_machine_run(void *opaque)
{
    VirtMachine *m = opaque;
    int delay, i;
    FBDevice *fb_dev;
    
    if (m->console_dev && virtio_console_can_write_data(m->console_dev)) {
        uint8_t buf[128];
        int ret, len;
        len = virtio_console_get_write_len(m->console_dev);
        len = min_int(len, sizeof(buf));
        ret = m->console->read_data(m->console->opaque, buf, len);
        if (ret > 0)
            virtio_console_write_data(m->console_dev, buf, ret);
        if (console_resize_pending) {
            int w, h;
            console_get_size(&w, &h);
            virtio_console_resize_event(m->console_dev, w, h);
            console_resize_pending = FALSE;
        }
    }

    fb_dev = m->fb_dev;
    if (fb_dev) {
        /* refresh the display */
        fb_dev->refresh(fb_dev, fb_refresh1, NULL);
    }
    
    i = 0;
    for(;;) {
        /* wait for an event: the only asynchronous event is the RTC timer */
        delay = virt_machine_get_sleep_duration(m, MAX_SLEEP_TIME);
        if (delay != 0 || i >= MAX_EXEC_TOTAL_CYCLE / MAX_EXEC_CYCLE)
            break;
        virt_machine_interp(m, MAX_EXEC_CYCLE);
        i++;
    }
    
    if (delay == 0) {
        emscripten_async_call(virt_machine_run, m, 0);
    } else {
        emscripten_async_call(virt_machine_run, m, MAX_SLEEP_TIME);
    }
}

