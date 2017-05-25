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

void virt_machine_run(void *opaque);

static uint8_t console_fifo[1024];
static int console_fifo_windex;
static int console_fifo_rindex;
static int console_fifo_count;
static BOOL console_resize_pending;

/* provided in lib.js */
extern void console_write(void *opaque, const uint8_t *buf, int len);
extern void console_get_size(int *pw, int *ph);

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
    console_resize_pending = TRUE;
    dev = mallocz(sizeof(*dev));
    dev->write_data = console_write;
    dev->read_data = console_read;
    return dev;
}

static void init_vm(void *arg);

static FSDevice *global_fs;
static char *global_cmdline;
static int global_ram_size;

void vm_start(const char *url, int ram_size, const char *cmdline,
              const char *pwd)
{
    global_ram_size = ram_size;
    global_fs = fs_net_init(url, init_vm, NULL);
    if (pwd) {
        fs_net_set_pwd(global_fs, pwd);
    }
    global_cmdline = strdup(cmdline);
}

static void init_vm(void *arg)
{
    VirtMachine *s;
    uint8_t *kernel_buf;
    int kernel_size;
    VirtMachineParams p_s, *p = &p_s;
    
    virt_machine_set_defaults(p);

    p->console = console_init();
    p->rtc_real_time = TRUE;
    p->ram_size = global_ram_size << 20;
    p->tab_fs[0] = global_fs;
    p->fs_count = 1;
    p->cmdline = global_cmdline;
        
    s = virt_machine_init(p);

    free(global_cmdline);
    
    /* load the kernel to memory */
    kernel_size = fs_net_get_file(global_fs, &kernel_buf, "kernel.bin");
    assert(kernel_size > 0);
    copy_kernel(s, kernel_buf, kernel_size);

    setup_linux_config(s);

    emscripten_async_call(virt_machine_run, s, 0);
}

/* need to be long enough to hide the non zero delay of setTimeout(_, 0) */
#define MAX_EXEC_TOTAL_CYCLE 3000000
#define MAX_EXEC_CYCLE        200000

#define MAX_SLEEP_TIME 10 /* in ms */

void virt_machine_run(void *opaque)
{
    VirtMachine *m = opaque;
    int delay, i;
    
    if (virtio_console_can_write_data(m->console_dev)) {
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

    for(i = 0; i < MAX_EXEC_TOTAL_CYCLE / MAX_EXEC_CYCLE; i++) {
        /* wait for an event: the only asynchronous event is the RTC timer */
        delay = virt_machine_get_sleep_duration(m, MAX_SLEEP_TIME);
        if (delay != 0)
            break;
        virt_machine_interp(m, MAX_EXEC_CYCLE);
    }
    
    if (delay == 0) {
        emscripten_async_call(virt_machine_run, m, 0);
    } else {
        emscripten_async_call(virt_machine_run, m, MAX_SLEEP_TIME);
    }
}

