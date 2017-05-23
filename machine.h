/*
 * VM definitions
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

#define MAX_DRIVE_DEVICE 4
#define MAX_FS_DEVICE 4

typedef struct {
    uint64_t ram_size;
    BOOL rtc_real_time;
    CharacterDevice *console;
    BlockDevice *tab_drive[MAX_DRIVE_DEVICE];
    int drive_count;
    EthernetDevice *net;
    FSDevice *tab_fs[MAX_FS_DEVICE];
    int fs_count;
    char *cmdline; /* kernel command line */
    BOOL accel_enable; /* enable acceleration (KVM) */
} VirtMachineParams;

typedef struct VirtMachine {
    /* network */
    VIRTIODevice *net_dev;
    EthernetDevice *net;
    /* console */
    VIRTIODevice *console_dev;
    CharacterDevice *console;
} VirtMachine;

void virt_machine_set_defaults(VirtMachineParams *p);
VirtMachine *virt_machine_init(const VirtMachineParams *p);
void virt_machine_end(VirtMachine *s);
void copy_kernel(VirtMachine *s, const uint8_t *buf, int buf_len);
int virt_machine_get_sleep_duration(VirtMachine *s, int delay);
void virt_machine_interp(VirtMachine *s, int max_exec_cycle);
void setup_linux_config(VirtMachine *s1);
