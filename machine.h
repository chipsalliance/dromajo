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
#include "json.h"

typedef struct FBDevice FBDevice;

typedef void SimpleFBDrawFunc(FBDevice *fb_dev, void *opaque,
                              int x, int y, int w, int h);

struct FBDevice {
    /* the following is set by the device */
    int width;
    int height;
    int stride; /* current stride in bytes */
    uint8_t *fb_data; /* current pointer to the pixel data */
    int fb_size; /* frame buffer memory size (info only) */
    void *device_opaque;
    void (*refresh)(struct FBDevice *fb_dev,
                    SimpleFBDrawFunc *redraw_func, void *opaque);
};

#define MAX_DRIVE_DEVICE 4
#define MAX_FS_DEVICE 4
#define MAX_ETH_DEVICE 1

#define VM_CONFIG_VERSION 1

typedef enum {
    VM_FILE_BIOS,
    VM_FILE_VGA_BIOS,
    VM_FILE_KERNEL,
    VM_FILE_INITRD,

    VM_FILE_COUNT,
} VMFileTypeEnum;

typedef struct {
    char *filename;
    uint8_t *buf;
    int len;
} VMFileEntry;

typedef struct {
    char *device;
    char *filename;
    BlockDevice *block_dev;
} VMDriveEntry;

typedef struct {
    char *device;
    char *tag; /* 9p mount tag */
    char *filename;
    FSDevice *fs_dev;
} VMFSEntry;

typedef struct {
    char *driver;
    char *ifname;
    EthernetDevice *net;
} VMEthEntry;

typedef struct VirtMachineClass VirtMachineClass;

typedef struct {
    char *cfg_filename;
    const VirtMachineClass *vmc;
    char *machine_name;
    uint64_t ram_size;
    BOOL rtc_real_time;
    BOOL rtc_local_time;
    char *display_device; /* NULL means no display */
    int width, height; /* graphic width & height */
    CharacterDevice *console;
    VMDriveEntry tab_drive[MAX_DRIVE_DEVICE];
    int drive_count;
    VMFSEntry tab_fs[MAX_FS_DEVICE];
    int fs_count;
    VMEthEntry tab_eth[MAX_ETH_DEVICE];
    int eth_count;

    char *cmdline; /* bios or kernel command line */
    BOOL accel_enable; /* enable acceleration (KVM) */
    char *input_device; /* NULL means no input */
    
    /* kernel, bios and other auxiliary files */
    VMFileEntry files[VM_FILE_COUNT];
} VirtMachineParams;

typedef struct VirtMachine {
    const VirtMachineClass *vmc;
    /* network */
    EthernetDevice *net;
    /* console */
    VIRTIODevice *console_dev;
    CharacterDevice *console;
    /* graphics */
    FBDevice *fb_dev;
} VirtMachine;

struct VirtMachineClass {
    const char *machine_names;
    void (*virt_machine_set_defaults)(VirtMachineParams *p);
    VirtMachine *(*virt_machine_init)(const VirtMachineParams *p);
    void (*virt_machine_end)(VirtMachine *s);
    int (*virt_machine_get_sleep_duration)(VirtMachine *s, int delay);
    void (*virt_machine_interp)(VirtMachine *s, int max_exec_cycle);
    BOOL (*vm_mouse_is_absolute)(VirtMachine *s);
    void (*vm_send_mouse_event)(VirtMachine *s1, int dx, int dy, int dz,
                                unsigned int buttons);
    void (*vm_send_key_event)(VirtMachine *s1, BOOL is_down, uint16_t key_code);
};

extern const VirtMachineClass riscv_machine_class;
extern const VirtMachineClass pc_machine_class;

void __attribute__((format(printf, 1, 2))) vm_error(const char *fmt, ...);
int vm_get_int(JSONValue obj, const char *name, int *pval);
int vm_get_int_opt(JSONValue obj, const char *name, int *pval, int def_val);

void virt_machine_set_defaults(VirtMachineParams *p);
void virt_machine_load_config_file(VirtMachineParams *p,
                                   const char *filename,
                                   void (*start_cb)(void *opaque),
                                   void *opaque);
void vm_add_cmdline(VirtMachineParams *p, const char *cmdline);
char *get_file_path(const char *base_filename, const char *filename);
void virt_machine_free_config(VirtMachineParams *p);
VirtMachine *virt_machine_init(const VirtMachineParams *p);
void virt_machine_end(VirtMachine *s);
static inline int virt_machine_get_sleep_duration(VirtMachine *s, int delay)
{
    return s->vmc->virt_machine_get_sleep_duration(s, delay);
}
static inline void virt_machine_interp(VirtMachine *s, int max_exec_cycle)
{
    s->vmc->virt_machine_interp(s, max_exec_cycle);
}
static inline BOOL vm_mouse_is_absolute(VirtMachine *s)
{
    return s->vmc->vm_mouse_is_absolute(s);
}
static inline void vm_send_mouse_event(VirtMachine *s1, int dx, int dy, int dz,
                                       unsigned int buttons)
{
    s1->vmc->vm_send_mouse_event(s1, dx, dy, dz, buttons);
}
static inline void vm_send_key_event(VirtMachine *s1, BOOL is_down, uint16_t key_code)
{
    s1->vmc->vm_send_key_event(s1, is_down, key_code);
}

/* gui */
void sdl_refresh(VirtMachine *m);
void sdl_init(int width, int height);

/* simplefb.c */
typedef struct SimpleFBState SimpleFBState;
SimpleFBState *simplefb_init(PhysMemoryMap *map, uint64_t phys_addr,
                             FBDevice *fb_dev, int width, int height);
void simplefb_refresh(FBDevice *fb_dev,
                      SimpleFBDrawFunc *redraw_func, void *opaque,
                      PhysMemoryRange *mem_range,
                      int fb_page_count);

/* vga.c */
typedef struct VGAState VGAState;
VGAState *pci_vga_init(PCIBus *bus, FBDevice *fb_dev,
                       int width, int height,
                       const uint8_t *vga_rom_buf, int vga_rom_size);
                      
/* block_net.c */
BlockDevice *block_device_init_http(const char *url,
                                    int max_cache_size_kb,
                                    void (*start_cb)(void *opaque),
                                    void *start_opaque);
