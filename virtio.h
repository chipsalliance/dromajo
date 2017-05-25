/*
 * VIRTIO driver
 * 
 * Copyright (c) 2016 Fabrice Bellard
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
#ifndef VIRTIO_H
#define VIRTIO_H

#define VIRTIO_PAGE_SIZE 4096

#if defined(EMSCRIPTEN)
#define VIRTIO_ADDR_BITS 32
#else
#define VIRTIO_ADDR_BITS 64
#endif

#if VIRTIO_ADDR_BITS == 64
typedef uint64_t virtio_phys_addr_t;
#else
typedef uint32_t virtio_phys_addr_t;
#endif

typedef void VIRTIOSetIrqFunc(void *opaque, int irq_num, int state);
/* return NULL if no RAM at this address. The mapping is valid for one page */
typedef uint8_t *VIRTIOGetRAMPtrFunc(void *opaque, virtio_phys_addr_t paddr);

typedef struct VIRTIODevice VIRTIODevice; 

#define VIRTIO_DEBUG_IO (1 << 0)
#define VIRTIO_DEBUG_9P (1 << 1)

void virtio_set_debug(VIRTIODevice *s, int debug_flags);
uint32_t virtio_mmio_read(VIRTIODevice *s, uint32_t offset, int size_log2);
void virtio_mmio_write(VIRTIODevice *s, uint32_t offset, uint32_t val, int size_log2);

/* block device */

typedef void BlockDeviceCompletionFunc(void *opaque);

typedef struct BlockDevice BlockDevice;

struct BlockDevice {
    int64_t (*get_sector_count)(BlockDevice *bs);
    int (*read_async)(BlockDevice *bs,
                      uint64_t sector_num, uint8_t *buf, int n,
                      BlockDeviceCompletionFunc *cb, void *opaque);
    int (*write_async)(BlockDevice *bs,
                       uint64_t sector_num, const uint8_t *buf, int n,
                       BlockDeviceCompletionFunc *cb, void *opaque);
    void *opaque;
};

VIRTIODevice *virtio_block_init(VIRTIOSetIrqFunc *set_irq, int irq_num,
                                VIRTIOGetRAMPtrFunc *get_ram_ptr,
                                void *host_opaque, BlockDevice *bs);

/* network device */

typedef struct EthernetDevice EthernetDevice; 

struct EthernetDevice {
    void (*write_packet)(EthernetDevice *bs,
                         const uint8_t *buf, int len);
    void *opaque;
};

VIRTIODevice *virtio_net_init(VIRTIOSetIrqFunc *set_irq, int irq_num,
                              VIRTIOGetRAMPtrFunc *get_ram_ptr,
                              void *host_opaque, EthernetDevice *es);
BOOL virtio_net_can_write_packet(VIRTIODevice *s);
void virtio_net_write_packet(VIRTIODevice *s, const uint8_t *buf, int buf_len);

/* console device */

typedef struct {
    void *opaque;
    void (*write_data)(void *opaque, const uint8_t *buf, int len);
    int (*read_data)(void *opaque, uint8_t *buf, int len);
} CharacterDevice;

VIRTIODevice *virtio_console_init(VIRTIOSetIrqFunc *set_irq, int irq_num,
                                  VIRTIOGetRAMPtrFunc *get_ram_ptr,
                                  void *host_opaque, CharacterDevice *cs);
BOOL virtio_console_can_write_data(VIRTIODevice *s);
int virtio_console_get_write_len(VIRTIODevice *s);
int virtio_console_write_data(VIRTIODevice *s, const uint8_t *buf, int buf_len);
void virtio_console_resize_event(VIRTIODevice *s, int width, int height);

/* 9p filesystem device */

#include "fs.h"

VIRTIODevice *virtio_9p_init(VIRTIOSetIrqFunc *set_irq, int irq_num,
                             VIRTIOGetRAMPtrFunc *get_ram_ptr,
                             void *host_opaque, FSDevice *fs,
                             const char *mount_tag);

#endif /* VIRTIO_H */
