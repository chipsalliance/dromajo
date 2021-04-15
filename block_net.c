/*
 * HTTP block device
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

#include "cutils.h"
#include "virtio.h"
#include "fs_wget.h"
#include "list.h"
#include "fbuf.h"
#include "machine.h"

typedef enum {
    CBLOCK_LOADING,
    CBLOCK_LOADED,
} CachedBlockStateEnum;

typedef struct CachedBlock {
    struct list_head link;
    struct BlockDeviceHTTP *bf;
    unsigned int block_num;
    CachedBlockStateEnum state;
    FileBuffer fbuf;
} CachedBlock;

#define BLK_FMT "%sblk%09u.bin"
#define GROUP_FMT "%sgrp%09u.bin"
#define PREFETCH_GROUP_LEN_MAX 32

typedef struct {
    struct BlockDeviceHTTP *bf;
    int group_num;
    int n_block_num;
    CachedBlock *tab_block[PREFETCH_GROUP_LEN_MAX];
} PrefetchGroupRequest;

/* modified data is stored per cluster (smaller than cached blocks to
   avoid losing space) */
typedef struct Cluster {
    FileBuffer fbuf;
} Cluster;

typedef struct BlockDeviceHTTP {
    BlockDevice *bs;
    int max_cache_size_kb;
    char url[1024];
    int prefetch_count;
    void (*start_cb)(void *opaque);
    void *start_opaque;
    
    int64_t nb_sectors;
    int block_size; /* in sectors, power of two */
    int nb_blocks;
    struct list_head cached_blocks; /* list of CachedBlock */
    int n_cached_blocks;
    int n_cached_blocks_max;

    /* write support */
    int sectors_per_cluster; /* power of two */
    Cluster **clusters; /* NULL if no written data */
    int n_clusters;
    int n_allocated_clusters;
    
    /* statistics */
    int64_t n_read_sectors;
    int64_t n_read_blocks;
    int64_t n_write_sectors;

    /* current read request */
    BOOL is_write;
    uint64_t sector_num;
    int cur_block_num;
    int sector_index, sector_count;
    BlockDeviceCompletionFunc *cb;
    void *opaque;
    uint8_t *io_buf;

    /* prefetch */
    int prefetch_group_len;
} BlockDeviceHTTP;

static void bf_update_block(CachedBlock *b, const uint8_t *data);
static void bf_read_onload(void *opaque, int err, void *data, size_t size);
static void bf_init_onload(void *opaque, int err, void *data, size_t size);
static void bf_prefetch_group_onload(void *opaque, int err, void *data,
                                     size_t size);

static CachedBlock *bf_find_block(BlockDeviceHTTP *bf, unsigned int block_num)
{
    CachedBlock *b;
    struct list_head *el;
    
    list_for_each(el, &bf->cached_blocks) {
        b = list_entry(el, CachedBlock, link);
        if (b->block_num == block_num) {
            /* move to front */
            if (bf->cached_blocks.next != el) {
                list_del(&b->link);
                list_add(&b->link, &bf->cached_blocks);
            }
            return b;
        }
    }
    return NULL;
}

static void bf_free_block(BlockDeviceHTTP *bf, CachedBlock *b)
{
    bf->n_cached_blocks--;
    file_buffer_reset(&b->fbuf);
    list_del(&b->link);
    free(b);
}

static CachedBlock *bf_add_block(BlockDeviceHTTP *bf, unsigned int block_num)
{
    CachedBlock *b;
    if (bf->n_cached_blocks >= bf->n_cached_blocks_max) {
        struct list_head *el, *el1;
        /* start by looking at the least unused blocks */
        list_for_each_prev_safe(el, el1, &bf->cached_blocks) {
            b = list_entry(el, CachedBlock, link);
            if (b->state == CBLOCK_LOADED) {
                bf_free_block(bf, b);
                if (bf->n_cached_blocks < bf->n_cached_blocks_max)
                    break;
            }
        }
    }
    b = mallocz(sizeof(CachedBlock));
    b->bf = bf;
    b->block_num = block_num;
    b->state = CBLOCK_LOADING;
    file_buffer_init(&b->fbuf);
    file_buffer_resize(&b->fbuf, bf->block_size * 512);
    list_add(&b->link, &bf->cached_blocks);
    bf->n_cached_blocks++;
    return b;
}

static int64_t bf_get_sector_count(BlockDevice *bs)
{
    BlockDeviceHTTP *bf = bs->opaque;
    return bf->nb_sectors;
}

static void bf_start_load_block(BlockDevice *bs, int block_num)
{
    BlockDeviceHTTP *bf = bs->opaque;
    char filename[1024];
    CachedBlock *b;
    b = bf_add_block(bf, block_num);
    bf->n_read_blocks++;
    /* make a XHR to read the block */
#if 0
    printf("%u,\n", block_num);
#endif
#if 0
    printf("load_blk=%d cached=%d read=%d KB (%d KB) write=%d KB (%d KB)\n",
           block_num, bf->n_cached_blocks,
           (int)(bf->n_read_sectors / 2),
           (int)(bf->n_read_blocks * bf->block_size / 2),
           (int)(bf->n_write_sectors / 2),
           (int)(bf->n_allocated_clusters * bf->sectors_per_cluster / 2));
#endif
    snprintf(filename, sizeof(filename), BLK_FMT, bf->url, block_num);
    //    printf("wget %s\n", filename);
    fs_wget(filename, NULL, NULL, b, bf_read_onload, TRUE);
}

static void bf_start_load_prefetch_group(BlockDevice *bs, int group_num,
                                         const int *tab_block_num,
                                         int n_block_num)
{
    BlockDeviceHTTP *bf = bs->opaque;
    CachedBlock *b;
    PrefetchGroupRequest *req;
    char filename[1024];
    BOOL req_flag;
    int i;
    
    req_flag = FALSE;
    req = malloc(sizeof(*req));
    req->bf = bf;
    req->group_num = group_num;
    req->n_block_num = n_block_num;
    for(i = 0; i < n_block_num; i++) {
        b = bf_find_block(bf, tab_block_num[i]);
        if (!b) {
            b = bf_add_block(bf, tab_block_num[i]);
            req_flag = TRUE;
        } else {
            /* no need to read the block if it is already loading or
               loaded */
            b = NULL;
        }
        req->tab_block[i] = b;
    }

    if (req_flag) {
        snprintf(filename, sizeof(filename), GROUP_FMT, bf->url, group_num);
        //        printf("wget %s\n", filename);
        fs_wget(filename, NULL, NULL, req, bf_prefetch_group_onload, TRUE);
        /* XXX: should add request in a list to free it for clean exit */
    } else {
        free(req);
    }
}

static void bf_prefetch_group_onload(void *opaque, int err, void *data,
                                     size_t size)
{
    PrefetchGroupRequest *req = opaque;
    BlockDeviceHTTP *bf = req->bf;
    CachedBlock *b;
    int block_bytes, i;
    
    if (err < 0) {
        fprintf(stderr, "Could not load group %u\n", req->group_num);
        exit(1);
    }
    block_bytes = bf->block_size * 512;
    assert(size == block_bytes * req->n_block_num);
    for(i = 0; i < req->n_block_num; i++) {
        b = req->tab_block[i];
        if (b) {
            bf_update_block(b, (const uint8_t *)data + block_bytes * i);
        }
    }
    free(req);
}

static int bf_rw_async1(BlockDevice *bs, BOOL is_sync)
{
    BlockDeviceHTTP *bf = bs->opaque;
    int offset, block_num, n, cluster_num;
    CachedBlock *b;
    Cluster *c;
    
    for(;;) {
        n = bf->sector_count - bf->sector_index;
        if (n == 0)
            break;
        cluster_num = bf->sector_num / bf->sectors_per_cluster;
        c = bf->clusters[cluster_num];
        if (c) {
            offset = bf->sector_num % bf->sectors_per_cluster;
            n = min_int(n, bf->sectors_per_cluster - offset);
            if (bf->is_write) {
                file_buffer_write(&c->fbuf, offset * 512,
                                  bf->io_buf + bf->sector_index * 512, n * 512);
            } else {
                file_buffer_read(&c->fbuf, offset * 512,
                                 bf->io_buf + bf->sector_index * 512, n * 512);
            }
            bf->sector_index += n;
            bf->sector_num += n;
        } else {
            block_num = bf->sector_num / bf->block_size;
            offset = bf->sector_num % bf->block_size;
            n = min_int(n, bf->block_size - offset);
            bf->cur_block_num = block_num;
            
            b = bf_find_block(bf, block_num);
            if (b) {
                if (b->state == CBLOCK_LOADING) {
                    /* wait until the block is loaded */
                    return 1;
                } else {
                    if (bf->is_write) {
                        int cluster_size, cluster_offset;
                        uint8_t *buf;
                        /* allocate a new cluster */
                        c = mallocz(sizeof(Cluster));
                        cluster_size = bf->sectors_per_cluster * 512;
                        buf = malloc(cluster_size);
                        file_buffer_init(&c->fbuf);
                        file_buffer_resize(&c->fbuf, cluster_size);
                        bf->clusters[cluster_num] = c;
                        /* copy the cached block data to the cluster */
                        cluster_offset = (cluster_num * bf->sectors_per_cluster) &
                            (bf->block_size - 1);
                        file_buffer_read(&b->fbuf, cluster_offset * 512,
                                         buf, cluster_size);
                        file_buffer_write(&c->fbuf, 0, buf, cluster_size);
                        free(buf);
                        bf->n_allocated_clusters++;
                        continue; /* write to the allocated cluster */
                    } else {
                        file_buffer_read(&b->fbuf, offset * 512,
                                         bf->io_buf + bf->sector_index * 512, n * 512);
                    }
                    bf->sector_index += n;
                    bf->sector_num += n;
                }
            } else {
                bf_start_load_block(bs, block_num);
                return 1;
            }
            bf->cur_block_num = -1;
        }
    }

    if (!is_sync) {
        //        printf("end of request\n");
        /* end of request */
        bf->cb(bf->opaque, 0);
    } 
    return 0;
}

static void bf_update_block(CachedBlock *b, const uint8_t *data)
{
    BlockDeviceHTTP *bf = b->bf;
    BlockDevice *bs = bf->bs;

    assert(b->state == CBLOCK_LOADING);
    file_buffer_write(&b->fbuf, 0, data, bf->block_size * 512);
    b->state = CBLOCK_LOADED;
    
    /* continue I/O read/write if necessary */
    if (b->block_num == bf->cur_block_num) {
        bf_rw_async1(bs, FALSE);
    }
}

static void bf_read_onload(void *opaque, int err, void *data, size_t size)
{
    CachedBlock *b = opaque;
    BlockDeviceHTTP *bf = b->bf;

    if (err < 0) {
        fprintf(stderr, "Could not load block %u\n", b->block_num);
        exit(1);
    }
    
    assert(size == bf->block_size * 512);
    bf_update_block(b, data);
}

static int bf_read_async(BlockDevice *bs,
                         uint64_t sector_num, uint8_t *buf, int n,
                         BlockDeviceCompletionFunc *cb, void *opaque)
{
    BlockDeviceHTTP *bf = bs->opaque;
    //    printf("bf_read_async: sector_num=%" PRId64 " n=%d\n", sector_num, n);
    bf->is_write = FALSE;
    bf->sector_num = sector_num;
    bf->io_buf = buf;
    bf->sector_count = n;
    bf->sector_index = 0;
    bf->cb = cb;
    bf->opaque = opaque;
    bf->n_read_sectors += n;
    return bf_rw_async1(bs, TRUE);
}

static int bf_write_async(BlockDevice *bs,
                          uint64_t sector_num, const uint8_t *buf, int n,
                          BlockDeviceCompletionFunc *cb, void *opaque)
{
    BlockDeviceHTTP *bf = bs->opaque;
    //    printf("bf_write_async: sector_num=%" PRId64 " n=%d\n", sector_num, n);
    bf->is_write = TRUE;
    bf->sector_num = sector_num;
    bf->io_buf = (uint8_t *)buf;
    bf->sector_count = n;
    bf->sector_index = 0;
    bf->cb = cb;
    bf->opaque = opaque;
    bf->n_write_sectors += n;
    return bf_rw_async1(bs, TRUE);
}

BlockDevice *block_device_init_http(const char *url,
                                    int max_cache_size_kb,
                                    void (*start_cb)(void *opaque),
                                    void *start_opaque)
{
    BlockDevice *bs;
    BlockDeviceHTTP *bf;
    char *p;

    bs = mallocz(sizeof(*bs));
    bf = mallocz(sizeof(*bf));
    strcpy(bf->url, url);
    /* get the path with the trailing '/' */
    p = strrchr(bf->url, '/');
    if (!p)
        p = bf->url;
    else
        p++;
    *p = '\0';

    init_list_head(&bf->cached_blocks);
    bf->max_cache_size_kb = max_cache_size_kb;
    bf->start_cb = start_cb;
    bf->start_opaque = start_opaque;
    bf->bs = bs;
    
    bs->opaque = bf;
    bs->get_sector_count = bf_get_sector_count;
    bs->read_async = bf_read_async;
    bs->write_async = bf_write_async;
    
    fs_wget(url, NULL, NULL, bs, bf_init_onload, TRUE);
    return bs;
}

static void bf_init_onload(void *opaque, int err, void *data, size_t size)
{
    BlockDevice *bs = opaque;
    BlockDeviceHTTP *bf = bs->opaque;
    int block_size_kb, block_num;
    JSONValue cfg, array;
    
    if (err < 0) {
        fprintf(stderr, "Could not load block device file (err=%d)\n", -err);
        exit(1);
    }

    /* parse the disk image info */
    cfg = json_parse_value_len(data, size);
    if (json_is_error(cfg)) {
        vm_error("error: %s\n", json_get_error(cfg));
    config_error:
        json_free(cfg);
        exit(1);
    }

    if (vm_get_int(cfg, "block_size", &block_size_kb) < 0)
        goto config_error;
    bf->block_size = block_size_kb * 2;
    if (bf->block_size <= 0 ||
        (bf->block_size & (bf->block_size - 1)) != 0) {
        vm_error("invalid block_size\n");
        goto config_error;
    }
    if (vm_get_int(cfg, "n_block", &bf->nb_blocks) < 0)
        goto config_error;
    if (bf->nb_blocks <= 0) {
        vm_error("invalid n_block\n");
        goto config_error;
    }

    bf->nb_sectors = bf->block_size * (uint64_t)bf->nb_blocks;
    bf->n_cached_blocks = 0;
    bf->n_cached_blocks_max = max_int(1, bf->max_cache_size_kb / block_size_kb);
    bf->cur_block_num = -1; /* no request in progress */
    
    bf->sectors_per_cluster = 8; /* 4 KB */
    bf->n_clusters = (bf->nb_sectors + bf->sectors_per_cluster - 1) / bf->sectors_per_cluster;
    bf->clusters = mallocz(sizeof(bf->clusters[0]) * bf->n_clusters);

    if (vm_get_int_opt(cfg, "prefetch_group_len",
                       &bf->prefetch_group_len, 1) < 0)
        goto config_error;
    if (bf->prefetch_group_len > PREFETCH_GROUP_LEN_MAX) {
        vm_error("prefetch_group_len is too large");
        goto config_error;
    }
    
    array = json_object_get(cfg, "prefetch");
    if (!json_is_undefined(array)) {
        int idx, prefetch_len, l, i;
        JSONValue el;
        int tab_block_num[PREFETCH_GROUP_LEN_MAX];
                          
        if (array.type != JSON_ARRAY) {
            vm_error("expecting an array\n");
            goto config_error;
        }
        prefetch_len = array.u.array->len;
        idx = 0;
        while (idx < prefetch_len) {
            l = min_int(prefetch_len - idx, bf->prefetch_group_len);
            for(i = 0; i < l; i++) {
                el = json_array_get(array, idx + i);
                if (el.type != JSON_INT) {
                    vm_error("expecting an integer\n");
                    goto config_error;
                }
                tab_block_num[i] = el.u.int32;
            }
            if (l == 1) {
                block_num = tab_block_num[0];
                if (!bf_find_block(bf, block_num)) {
                    bf_start_load_block(bs, block_num);
                }
            } else {
                bf_start_load_prefetch_group(bs, idx / bf->prefetch_group_len,
                                             tab_block_num, l);
            }
            idx += l;
        }
    }
    json_free(cfg);
    
    if (bf->start_cb) {
        bf->start_cb(bf->start_opaque);
    }
}
