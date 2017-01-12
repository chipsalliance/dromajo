/*
 * Networked Filesystem using HTTP
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
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <stdarg.h>
#include <sys/time.h>
#include <ctype.h>

#include "cutils.h"
#include "list.h"
#include "fs.h"

#ifdef EMSCRIPTEN
#include <emscripten.h>
#else
#include <curl/multi.h>
#endif

/*
  TODO:
  - rework FID handling (use paths instead of FID in FS API)
*/

//#define DEBUG_CACHE

#define DEFAULT_INODE_CACHE_SIZE (32 * 1024 * 1024)

typedef enum {
    FT_FIFO = 1,
    FT_CHR = 2,
    FT_DIR = 4,
    FT_BLK = 6,
    FT_REG = 8,
    FT_LNK = 10,
    FT_SOCK = 12,
} FSINodeTypeEnum;

typedef enum {
    REG_STATE_LOCAL, /* local content */
    REG_STATE_UNLOADED, /* content not loaded */
    REG_STATE_LOADING, /* content is being loaded */
    REG_STATE_LOADED, /* loaded, not modified, stored in cached_inode_list */
} FSINodeRegStateEnum;

typedef struct FSINode {
    struct list_head link;
    uint64_t inode_num; /* inode number */
    int32_t refcount;
    int32_t open_count;
    FSINodeTypeEnum type;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint32_t mtime_sec;
    uint32_t ctime_sec;
    uint32_t mtime_nsec;
    uint32_t ctime_nsec;
    union {
        struct {
            FSINodeRegStateEnum state;
            size_t size; /* real file size */
            size_t allocated_size;
            uint8_t *data; 
            char *path; /* path to load the file */
            struct list_head link;
            struct FSOpenInfo *open_info; /* used in LOADING state */
        } reg;
        struct list_head dir; /* list of FSDirEntry */
        struct {
            uint32_t major;
            uint32_t minor;
        } dev;
        struct {
            char *name;
        } symlink;
    } u;
} FSINode;

typedef struct {
    struct list_head link;
    FSINode *inode;
    char name[0];
} FSDirEntry;

struct FSFile {
    struct list_head link;
    uint32_t fid;
    uint32_t uid;
    FSINode *inode;
    BOOL is_opened;
    uint32_t open_flags;
};

typedef struct {
    uint8_t *buf;
    size_t size;
    size_t allocated_size;
} DynBuf;

typedef struct {
    struct list_head link;
    const char *name;
} PreloadFile;

typedef struct {
    struct list_head link;
    const char *name;
    struct list_head file_list; /* list of PreloadFile.link */
} PreloadEntry;

typedef struct FSDeviceMem {
    FSDevice common;

    struct list_head inode_list; /* list of FSINode */
    struct list_head file_list; /* list of FSFile */
    int64_t inode_count; /* current number of inodes */
    uint64_t inode_limit;
    int64_t total_size; /* total data size in regular files */
    uint64_t fs_size; /* total size, just for statfs */
    uint64_t inode_num_alloc;
    uint32_t block_size; /* for stat/statfs */
    FSINode *root_inode;
    struct list_head inode_cache_list; /* list of FSINode.u.reg.link */
    int64_t inode_cache_size;
    int64_t inode_cache_size_limit;
    struct list_head preload_list; /* list of PreloadEntry.link */
    
    /* network */
    DynBuf filelist;
    char *base_url;
    char *root_url;
    char *kernel_url;
    DynBuf kernel;

    void (*start_cb)(void *opaque);
    void *start_opaque;
} FSDeviceMem;

/* err < 0: error (no data provided)
   err = 0: end of transfer (data can be provided too)
   err = 1: data chunk
*/
typedef void WGetCallbackFunc(void *opaque, int err, void *data, size_t size);
typedef struct XHRState XHRState;

typedef struct FSOpenInfo {
    FSDevice *fs;
    XHRState *xhr;
    FSINode *n;
    /* the following is set in case there is a fs_open callback */
    FSFile *f;
    FSOpenCompletionFunc *cb;
    void *opaque;
} FSOpenInfo;

XHRState *fs_wget(const char *url, void *opaque, WGetCallbackFunc *cb);
void fs_wget_free(XHRState *s);

static void fs_close(FSDevice *fs, FSFile *f);
static void inode_decref(FSDevice *fs1, FSINode *n);

static char *compose_path(const char *path, const char *name)
{
    int path_len, name_len;
    char *d;

    if (path[0] == '\0') {
        d = strdup(name);
    } else {
        path_len = strlen(path);
        name_len = strlen(name);
        d = malloc(path_len + 1 + name_len + 1);
        memcpy(d, path, path_len);
        d[path_len] = '/';
        memcpy(d + path_len + 1, name, name_len + 1);
    }
    return d;
}

static FSINode *inode_incref(FSDevice *fs, FSINode *n)
{
    n->refcount++;
    return n;
}

static void inode_dirent_delete(FSDevice *fs, FSDirEntry *de)
{
    inode_decref(fs, de->inode);
    list_del(&de->link);
    free(de);
}

static void inode_decref(FSDevice *fs1, FSINode *n)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;
    if (--n->refcount == 0) {
        switch(n->type) {
        case FT_REG:
            fs->total_size -= n->u.reg.size;
            assert(fs->total_size >= 0);
            free(n->u.reg.data);
            free(n->u.reg.path);
            switch(n->u.reg.state)  {
            case REG_STATE_LOADED:
                list_del(&n->u.reg.link);
                fs->inode_cache_size -= n->u.reg.size;
                assert(fs->inode_cache_size >= 0);
                break;
            case REG_STATE_LOADING:
                {
                    FSOpenInfo *oi = n->u.reg.open_info;
                    fs_wget_free(oi->xhr);
                    free(oi);
                }
                break;
            case REG_STATE_LOCAL:
            case REG_STATE_UNLOADED:
                break;
            default:
                abort();
            }
            break;
        case FT_LNK:
            free(n->u.symlink.name);
            break;
        case FT_DIR:
            {
                struct list_head *el, *el1;
                FSDirEntry *de;
                /* when removing a directory, the reference counts
                   are manually updated. */
                list_for_each_safe(el, el1, &n->u.dir) {
                    de = list_entry(el, FSDirEntry, link);
                    free(de);
                }
            }
            break;
        default:
            break;
        }
        list_del(&n->link);
        free(n);
        fs->inode_count--;
        assert(fs->inode_count >= 0);
    }
}

static void inode_update_mtime(FSDevice *fs, FSINode *n)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    n->mtime_sec = tv.tv_sec;
    n->mtime_nsec = tv.tv_usec * 1000;
}

static FSINode *inode_new(FSDevice *fs1, FSINodeTypeEnum type,
                          uint32_t mode, uint32_t uid, uint32_t gid)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;
    FSINode *n;

    n = mallocz(sizeof(*n));
    n->refcount = 1;
    n->inode_num = fs->inode_num_alloc;
    fs->inode_num_alloc++;
    n->type = type;
    n->mode = mode & 0xfff;
    n->uid = uid;
    n->gid = gid;

    switch(type) {
    case FT_DIR:
        init_list_head(&n->u.dir);
        break;
    default:
        break;
    }

    list_add(&n->link, &fs->inode_list);
    fs->inode_count++;

    inode_update_mtime(fs1, n);
    n->ctime_sec = n->mtime_sec;
    n->ctime_nsec = n->mtime_nsec;

    return n;
}

static void inode_dir_add(FSDevice *fs, FSINode *n, const char *name,
                          FSINode *n1)
{
    FSDirEntry *de;
    int name_len;
    assert(n->type == FT_DIR);

    name_len = strlen(name);
    de = mallocz(sizeof(*de) + name_len + 1);
    de->inode = inode_incref(fs, n1);
    memcpy(de->name, name, name_len + 1);
    list_add_tail(&de->link, &n->u.dir);
}

static FSDirEntry *inode_search(FSDevice *fs, FSINode *n, const char *name)
{
    struct list_head *el;
    FSDirEntry *de;
    
    if (n->type != FT_DIR)
        return NULL;

    list_for_each(el, &n->u.dir) {
        de = list_entry(el, FSDirEntry, link);
        if (!strcmp(de->name, name))
            return de;
    }
    return NULL;
}

static FSINode *inode_search_path(FSDevice *fs, FSINode *n, const char *path)
{
    char name[1024];
    const char *p, *p1;
    int len;
    FSDirEntry *de;
    
    p = path;
    if (*p == '\0')
        return n;
    for(;;) {
        p1 = strchr(p, '/');
        if (!p1) {
            len = strlen(p);
        } else {
            len = p1 - p;
            p1++;
        }
        if (len > sizeof(name) - 1)
            return NULL;
        memcpy(name, p, len);
        name[len] = '\0';
        if (n->type != FT_DIR)
            return NULL;
        de = inode_search(fs, n, name);
        if (!de)
            return NULL;
        n = de->inode;
        p = p1;
        if (!p)
            break;
    }
    return n;
}

static BOOL is_empty_dir(FSDevice *fs, FSINode *n)
{
    struct list_head *el;
    FSDirEntry *de;

    list_for_each(el, &n->u.dir) {
        de = list_entry(el, FSDirEntry, link);
        if (strcmp(de->name, ".") != 0 &&
            strcmp(de->name, "..") != 0)
            return FALSE;
    }
    return TRUE;
}

static FSFile *fid_find(FSDevice *s1, uint32_t fid)
{
    FSDeviceMem *s = (FSDeviceMem *)s1;
    struct list_head *el;
    FSFile *f;

    list_for_each(el, &s->file_list) {
        f = list_entry(el, FSFile, link);
        if (f->fid == fid)
            return f;
    }
    return NULL;
}

static void fid_delete(FSDevice *fs, uint32_t fid)
{
    FSFile *f;
    f = fid_find(fs, fid);
    if (!f)
        return;
    fs_close(fs, f);
    inode_decref(fs, f->inode);
    list_del(&f->link);
    free(f);
}

static FSFile *fid_create(FSDevice *fs1, uint32_t fid, FSINode *n,
                          uint32_t uid)
{
    FSDeviceMem *s = (FSDeviceMem *)fs1;
    FSFile *f;
    FSINode *n1;

    f = fid_find(fs1, fid);
    if (f) {
        n1 = f->inode;
        f->inode = inode_incref(fs1, n);
        inode_decref(fs1, n1);
        f->uid = uid;
    } else {
        f = mallocz(sizeof(*f));
        f->fid = fid;
        f->inode = inode_incref(fs1, n);
        f->uid = uid;
        list_add(&f->link, &s->file_list);
    }
    return f;
}

static void inode_to_qid(FSQID *qid, FSINode *n)
{
    if (n->type == FT_DIR)
        qid->type = P9_QTDIR;
    else if (n->type == FT_LNK)
        qid->type = P9_QTSYMLINK;
    else
        qid->type = P9_QTFILE;
    qid->version = 0; /* no caching on client */
    qid->path = n->inode_num;
}

static void fs_statfs(FSDevice *fs1, FSStatFS *st)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;
    st->f_bsize = fs->block_size;
    st->f_blocks = fs->fs_size / fs->block_size;
    st->f_bfree = (fs->fs_size - fs->total_size) / fs->block_size;
    st->f_bavail = st->f_bfree;
    st->f_files = fs->inode_limit;
    st->f_ffree = fs->inode_limit - fs->inode_count;
}

static int fs_attach(FSDevice *fs1, FSQID *qid, uint32_t fid, uint32_t uid)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;

    fid_create(fs1, fid, fs->root_inode, uid);
    inode_to_qid(qid, fs->root_inode);
    return 0;
}

static int fs_walk(FSDevice *fs, FSQID *qids, FSFile *f, uint32_t newfid, 
                   int count, char **names)
{
    int i;
    FSINode *n;
    FSDirEntry *de;

    n = f->inode;
    for(i = 0; i < count; i++) {
        de = inode_search(fs, n, names[i]);
        if (!de)
            break;
        n = de->inode;
        inode_to_qid(&qids[i], n);
    }
    fid_create(fs, newfid, n, f->uid);
    return i;
}

static int fs_mkdir(FSDevice *fs, FSQID *qid, FSFile *f,
                    const char *name, uint32_t mode, uint32_t gid)
{
    FSINode *n, *n1;

    n = f->inode;
    if (n->type != FT_DIR)
        return -P9_ENOTDIR;
    if (inode_search(fs, n, name))
        return -P9_EEXIST;
    n1 = inode_new(fs, FT_DIR, mode, f->uid, gid);
    inode_dir_add(fs, n1, ".", n1);
    inode_dir_add(fs, n1, "..", n);
    inode_dir_add(fs, n, name, n1);
    inode_decref(fs, n1);
    inode_to_qid(qid, n1);
    return 0;
}

/* remove elements in the cache considering that 'added_size' will be
   added */
static void fs_trim_cache(FSDevice *fs1, int64_t added_size)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;
    struct list_head *el, *el1;
    FSINode *n;

#if defined(DEBUG_CACHE) && 0
    printf("fs_trim_cache: size=%" PRId64 "/%" PRId64 " added=%" PRId64 "\n",
           fs->inode_cache_size, fs->inode_cache_size_limit, added_size);
#endif
    if ((fs->inode_cache_size + added_size) <= fs->inode_cache_size_limit)
        return;
    list_for_each_prev_safe(el, el1, &fs->inode_cache_list) {
        n = list_entry(el, FSINode, u.reg.link);
        assert(n->u.reg.state == REG_STATE_LOADED);
        /* cannot remove open files */
        //        printf("open_count=%d\n", n->open_count);
        if (n->open_count != 0)
            continue;
#ifdef DEBUG_CACHE
        printf("fs_trim_cache: remove inode %d size=%ld\n",
               (int)n->inode_num, n->u.reg.size);
#endif
        free(n->u.reg.data);
        n->u.reg.data = NULL;
        n->u.reg.allocated_size = 0;
        n->u.reg.state = REG_STATE_UNLOADED;
        list_del(&n->u.reg.link);
        fs->inode_cache_size -= n->u.reg.size;
        assert(fs->inode_cache_size >= 0);
        if ((fs->inode_cache_size + added_size) <= fs->inode_cache_size_limit)
            break;
    }
}

static void fs_open_cb(void *opaque, int err, void *data, size_t size)
{
    FSOpenInfo *oi = opaque;
    FSINode *n = oi->n;
    FSDeviceMem *fs;
    size_t len;
    FSQID qid;
    FSFile *f;
    
    //    printf("open_cb: err=%d size=%ld\n", err, size);
    if (err < 0) {
    error:
        n->u.reg.state = REG_STATE_UNLOADED;
        free(n->u.reg.data);
        n->u.reg.data = NULL;
        n->u.reg.allocated_size = 0;
        if (oi->cb) {
            oi->cb(oi->fs, NULL, -P9_EIO, oi->opaque);
        }
        free(oi);
    } else {
        /* we ignore extraneous data */
        len = n->u.reg.size - n->u.reg.allocated_size;
        if (size < len)
            len = size;
        memcpy(n->u.reg.data + n->u.reg.allocated_size, data, len);
        n->u.reg.allocated_size += len;
        
        if (err == 0) {
            /* end of transfer */
            if (n->u.reg.allocated_size != n->u.reg.size)
                goto error;
            fs = (FSDeviceMem *)oi->fs;
            n->u.reg.state = REG_STATE_LOADED;
            list_add(&n->u.reg.link, &fs->inode_cache_list);
            fs->inode_cache_size += n->u.reg.size;

            if (oi->cb) {
                f = oi->f;
                f->is_opened = TRUE;
                n->open_count++;
                inode_to_qid(&qid, n);
                oi->cb(oi->fs, &qid, 0, oi->opaque);
            }
            free(oi);
        }
    }
}

static int fs_open_wget(FSDevice *fs1, FSINode *n)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;
    char *url;
    FSOpenInfo *oi;
    
    fs_trim_cache(fs1, n->u.reg.size);
    
    n->u.reg.data = malloc(n->u.reg.size);
    if (!n->u.reg.data)
        return -P9_EIO;
    n->u.reg.allocated_size = 0;
    n->u.reg.state = REG_STATE_LOADING;
    url = compose_path(fs->root_url, n->u.reg.path);
#ifdef DEBUG_CACHE
    printf("load file: %s\n", n->u.reg.path);
#endif
    oi = mallocz(sizeof(*oi));
    oi->fs = fs1;
    oi->n = n;
    oi->xhr = fs_wget(url, oi, fs_open_cb);
    n->u.reg.open_info = oi;
    return 0;
}

static void fs_preload_files(FSDevice *fs1, const char *name)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;
    struct list_head *el;
    PreloadEntry *pe;
    PreloadFile *pf;
    FSINode *n;
    
    list_for_each(el, &fs->preload_list) {
        pe = list_entry(el, PreloadEntry, link);
        if (!strcmp(pe->name, name))
            goto found;
    }
    return;
 found:
    list_for_each(el, &pe->file_list) {
        pf = list_entry(el, PreloadFile, link);
        n = inode_search_path(fs1, fs->root_inode, pf->name);
        if (n && n->type == FT_REG && n->u.reg.state == REG_STATE_UNLOADED) {
            fs_open_wget(fs1, n);
        }
    }
}

/* return < 0 if error, 0 if OK, 1 if asynchronous completion */
/* XXX: we don't support several simultaneous asynchronous open on the
   same inode */
static int fs_open(FSDevice *fs1, FSQID *qid, FSFile *f, uint32_t flags,
                   FSOpenCompletionFunc *cb, void *opaque)
{
    FSINode *n = f->inode;
    FSDeviceMem *fs = (FSDeviceMem *)fs1;
    int ret;
    
    fs_close(fs1, f);

    if (flags & P9_O_DIRECTORY) {
        if (n->type != FT_DIR)
            return -P9_ENOTDIR;
    } else {
        if (n->type != FT_REG && n->type != FT_DIR)
        return -P9_EINVAL; /* XXX */
    }
    f->open_flags = flags;
    if (n->type == FT_REG) {
        switch(n->u.reg.state) {
        case REG_STATE_UNLOADED:
            {
                FSOpenInfo *oi;
                /* need to load the file */
                
                fs_preload_files(fs1, n->u.reg.path);

                ret = fs_open_wget(fs1, n);
                if (ret)
                    return ret;
                oi = n->u.reg.open_info;
                oi->f = f;
                oi->cb = cb;
                oi->opaque = opaque;
                return 1; /* completion callback will be called later */
            }
            break;
        case REG_STATE_LOADING:
            {
                FSOpenInfo *oi;
                /* we only handle the case where the file is being preloaded */
                oi = n->u.reg.open_info;
                if (oi->cb)
                    return -P9_EIO;
                oi = n->u.reg.open_info;
                oi->f = f;
                oi->cb = cb;
                oi->opaque = opaque;
                return 1; /* completion callback will be called later */
            }
            break;
        case REG_STATE_LOCAL:
            goto do_open;
        case REG_STATE_LOADED:
            /* move to front */
            list_del(&n->u.reg.link);
            list_add(&n->u.reg.link, &fs->inode_cache_list);
            goto do_open;
        default:
            abort();
        }
    } else {
    do_open:
        f->is_opened = TRUE;
        n->open_count++;
        inode_to_qid(qid, n);
        return 0;
    }
}

static int fs_create(FSDevice *fs, FSQID *qid, FSFile *f, const char *name, 
                     uint32_t flags, uint32_t mode, uint32_t gid)
{
    FSINode *n1, *n = f->inode;
    
    if (n->type != FT_DIR)
        return -P9_ENOTDIR;
    if (inode_search(fs, n, name))
        return -P9_EEXIST;

    fs_close(fs, f);
    
    n1 = inode_new(fs, FT_REG, mode, f->uid, gid);
    inode_dir_add(fs, n, name, n1);

    inode_decref(fs, f->inode);
    f->inode = n1;
    f->is_opened = TRUE;
    f->open_flags = flags;
    n1->open_count++;
    inode_to_qid(qid, n1);
    return 0;
}

static int fs_readdir(FSDevice *fs, FSFile *f, uint64_t offset1,
                      uint8_t *buf, int count)
{
    FSINode *n1, *n = f->inode;
    int len, pos, name_len, type;
    struct list_head *el;
    FSDirEntry *de;
    uint64_t offset;

    if (!f->is_opened || n->type != FT_DIR)
        return -P9_EPROTO;
    
    el = n->u.dir.next;
    offset = 0;
    while (offset < offset1) {
        if (el == &n->u.dir)
            return 0; /* no more entries */
        offset++;
        el = el->next;
    }
    
    pos = 0;
    for(;;) {
        if (el == &n->u.dir)
            break;
        de = list_entry(el, FSDirEntry, link);
        name_len = strlen(de->name);
        len = 13 + 8 + 1 + 2 + name_len;
        if ((pos + len) > count)
            break;
        offset++;
        n1 = de->inode;
        if (n1->type == FT_DIR)
            type = P9_QTDIR;
        else if (n1->type == FT_LNK)
            type = P9_QTSYMLINK;
        else
            type = P9_QTFILE;
        buf[pos++] = type;
        put_le32(buf + pos, 0); /* version */
        pos += 4;
        put_le64(buf + pos, n1->inode_num);
        pos += 8;
        put_le64(buf + pos, offset);
        pos += 8;
        buf[pos++] = n1->type;
        put_le16(buf + pos, name_len);
        pos += 2;
        memcpy(buf + pos, de->name, name_len);
        pos += name_len;
        el = el->next;
    }
    return pos;
}

static int fs_read(FSDevice *fs, FSFile *f, uint64_t offset,
                   uint8_t *buf, int count)
{
    FSINode *n = f->inode;
    uint64_t count1;

    if (!f->is_opened)
        return -P9_EPROTO;
    if (n->type != FT_REG)
        return -P9_EIO;
    if ((f->open_flags & P9_O_NOACCESS) == P9_O_WRONLY)
        return -P9_EIO;

    if (offset >= n->u.reg.size)
        return 0;
    count1 = n->u.reg.size - offset;
    if (count1 < count)
        count = count1;
    memcpy(buf, n->u.reg.data + offset, count);
    return count;
}

static int fs_truncate(FSDevice *fs1, FSINode *n, uint64_t size)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;
    intptr_t diff;
    uint8_t *new_data;
    size_t new_allocated_size;
    
    if (n->type != FT_REG)
        return -P9_EINVAL;
    if (size > UINTPTR_MAX)
        return -P9_ENOSPC;
    diff = size - n->u.reg.size;
    if (diff == 0)
        return 0;
    /* currently cannot resize while loading */
    switch(n->u.reg.state) {
    case REG_STATE_LOADING:
        return -P9_EIO;
    case REG_STATE_UNLOADED:
        break;
    case REG_STATE_LOADED:
    case REG_STATE_LOCAL:
        if (diff > 0) {
            if ((fs->total_size + diff) > fs->fs_size)
                return -P9_ENOSPC;
            if (size > n->u.reg.allocated_size) {
                new_allocated_size = n->u.reg.allocated_size * 5 / 4;
                if (size > new_allocated_size)
                    new_allocated_size = size;
                new_data = realloc(n->u.reg.data, new_allocated_size);
                if (!new_data)
                    return -P9_ENOSPC;
                n->u.reg.allocated_size = new_allocated_size;
                n->u.reg.data = new_data;
            }
            memset(n->u.reg.data + n->u.reg.size, 0, diff);
        } else {
            new_allocated_size = n->u.reg.allocated_size * 4 / 5;
            if (size <= new_allocated_size) {
                new_data = realloc(n->u.reg.data, new_allocated_size);
                if (!new_data && size != 0)
                    return -P9_ENOSPC;
                n->u.reg.allocated_size = new_allocated_size;
                n->u.reg.data = new_data;
            }
        }
        /* file is modified, so it is now local */
        if (n->u.reg.state == REG_STATE_LOADED) {
            list_del(&n->u.reg.link);
            fs->inode_cache_size -= n->u.reg.size;
            assert(fs->inode_cache_size >= 0);
            n->u.reg.state = REG_STATE_LOCAL;
        }
        break;
    default:
        abort();
    }
    n->u.reg.size = size;
    fs->total_size += diff;
    assert(fs->total_size >= 0);
    return 0;
}

static int fs_write(FSDevice *fs1, FSFile *f, uint64_t offset,
                    const uint8_t *buf, int count)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;
    FSINode *n = f->inode;
    uint64_t end;
    int err;
    
    if (!f->is_opened)
        return -P9_EPROTO;
    if (n->type != FT_REG)
        return -P9_EIO;
    if ((f->open_flags & P9_O_NOACCESS) == P9_O_RDONLY)
        return -P9_EIO;
    if (count == 0)
        return 0;
    end = offset + count;
    if (end > n->u.reg.size) {
        err = fs_truncate(fs1, n, end);
        if (err)
            return err;
    }
    inode_update_mtime(fs1, n);
    /* file is modified, so it is now local */
    if (n->u.reg.state == REG_STATE_LOADED) {
        list_del(&n->u.reg.link);
        fs->inode_cache_size -= n->u.reg.size;
        assert(fs->inode_cache_size >= 0);
        n->u.reg.state = REG_STATE_LOCAL;
    }
    memcpy(n->u.reg.data + offset, buf, count);
    return count;
}

static void fs_close(FSDevice *fs, FSFile *f)
{
    FSINode *n = f->inode;
    if (f->is_opened) {
        f->is_opened = FALSE;
        n->open_count--;
        assert(n->open_count >= 0);
    }
}

static int fs_stat(FSDevice *fs1, FSFile *f, FSStat *st)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;
    FSINode *n = f->inode;

    inode_to_qid(&st->qid, n);
    st->st_mode = n->mode | (n->type << 12);
    st->st_uid = n->uid;
    st->st_gid = n->gid;
    st->st_nlink = n->refcount - 1; /* remove 1 for the reference by the fid */
    if (n->type == FT_BLK || n->type == FT_CHR) {
        /* XXX: check */
        st->st_rdev = (n->u.dev.major << 8) | n->u.dev.minor;
    } else {
        st->st_rdev = 0;
    }
    st->st_blksize = fs->block_size;
    if (n->type == FT_REG) {
        st->st_size = n->u.reg.size;
        st->st_blocks = (st->st_size + fs->block_size - 1) / fs->block_size;
    } else if (n->type == FT_LNK) {
        st->st_size = strlen(n->u.symlink.name);
        st->st_blocks = (st->st_size + fs->block_size - 1) / fs->block_size;
    } else {
        st->st_size = 0;
        st->st_blocks = 0;
    }
    /* Note: atime is not supported */
    st->st_atime_sec = n->mtime_sec;
    st->st_atime_nsec = n->mtime_nsec;
    st->st_mtime_sec = n->mtime_sec;
    st->st_mtime_nsec = n->mtime_nsec;
    st->st_ctime_sec = n->ctime_sec;
    st->st_ctime_nsec = n->ctime_nsec;
    return 0;
}



static int fs_setattr(FSDevice *fs1, FSFile *f, uint32_t mask,
                      uint32_t mode, uint32_t uid, uint32_t gid,
                      uint64_t size, uint64_t atime_sec, uint64_t atime_nsec,
                      uint64_t mtime_sec, uint64_t mtime_nsec)
{
    FSINode *n = f->inode;
    int ret;
    
    if (mask & P9_SETATTR_MODE) {
        n->mode = mode;
    }
    if (mask & P9_SETATTR_UID) {
        n->uid = uid;
    }
    if (mask & P9_SETATTR_GID) {
        n->gid = gid;
    }
    if (mask & P9_SETATTR_SIZE) {
        ret = fs_truncate(fs1, n, size);
        if (ret)
            return ret;
    }
    if (mask & P9_SETATTR_MTIME) {
        if (mask & P9_SETATTR_MTIME_SET) {
            n->mtime_sec = mtime_sec;
            n->mtime_nsec = mtime_nsec;
        } else {
            inode_update_mtime(fs1, n);
        }
    }
    if (mask & P9_SETATTR_CTIME) {
        inode_update_mtime(fs1, n);
        n->ctime_sec = n->mtime_sec;
        n->ctime_nsec = n->mtime_nsec;
    }
    return 0;
}

static int fs_link(FSDevice *fs, FSFile *df, FSFile *f, const char *name)
{
    FSINode *n = df->inode;
    
    if (f->inode->type == FT_DIR)
        return -P9_EPERM;
    if (inode_search(fs, n, name))
        return -P9_EEXIST;
    inode_dir_add(fs, n, name, f->inode);
    return 0;
}

static int fs_symlink(FSDevice *fs, FSQID *qid,
                      FSFile *f, const char *name, const char *symgt, uint32_t gid)
{
    FSINode *n1, *n = f->inode;
    
    if (inode_search(fs, n, name))
        return -P9_EEXIST;

    n1 = inode_new(fs, FT_LNK, 0777, f->uid, gid);
    n1->u.symlink.name = strdup(symgt);
    inode_dir_add(fs, n, name, n1);
    inode_decref(fs, n1);
    inode_to_qid(qid, n1);
    return 0;
}

static int fs_mknod(FSDevice *fs, FSQID *qid,
             FSFile *f, const char *name, uint32_t mode, uint32_t major,
             uint32_t minor, uint32_t gid)
{
    int type;
    FSINode *n1, *n = f->inode;

    type = (mode & P9_S_IFMT) >> 12;
    /* XXX: add FT_DIR support */
    if (type != FT_FIFO && type != FT_CHR && type != FT_BLK && type != FT_REG)
        return -P9_EINVAL;
    if (inode_search(fs, n, name))
        return -P9_EEXIST;
    n1 = inode_new(fs, type, mode, f->uid, gid);
    if (type == FT_CHR || type == FT_BLK) {
        n1->u.dev.major = major;
        n1->u.dev.minor = minor;
    }
    inode_dir_add(fs, n, name, n1);
    inode_decref(fs, n1);
    inode_to_qid(qid, n1);
    return 0;
}

static int fs_readlink(FSDevice *fs, char *buf, int buf_size, FSFile *f)
{
    FSINode *n = f->inode;
    int len;
    if (n->type != FT_LNK)
        return -P9_EIO;
    len = min_int(strlen(n->u.symlink.name), buf_size - 1);
    memcpy(buf, n->u.symlink.name, len);
    buf[len] = '\0';
    return 0;
}

static int fs_renameat(FSDevice *fs, FSFile *f, const char *name, 
                FSFile *new_f, const char *new_name)
{
    FSDirEntry *de;

    de = inode_search(fs, f->inode, name);
    if (!de)
        return -P9_ENOENT;
    if (inode_search(fs, new_f->inode, new_name))
        return -P9_EEXIST;
    inode_dir_add(fs, new_f->inode, new_name, de->inode);
    inode_dirent_delete(fs, de);
    return 0;
}

static int fs_unlinkat(FSDevice *fs, FSFile *f, const char *name)
{
    FSDirEntry *de;
    FSINode *n;

    if (!strcmp(name, ".") || !strcmp(name, ".."))
        return -P9_ENOENT;
    de = inode_search(fs, f->inode, name);
    if (!de)
        return -P9_ENOENT;
    n = de->inode;
    if (n->type == FT_DIR) {
        if (!is_empty_dir(fs, n))
            return -P9_ENOTEMPTY;
        inode_decref(fs, f->inode);
        inode_decref(fs, n);
    }
    inode_dirent_delete(fs, de);
    return 0;
}

static int fs_lock(FSDevice *fs, FSFile *f, const FSLock *lock)
{
    FSINode *n = f->inode;
    if (!f->is_opened)
        return -P9_EPROTO;
    if (n->type != FT_REG)
        return -P9_EIO;
    /* XXX: implement it */
    return P9_LOCK_SUCCESS;
}

static int fs_getlock(FSDevice *fs, FSFile *f, FSLock *lock)
{
    FSINode *n = f->inode;
    if (!f->is_opened)
        return -P9_EPROTO;
    if (n->type != FT_REG)
        return -P9_EIO;
    /* XXX: implement it */
    return 0;
}

FSDevice *fs_mem_init(void)
{
    FSDeviceMem *fs;
    FSDevice *fs1;
    FSINode *n;

    fs = mallocz(sizeof(*fs));
    fs1 = &fs->common;

    fs->common.fid_find = fid_find;
    fs->common.fid_delete = fid_delete;
    fs->common.fs_statfs = fs_statfs;
    fs->common.fs_attach = fs_attach;
    fs->common.fs_walk = fs_walk;
    fs->common.fs_mkdir = fs_mkdir;
    fs->common.fs_open = fs_open;
    fs->common.fs_create = fs_create;
    fs->common.fs_stat = fs_stat;
    fs->common.fs_setattr = fs_setattr;
    fs->common.fs_close = fs_close;
    fs->common.fs_readdir = fs_readdir;
    fs->common.fs_read = fs_read;
    fs->common.fs_write = fs_write;
    fs->common.fs_link = fs_link;
    fs->common.fs_symlink = fs_symlink;
    fs->common.fs_mknod = fs_mknod;
    fs->common.fs_readlink = fs_readlink;
    fs->common.fs_renameat = fs_renameat;
    fs->common.fs_unlinkat = fs_unlinkat;
    fs->common.fs_lock = fs_lock;
    fs->common.fs_getlock = fs_getlock;

    init_list_head(&fs->file_list);
    init_list_head(&fs->inode_list);
    fs->inode_num_alloc = 1;
    fs->block_size = 1024;
    fs->inode_limit = 1 << 20; /* arbitrary */
    fs->fs_size = 1 << 30; /* arbitrary */

    init_list_head(&fs->inode_cache_list);
    fs->inode_cache_size_limit = DEFAULT_INODE_CACHE_SIZE;

    init_list_head(&fs->preload_list);
    
    /* create the root inode */
    n = inode_new(fs1, FT_DIR, 0777, 0, 0);
    inode_dir_add(fs1, n, ".", n);
    inode_dir_add(fs1, n, "..", n);
    fs->root_inode = n;

    return (FSDevice *)fs;
}

/***********************************************/
/* HTTP get */

#ifdef EMSCRIPTEN

struct XHRState {
    void *opaque;
    WGetCallbackFunc *cb;
};

void fs_wget_init(void)
{
}

static void fs_wget_onerror(void *opaque)
{
    XHRState *s = opaque;
    if (s->cb)
        s->cb(s->opaque, -1, NULL, 0);
}

static void fs_wget_onload(void *opaque, void *data, int size)
{
    XHRState *s = opaque;
    if (s->cb)
        s->cb(s->opaque, 0, data, size);
}
    
XHRState *fs_wget(const char *url, void *opaque, WGetCallbackFunc *cb)
{
    XHRState *s;

    s = mallocz(sizeof(*s));
    s->opaque = opaque;
    s->cb = cb;
    emscripten_async_wget_data(url, s, fs_wget_onload,
                               fs_wget_onerror);
    return s;
}

void fs_wget_free(XHRState *s)
{
    s->cb = NULL;
    s->opaque = NULL;
}

#else /* !EMSCRIPTEN */

struct XHRState {
    struct list_head link;
    CURL *eh;
    void *opaque;
    WGetCallbackFunc *cb;
};

static CURLM *curl_multi_ctx;
static struct list_head xhr_list; /* list of XHRState.link */

void fs_wget_init(void)
{
    if (curl_multi_ctx)
        return;
    curl_global_init(CURL_GLOBAL_ALL);
    curl_multi_ctx = curl_multi_init();
    init_list_head(&xhr_list);
}

void fs_wget_end(void)
{
    curl_multi_cleanup(curl_multi_ctx);
    curl_global_cleanup();
}

static size_t fs_wget_cb(char *ptr, size_t size, size_t nmemb,
                         void *userdata)
{
    XHRState *s = userdata;
    size *= nmemb;
    s->cb(s->opaque, 1, ptr, size);
    return size;
}

XHRState *fs_wget(const char *url, void *opaque, WGetCallbackFunc *cb)
{
    XHRState *s;
    s = mallocz(sizeof(*s));
    s->eh = curl_easy_init();
    s->opaque = opaque;
    s->cb = cb;
        
    curl_easy_setopt(s->eh, CURLOPT_PRIVATE, s);
    curl_easy_setopt(s->eh, CURLOPT_WRITEDATA, s);
    curl_easy_setopt(s->eh, CURLOPT_WRITEFUNCTION, fs_wget_cb);
    curl_easy_setopt(s->eh, CURLOPT_HEADER, 0);
    curl_easy_setopt(s->eh, CURLOPT_URL, url);
    curl_easy_setopt(s->eh, CURLOPT_VERBOSE, 0L);
    curl_easy_setopt(s->eh, CURLOPT_ACCEPT_ENCODING, "");
    
    curl_multi_add_handle(curl_multi_ctx, s->eh);
    list_add_tail(&s->link, &xhr_list);
    return s;
}

void fs_wget_free(XHRState *s)
{
    curl_easy_cleanup(s->eh);
    list_del(&s->link);
    free(s);
}

void fs_net_set_fdset(int *pfd_max, fd_set *rfds, fd_set *wfds, fd_set *efds,
                      int *ptimeout)
{
    long timeout;
    int n, fd_max;
    CURLMsg *msg;

    if (!curl_multi_ctx)
        return;
    
    curl_multi_perform(curl_multi_ctx, &n);

    for(;;) {
        msg = curl_multi_info_read(curl_multi_ctx, &n);
        if (!msg)
            break;
        if (msg->msg == CURLMSG_DONE) {
            XHRState *s;
            long http_code;

            curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, (char **)&s);
            curl_easy_getinfo(msg->easy_handle, CURLINFO_RESPONSE_CODE,
                              &http_code);
            /* signal the end of the transfer or error */
            if (http_code == 200) {
                s->cb(s->opaque, 0, NULL, 0);
            } else {
                s->cb(s->opaque, -1, NULL, 0);
            }
            curl_multi_remove_handle(curl_multi_ctx, s->eh);
            curl_easy_cleanup(s->eh);
            list_del(&s->link);
            free(s);
        }
    }

    curl_multi_fdset(curl_multi_ctx, rfds, wfds, efds, &fd_max);
    *pfd_max = max_int(*pfd_max, fd_max);
    curl_multi_timeout(curl_multi_ctx, &timeout);
    if (timeout >= 0)
        *ptimeout = min_int(*ptimeout, timeout);
}

void fs_net_event_loop(void)
{
    fd_set rfds, wfds, efds;
    int timeout, fd_max;
    struct timeval tv;
    
    if (!curl_multi_ctx)
        return;

    for(;;) {
        fd_max = -1;
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_ZERO(&efds);
        timeout = 10000;
        fs_net_set_fdset(&fd_max, &rfds, &wfds, &efds, &timeout);
        if (list_empty(&xhr_list))
            break;
        tv.tv_sec = timeout / 1000;
        tv.tv_usec = (timeout % 1000) * 1000;
        select(fd_max + 1, &rfds, &wfds, &rfds, &tv);
    }
}

#endif /* EMSCRIPTEN */

/***********************************************/
/* file list processing */

static int from_hex(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    else if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    else if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    else
        return -1;
}

static BOOL isspace_nolf(int c)
{
    return (c == ' ' || c == '\t');
}

static int parse_fname(char *buf, int buf_size, const char **pp)
{
    const char *p;
    char *q;
    int c, h;
    
    p = *pp;
    q = buf;
    if (*p == '"') {
        p++;
        for(;;) {
            c = *p++;
            if (c == '\0' || c == '\n') {
                return -1;
            } else if (c == '\"') {
                break;
            } else if (c == '\\') {
                c = *p++;
                switch(c) {
                case '\'':
                case '\"':
                case '\\':
                    goto add_char;
                case 'n':
                    c = '\n';
                    goto add_char;
                case 'r':
                    c = '\r';
                    goto add_char;
                case 't':
                    c = '\t';
                    goto add_char;
                case 'x':
                    h = from_hex(*p++);
                    if (h < 0)
                        return -1;
                    c = h << 4;
                    h = from_hex(*p++);
                    if (h < 0)
                        return -1;
                    c |= h;
                    goto add_char;
                default:
                    return -1;
                }
            } else {
            add_char:
                if (q >= buf + buf_size - 1)
                    return -1;
                *q++ = c;
            }
        }
        p++;
    } else {
        while (!isspace_nolf(*p) && *p != '\0' && *p != '\n') {
            if (q >= buf + buf_size - 1)
                return -1;
            *q++ = *p++;
        }
    }
    *q = '\0';
    *pp = p;
    return 0;
}

static void skip_line(const char **pp)
{
    const char *p;
    p = *pp;
    while (*p != '\n' && *p != '\0')
        p++;
    if (*p == '\n')
        p++;
    *pp = p;
}

int filelist_load_rec(FSDevice *fs1, const char **pp, FSINode *dir,
                      const char *path)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;
    char fname[1024], lname[1024];
    int c, ret;
    const char *p;
    FSINodeTypeEnum type;
    uint32_t mode, uid, gid;
    FSINode *n;

    p = *pp;
    for(;;) {
        /* skip comments or empty lines */
        if (*p == '\0')
            break;
        if (*p == '#') {
            skip_line(&p);
            continue;
        }
        /* end of directory */
        c = *p++;
        if (c == '.') {
            skip_line(&p);
            break;
        }
        switch(c) {
        case 'p':
            type = FT_FIFO;
            break;
        case 'c':
            type = FT_CHR;
            break;
        case 'd':
            type = FT_DIR;
            break;
        case 'b':
            type = FT_BLK;
            break;
        case '-':
            type = FT_REG;
            break;
        case 'l':
            type = FT_LNK;
            break;
        case 's':
            type = FT_SOCK;
            break;
        default:
            fprintf(stderr, "invalid file type: %c\n", c);
            return -1;
        }

        mode = 0;

        c = *p++;
        if (c == 'r')
            mode |= 0400;
        else if (c != '-')
            goto invalid_mode;

        c = *p++;
        if (c == 'w')
            mode |= 0200;
        else if (c != '-')
            goto invalid_mode;

        c = *p++;
        if (c == 'x')
            mode |= 0100;
        else if (c == 's')
            mode |= 0100 | P9_S_ISUID;
        else if (c == 'S')
            mode |= P9_S_ISUID;
        else if (c != '-')
            goto invalid_mode;
        
        c = *p++;
        if (c == 'r')
            mode |= 0040;
        else if (c != '-')
            goto invalid_mode;

        c = *p++;
        if (c == 'w')
            mode |= 0020;
        else if (c != '-')
            goto invalid_mode;

        c = *p++;
        if (c == 'x')
            mode |= 0010;
        else if (c == 's')
            mode |= 0010 | P9_S_ISGID;
        else if (c == 'S')
            mode |= P9_S_ISGID;
        else if (c != '-')
            goto invalid_mode;
            
        c = *p++;
        if (c == 'r')
            mode |= 0004;
        else if (c != '-')
            goto invalid_mode;

        c = *p++;
        if (c == 'w')
            mode |= 0002;
        else if (c != '-')
            goto invalid_mode;

        c = *p++;
        if (c == 'x')
            mode |= 0001;
        else if (c == 't')
            mode |= 0001 | P9_S_ISVTX;
        else if (c == 'T')
            mode |= P9_S_ISVTX;
        else if (c != '-') {
        invalid_mode:
            fprintf(stderr, "invalid mode: '%c'\n", c);
            return -1;
        }
        
        while (isspace_nolf(*p))
            p++;
        uid = strtoul(p, (char **)&p, 0);
        if (*p != ' ') {
            fprintf(stderr, "invalid uid\n");
            return -1;
        }

        while (isspace_nolf(*p))
            p++;
        gid = strtoul(p, (char **)&p, 0);
        if (*p != ' ') {
            fprintf(stderr, "invalid gid\n");
            return -1;
        }

        n = inode_new(fs1, type, mode, uid, gid);
        
        switch(type) {
        case FT_CHR:
        case FT_BLK:
            while (isspace_nolf(*p))
                p++;
            n->u.dev.major = strtoul(p, (char **)&p, 0);
            if (*p != ' ') {
                fprintf(stderr, "invalid major\n");
                return -1;
            }
            while (isspace_nolf(*p))
                p++;
            n->u.dev.minor = strtoul(p, (char **)&p, 0);
            if (*p != ' ') {
                fprintf(stderr, "invalid minor\n");
                return -1;
            }
            break;
        case FT_REG:
            {
                uint64_t size;
                while (isspace_nolf(*p))
                    p++;
                size = strtoull(p, (char **)&p, 0);
                if (*p != ' ' || size > UINTPTR_MAX) {
                    fprintf(stderr, "invalid size\n");
                    return -1;
                }
                n->u.reg.size = size;
                if (size != 0)
                    n->u.reg.state = REG_STATE_UNLOADED;
                fs->total_size += size;
            }
            break;
        default:
            break;
        }
        
        /* modification time */
        while (isspace_nolf(*p))
            p++;
        n->mtime_sec = strtoul(p, (char **)&p, 0);
        n->mtime_nsec = 0;
        if (*p != ' ' && *p != '.') {
            fprintf(stderr, "invalid mtime\n");
            return -1;
        }
        if (*p == '.') {
            uint32_t v, m;
            p++;
            /* XXX: inefficient */
            m = 1000000000;
            v = 0;
            while (*p >= '0' && *p <= '9') {
                m /= 10;
                v += (*p - '0') * m;
                p++;
            }
            n->mtime_nsec = v;
            if (*p != ' ') {
                fprintf(stderr, "invalid frac mtime\n");
                return -1;
            }
        }

        while (isspace_nolf(*p))
            p++;
        if (parse_fname(fname, sizeof(fname), &p) < 0) {
            fprintf(stderr, "invalid filename\n");
            return -1;
        }
        inode_dir_add(fs1, dir, fname, n);

        if (type == FT_LNK) {
            while (isspace_nolf(*p))
                p++;
            if (parse_fname(lname, sizeof(lname), &p) < 0) {
                fprintf(stderr, "invalid symlink name\n");
                return -1;
            }
            n->u.symlink.name = strdup(lname);
        }

        skip_line(&p);
        
        if (type == FT_DIR) {
            char *path1;
            path1 = compose_path(path, fname);
            ret = filelist_load_rec(fs1, &p, n, path1);
            free(path1);
            if (ret)
                return ret;
        } else if (type == FT_REG && n->u.reg.size != 0) {
            /* set the path for later loading */
            n->u.reg.path = compose_path(path, fname);
        }
    }
    *pp = p;
    return 0;
}

static int parse_preload(FSDevice *fs1, const char *p)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;
    char fname[1024];
    PreloadEntry *pe;
    PreloadFile *pf;
    
    if (parse_fname(fname, sizeof(fname), &p) < 0) {
        fprintf(stderr, "invalid filename\n");
        return -1;
    }
    pe = mallocz(sizeof(*pe));
    pe->name = strdup(fname);
    init_list_head(&pe->file_list);
    list_add_tail(&pe->link, &fs->preload_list);

    for(;;) {
        while (isspace_nolf(*p))
            p++;
        if (*p == '\0' || *p == '\n')
            break;
        if (parse_fname(fname, sizeof(fname), &p) < 0) {
            fprintf(stderr, "invalid filename\n");
            return -1;
        }
        pf = mallocz(sizeof(*pf));
        pf->name = strdup(fname);
        list_add_tail(&pf->link, &pe->file_list); 
    }
    return 0;
}

static char *compose_url(const char *base_url, const char *name)
{
    if (strchr(name, ':')) {
        return strdup(name);
    } else {
        return compose_path(base_url, name);
    }
}

static int parse_kernel(FSDevice *fs1, const char *p)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;
    char fname[1024];

    if (fs->kernel_url ||
        parse_fname(fname, sizeof(fname), &p) < 0) {
        fprintf(stderr, "invalid kernel filename\n");
        return -1;
    }
    fs->kernel_url = compose_url(fs->base_url, fname);
    return 0;
}

int filelist_load(FSDevice *fs1, const char *p)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;
    int ret;
    char tagname[128], *q;
    
    ret = 0;
    for(;;) {
        if (*p == '\0')
            goto done;
        if (*p == '\n') {
            p++;
            break;
        }
        q = tagname;
        while (*p != ':' && *p != '\n' && *p != '\0') {
            if ((q - tagname) < sizeof(tagname) - 1)
                *q++ = *p;
            p++;
        }
        *q = '\0';
        if (*p == ':')
            p++;
        while (isspace_nolf(*p))
            p++;
        if (!strcmp(tagname, "Version")) {
            int version = atoi(p);
            if (version != 1) {
                fprintf(stderr, "Unusupported version: %d\n", version);
                ret = -1;
                goto done;
            }
        } else if (!strcmp(tagname, "Preload")) {
            ret = parse_preload(fs1, p);
            if (ret)
                goto done;
        } else if (!strcmp(tagname, "Kernel")) {
            ret = parse_kernel(fs1, p);
            if (ret)
                goto done;
        }
        skip_line(&p);
        if (*p == '\0')
            goto done;
    }
    ret = filelist_load_rec(fs1, &p, fs->root_inode, "");
 done:
    return ret;
}

static void dbuf_init(DynBuf *s)
{
    memset(s, 0, sizeof(*s));
}

static void dbuf_write(DynBuf *s, size_t offset, uint8_t *data, size_t len)
{
    size_t end, new_size;
    new_size = end = offset + len;
    if (new_size > s->allocated_size) {
        new_size = max_int(new_size, s->allocated_size * 3 / 2);
        s->buf = realloc(s->buf, new_size);
        s->allocated_size = new_size;
    }
    memcpy(s->buf + offset, data, len);
    if (end > s->size)
        s->size = end;
}

static void dbuf_putc(DynBuf *s, uint8_t c)
{
    dbuf_write(s, s->size, &c, 1);
}

static void dbuf_free(DynBuf *s)
{
    free(s->buf);
    memset(s, 0, sizeof(*s));
}

static void filelist_on_load(void *opaque, int err, void *data, size_t size);
static void kernel_on_load(void *opaque, int err, void *data, size_t size);

FSDevice *fs_net_init(const char *url, void (*start)(void *opaque), void *opaque)
{
    FSDevice *fs1;
    FSDeviceMem *fs;
    char *filelist_url;
    
    fs_wget_init();
    
    fs1 = fs_mem_init();
    fs = (FSDeviceMem *)fs1;

    dbuf_init(&fs->filelist);

    fs->base_url = strdup(url);

    /* set the default root URL */
    fs->root_url = compose_url(fs->base_url, "root");

    fs->start_cb = start;
    fs->start_opaque = opaque;
    
    /* start file list download */
    filelist_url = compose_url(fs->base_url, "filelist.txt");
    fs_wget(filelist_url, fs1, filelist_on_load);
    free(filelist_url);
    
    return fs1;
}

static void filelist_on_load(void *opaque, int err, void *data, size_t size)
{
    FSDevice *fs1 = opaque;
    FSDeviceMem *fs = (FSDeviceMem *)fs1;

    //    printf("err=%d size=%ld\n", err, size);
    if (err < 0) {
        fprintf(stderr, "Error while downloading file list\n");
        exit(1);
    } else {
        dbuf_write(&fs->filelist, fs->filelist.size, data, size);
        if (err == 0) {
            /* end of transfer */
            dbuf_putc(&fs->filelist, 0);
            filelist_load(fs1, (const char *)fs->filelist.buf);
            dbuf_free(&fs->filelist);

            /* try to load kernel if provided */
            if (fs->kernel_url)
                fs_wget(fs->kernel_url, fs1, kernel_on_load);
        }
    }
}

static void kernel_on_load(void *opaque, int err, void *data, size_t size)
{
    FSDevice *fs1 = opaque;
    FSDeviceMem *fs = (FSDeviceMem *)fs1;

    //    printf("kernel: err=%d size=%ld\n", err, size);
    if (err < 0) {
        fprintf(stderr, "Error while downloading kernel\n");
        exit(1);
    } else {
        dbuf_write(&fs->kernel, fs->kernel.size, data, size);
        if (err == 0) {
            if (fs->start_cb)
                fs->start_cb(fs->start_opaque);
        }
    }
}

int fs_net_get_kernel(FSDevice *fs1, uint8_t **pkernel)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;
    *pkernel = fs->kernel.buf;
    return fs->kernel.size;
}

void fs_net_free_kernel(FSDevice *fs1)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;
    dbuf_free(&fs->kernel);
}
