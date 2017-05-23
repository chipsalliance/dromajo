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
#include "fs_utils.h"
#include "fs_wget.h"

#if defined(EMSCRIPTEN)
#include <emscripten.h>
#endif

/*
  TODO:
  - implement fs_lock/fs_getlock
  - update fs_size with links ?
  - limit fs_size in dirent creation
  - limit filename length
*/

//#define DEBUG_CACHE
#define USE_PRELOAD 1

#if defined(EMSCRIPTEN)
#define DEFAULT_INODE_CACHE_SIZE (32 * 1024 * 1024)
#else
#define DEFAULT_INODE_CACHE_SIZE (256 * 1024 * 1024)
#endif

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

typedef struct FSBaseURL {
    struct list_head link;
    int ref_count;
    char *base_url_id;
    char *url;
    char *user;
    char *password;
    BOOL encrypted;
    AES_KEY aes_state;
} FSBaseURL;

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
            FSBaseURL *base_url;
            FSFileID file_id; /* network file ID */
            struct list_head link;
            struct FSOpenInfo *open_info; /* used in LOADING state */
            BOOL is_fscmd;
#ifdef DEBUG_CACHE
            char *filename;
#endif
        } reg;
        struct {
            struct list_head de_list; /* list of FSDirEntry */
            int size;
        } dir;
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
    uint8_t mark; /* temporary use only */
    char name[0];
} FSDirEntry;

typedef enum {
    FS_CMD_XHR,
    FS_CMD_PBKDF2,
} FSCMDRequestEnum;

#define FS_CMD_REPLY_LEN_MAX 64

typedef struct {
    FSCMDRequestEnum type;
    struct CmdXHRState *xhr_state;
    int reply_len;
    uint8_t reply_buf[FS_CMD_REPLY_LEN_MAX];
} FSCMDRequest;

struct FSFile {
    uint32_t uid;
    FSINode *inode;
    BOOL is_opened;
    uint32_t open_flags;
    FSCMDRequest *req;
};

typedef struct {
    struct list_head link;
    const char *name;
} PreloadFile;

typedef struct {
    struct list_head link;
    FSFileID file_id;
    struct list_head file_list; /* list of PreloadFile.link */
} PreloadEntry;

typedef struct FSDeviceMem {
    FSDevice common;

    struct list_head inode_list; /* list of FSINode */
    int64_t inode_count; /* current number of inodes */
    uint64_t inode_limit;
    int64_t fs_blocks;
    uint64_t fs_max_blocks;
    uint64_t inode_num_alloc;
    int block_size_log2;
    uint32_t block_size; /* for stat/statfs */
    FSINode *root_inode;
    struct list_head inode_cache_list; /* list of FSINode.u.reg.link */
    int64_t inode_cache_size;
    int64_t inode_cache_size_limit;
    struct list_head preload_list; /* list of PreloadEntry.link */
    /* network */
    struct list_head base_url_list; /* list of FSBaseURL.link */
} FSDeviceMem;

typedef struct FSOpenInfo {
    FSDevice *fs;
    XHRState *xhr;
    FSINode *n;
    DecryptFileState *dec_state;
    /* the following is set in case there is a fs_open callback */
    FSFile *f;
    FSOpenCompletionFunc *cb;
    void *opaque;
} FSOpenInfo;

static void fs_close(FSDevice *fs, FSFile *f);
static void inode_decref(FSDevice *fs1, FSINode *n);
static int fs_cmd_write(FSDevice *fs, FSFile *f, uint64_t offset,
                        const uint8_t *buf, int buf_len);
static int fs_cmd_read(FSDevice *fs, FSFile *f, uint64_t offset,
                       uint8_t *buf, int buf_len);
static int fs_truncate(FSDevice *fs1, FSINode *n, uint64_t size);
static void fs_open_end(FSOpenInfo *oi);
static void fs_base_url_decref(FSDevice *fs, FSBaseURL *bu);
static FSBaseURL *fs_net_set_base_url(FSDevice *fs1,
                                      const char *base_url_id,
                                      const char *url,
                                      const char *user, const char *password,
                                      AES_KEY *aes_state);
static void fs_cmd_close(FSDevice *fs, FSFile *f);

static int64_t to_blocks(FSDeviceMem *fs, uint64_t size)
{
    return (size + fs->block_size - 1) >> fs->block_size_log2;
}

static FSINode *inode_incref(FSDevice *fs, FSINode *n)
{
    n->refcount++;
    return n;
}

static FSINode *inode_inc_open(FSDevice *fs, FSINode *n)
{
    n->open_count++;
    return n;
}

static void inode_free(FSDevice *fs1, FSINode *n)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;

    //    printf("inode_free=%" PRId64 "\n", n->inode_num);
    assert(n->refcount == 0);
    assert(n->open_count == 0);
    switch(n->type) {
    case FT_REG:
        fs->fs_blocks -= to_blocks(fs, n->u.reg.size);
        assert(fs->fs_blocks >= 0);
        free(n->u.reg.data);
#ifdef DEBUG_CACHE
        free(n->u.reg.filename);
#endif
        switch(n->u.reg.state)  {
        case REG_STATE_LOADED:
            list_del(&n->u.reg.link);
            fs->inode_cache_size -= n->u.reg.size;
            assert(fs->inode_cache_size >= 0);
            fs_base_url_decref(fs1, n->u.reg.base_url);
            break;
        case REG_STATE_LOADING:
            {
                FSOpenInfo *oi = n->u.reg.open_info;
                fs_wget_free(oi->xhr);
                fs_open_end(oi);
                fs_base_url_decref(fs1, n->u.reg.base_url);
            }
            break;
        case REG_STATE_UNLOADED:
            fs_base_url_decref(fs1, n->u.reg.base_url);
            break;
        case REG_STATE_LOCAL:
            break;
        default:
            abort();
        }
        break;
    case FT_LNK:
        free(n->u.symlink.name);
        break;
    case FT_DIR:
        assert(list_empty(&n->u.dir.de_list));
        break;
    default:
        break;
    }
    list_del(&n->link);
    free(n);
    fs->inode_count--;
    assert(fs->inode_count >= 0);
}

static void inode_decref(FSDevice *fs1, FSINode *n)
{
    assert(n->refcount >= 1);
    if (--n->refcount <= 0 && n->open_count <= 0) {
        inode_free(fs1, n);
    }
}

static void inode_dec_open(FSDevice *fs1, FSINode *n)
{
    assert(n->open_count >= 1);
    if (--n->open_count <= 0 && n->refcount <= 0) {
        inode_free(fs1, n);
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
    n->open_count = 0;
    n->inode_num = fs->inode_num_alloc;
    fs->inode_num_alloc++;
    n->type = type;
    n->mode = mode & 0xfff;
    n->uid = uid;
    n->gid = gid;

    switch(type) {
    case FT_DIR:
        init_list_head(&n->u.dir.de_list);
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

/* warning: the refcount of 'n1' is not incremented by this function */
/* XXX: test FS max size */
static FSDirEntry *inode_dir_add(FSDevice *fs1, FSINode *n, const char *name,
                                 FSINode *n1)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;
    FSDirEntry *de;
    int name_len, dirent_size, new_size;
    assert(n->type == FT_DIR);

    name_len = strlen(name);
    de = mallocz(sizeof(*de) + name_len + 1);
    de->inode = n1;
    memcpy(de->name, name, name_len + 1);
    dirent_size = sizeof(*de) + name_len + 1;
    new_size = n->u.dir.size + dirent_size;
    fs->fs_blocks += to_blocks(fs, new_size) - to_blocks(fs, n->u.dir.size);
    n->u.dir.size = new_size;
    list_add_tail(&de->link, &n->u.dir.de_list);
    return de;
}

static FSDirEntry *inode_search(FSINode *n, const char *name)
{
    struct list_head *el;
    FSDirEntry *de;
    
    if (n->type != FT_DIR)
        return NULL;

    list_for_each(el, &n->u.dir.de_list) {
        de = list_entry(el, FSDirEntry, link);
        if (!strcmp(de->name, name))
            return de;
    }
    return NULL;
}

static FSINode *inode_search_path1(FSDevice *fs, FSINode *n, const char *path)
{
    char name[1024];
    const char *p, *p1;
    int len;
    FSDirEntry *de;
    
    p = path;
    if (*p == '/')
        p++;
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
        de = inode_search(n, name);
        if (!de)
            return NULL;
        n = de->inode;
        p = p1;
        if (!p)
            break;
    }
    return n;
}

static FSINode *inode_search_path(FSDevice *fs1, const char *path)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;
    if (!fs1)
        return NULL;
    return inode_search_path1(fs1, fs->root_inode, path);
}

static BOOL is_empty_dir(FSDevice *fs, FSINode *n)
{
    struct list_head *el;
    FSDirEntry *de;

    list_for_each(el, &n->u.dir.de_list) {
        de = list_entry(el, FSDirEntry, link);
        if (strcmp(de->name, ".") != 0 &&
            strcmp(de->name, "..") != 0)
            return FALSE;
    }
    return TRUE;
}

static void inode_dirent_delete_no_decref(FSDevice *fs1, FSINode *n, FSDirEntry *de)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;
    int dirent_size, new_size;
    dirent_size = sizeof(*de) + strlen(de->name) + 1;

    new_size = n->u.dir.size - dirent_size;
    fs->fs_blocks += to_blocks(fs, new_size) - to_blocks(fs, n->u.dir.size);
    n->u.dir.size = new_size;
    assert(n->u.dir.size >= 0);
    assert(fs->fs_blocks >= 0);
    list_del(&de->link);
    free(de);
}

static void inode_dirent_delete(FSDevice *fs, FSINode *n, FSDirEntry *de)
{
    FSINode *n1;
    n1 = de->inode;
    inode_dirent_delete_no_decref(fs, n, de);
    inode_decref(fs, n1);
}

static void flush_dir(FSDevice *fs, FSINode *n)
{
    struct list_head *el, *el1;
    FSDirEntry *de;
    list_for_each_safe(el, el1, &n->u.dir.de_list) {
        de = list_entry(el, FSDirEntry, link);
        inode_dirent_delete(fs, n, de);
    }
    assert(n->u.dir.size == 0);
}

static void fs_delete(FSDevice *fs, FSFile *f)
{
    fs_close(fs, f);
    inode_dec_open(fs, f->inode);
    free(f);
}

static FSFile *fid_create(FSDevice *fs1, FSINode *n, uint32_t uid)
{
    FSFile *f;

    f = mallocz(sizeof(*f));
    f->inode = inode_inc_open(fs1, n);
    f->uid = uid;
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
    st->f_bsize = 1024;
    st->f_blocks = fs->fs_max_blocks <<
        (fs->block_size_log2 - 10);
    st->f_bfree = (fs->fs_max_blocks - fs->fs_blocks) <<
        (fs->block_size_log2 - 10);
    st->f_bavail = st->f_bfree;
    st->f_files = fs->inode_limit;
    st->f_ffree = fs->inode_limit - fs->inode_count;
}

static int fs_attach(FSDevice *fs1, FSFile **pf, FSQID *qid, uint32_t uid,
                     const char *uname, const char *aname)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;

    *pf = fid_create(fs1, fs->root_inode, uid);
    inode_to_qid(qid, fs->root_inode);
    return 0;
}

static int fs_walk(FSDevice *fs, FSFile **pf, FSQID *qids,
                   FSFile *f, int count, char **names)
{
    int i;
    FSINode *n;
    FSDirEntry *de;

    n = f->inode;
    for(i = 0; i < count; i++) {
        de = inode_search(n, names[i]);
        if (!de)
            break;
        n = de->inode;
        inode_to_qid(&qids[i], n);
    }
    *pf = fid_create(fs, n, f->uid);
    return i;
}

static int fs_mkdir(FSDevice *fs, FSQID *qid, FSFile *f,
                    const char *name, uint32_t mode, uint32_t gid)
{
    FSINode *n, *n1;

    n = f->inode;
    if (n->type != FT_DIR)
        return -P9_ENOTDIR;
    if (inode_search(n, name))
        return -P9_EEXIST;
    n1 = inode_new(fs, FT_DIR, mode, f->uid, gid);
    inode_dir_add(fs, n1, ".", inode_incref(fs, n1));
    inode_dir_add(fs, n1, "..", inode_incref(fs, n));
    inode_dir_add(fs, n, name, n1);
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
        printf("fs_trim_cache: remove '%s' size=%ld\n",
               n->u.reg.filename, n->u.reg.size);
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

static void fs_open_end(FSOpenInfo *oi)
{
    if (oi->dec_state)
        decrypt_file_end(oi->dec_state);
    free(oi);
}

static int fs_open_write_cb(void *opaque, const uint8_t *data, size_t size)
{
    FSOpenInfo *oi = opaque;
    size_t len;
    FSINode *n = oi->n;
    
    /* we ignore extraneous data */
    len = n->u.reg.size - n->u.reg.allocated_size;
    if (size < len)
        len = size;
    memcpy(n->u.reg.data + n->u.reg.allocated_size, data, len);
    n->u.reg.allocated_size += len;
    return 0;
}

static void fs_open_cb(void *opaque, int err, void *data, size_t size)
{
    FSOpenInfo *oi = opaque;
    FSINode *n = oi->n;
    FSDeviceMem *fs;
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
        fs_open_end(oi);
    } else {
        if (oi->dec_state) {
            if (decrypt_file(oi->dec_state, data, size) < 0)
                goto error;
            if (err == 0) {
                if (decrypt_file_flush(oi->dec_state) < 0)
                    goto error;
            }
        } else {
            fs_open_write_cb(oi, data, size);
        }

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
                inode_to_qid(&qid, n);
                oi->cb(oi->fs, &qid, 0, oi->opaque);
            }
            fs_open_end(oi);
        }
    }
}

static int fs_open_wget(FSDevice *fs1, FSINode *n)
{
    char *url;
    FSOpenInfo *oi;
    char fname[FILEID_SIZE_MAX];
    FSBaseURL *bu;
    
    fs_trim_cache(fs1, n->u.reg.size);
    
    n->u.reg.data = malloc(n->u.reg.size);
    if (!n->u.reg.data)
        return -P9_EIO;
    n->u.reg.allocated_size = 0;
    n->u.reg.state = REG_STATE_LOADING;
    file_id_to_filename(fname, n->u.reg.file_id);
    bu = n->u.reg.base_url;
    url = compose_path(bu->url, fname);
#ifdef DEBUG_CACHE
    printf("load file: %s\n", n->u.reg.filename);
#endif
    oi = mallocz(sizeof(*oi));
    oi->fs = fs1;
    oi->n = n;
    if (bu->encrypted) {
        oi->dec_state = decrypt_file_init(&bu->aes_state, fs_open_write_cb, oi);
    }
    oi->xhr = fs_wget(url, bu->user, bu->password, oi, fs_open_cb);
    n->u.reg.open_info = oi;
    return 0;
}

static void fs_preload_files(FSDevice *fs1, FSFileID file_id)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;
    struct list_head *el;
    PreloadEntry *pe;
    PreloadFile *pf;
    FSINode *n;
    
    list_for_each(el, &fs->preload_list) {
        pe = list_entry(el, PreloadEntry, link);
        if (pe->file_id == file_id)
            goto found;
    }
    return;
 found:
    list_for_each(el, &pe->file_list) {
        pf = list_entry(el, PreloadFile, link);
        n = inode_search_path(fs1, pf->name);
        if (n && n->type == FT_REG && n->u.reg.state == REG_STATE_UNLOADED) {
#if defined(DEBUG_CACHE)
            printf("preload: %s\n", pf->name);
#endif
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
        if ((flags & P9_O_TRUNC) && (flags & P9_O_NOACCESS) != P9_O_RDONLY) {
            fs_truncate(fs1, n, 0);
        }

        switch(n->u.reg.state) {
        case REG_STATE_UNLOADED:
            {
                FSOpenInfo *oi;
                /* need to load the file */
                
                fs_preload_files(fs1, n->u.reg.file_id);

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
    if (inode_search(n, name)) {
        /* XXX: support it, but Linux does not seem to use this case */
        return -P9_EEXIST;
    } else {
        fs_close(fs, f);
        
        n1 = inode_new(fs, FT_REG, mode, f->uid, gid);
        inode_dir_add(fs, n, name, n1);
        
        inode_dec_open(fs, f->inode);
        f->inode = inode_inc_open(fs, n1);
        f->is_opened = TRUE;
        f->open_flags = flags;
        inode_to_qid(qid, n1);
        return 0;
    }
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
    
    el = n->u.dir.de_list.next;
    offset = 0;
    while (offset < offset1) {
        if (el == &n->u.dir.de_list)
            return 0; /* no more entries */
        offset++;
        el = el->next;
    }
    
    pos = 0;
    for(;;) {
        if (el == &n->u.dir.de_list)
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
    if (n->u.reg.is_fscmd)
        return fs_cmd_read(fs, f, offset, buf, count);
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
    intptr_t diff, diff_blocks;
    uint8_t *new_data;
    size_t new_allocated_size;
    
    if (n->type != FT_REG)
        return -P9_EINVAL;
    if (size > UINTPTR_MAX)
        return -P9_ENOSPC;
    diff = size - n->u.reg.size;
    if (diff == 0)
        return 0;
    diff_blocks = to_blocks(fs, size) - to_blocks(fs, n->u.reg.size);
    /* currently cannot resize while loading */
    switch(n->u.reg.state) {
    case REG_STATE_LOADING:
        return -P9_EIO;
    case REG_STATE_UNLOADED:
        if (size == 0) {
            /* now local content */
            n->u.reg.state = REG_STATE_LOCAL;
        }
        break;
    case REG_STATE_LOADED:
    case REG_STATE_LOCAL:
        if (diff > 0) {
            if ((fs->fs_blocks + diff_blocks) > fs->fs_max_blocks)
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
    fs->fs_blocks += diff_blocks;
    assert(fs->fs_blocks >= 0);
    n->u.reg.size = size;
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
    if (n->u.reg.is_fscmd) {
        return fs_cmd_write(fs1, f, offset, buf, count);
    }
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
    if (f->is_opened) {
        f->is_opened = FALSE;
    }
    if (f->req)
        fs_cmd_close(fs, f);
}

static int fs_stat(FSDevice *fs1, FSFile *f, FSStat *st)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;
    FSINode *n = f->inode;

    inode_to_qid(&st->qid, n);
    st->st_mode = n->mode | (n->type << 12);
    st->st_uid = n->uid;
    st->st_gid = n->gid;
    st->st_nlink = n->refcount;
    if (n->type == FT_BLK || n->type == FT_CHR) {
        /* XXX: check */
        st->st_rdev = (n->u.dev.major << 8) | n->u.dev.minor;
    } else {
        st->st_rdev = 0;
    }
    st->st_blksize = fs->block_size;
    if (n->type == FT_REG) {
        st->st_size = n->u.reg.size;
    } else if (n->type == FT_LNK) {
        st->st_size = strlen(n->u.symlink.name);
    } else if (n->type == FT_DIR) {
        st->st_size = n->u.dir.size;
    } else {
        st->st_size = 0;
    }
    /* in 512 byte blocks */
    st->st_blocks = to_blocks(fs, st->st_size) << (fs->block_size_log2 - 9);
    
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
        struct timeval tv;
        gettimeofday(&tv, NULL);
        n->ctime_sec = tv.tv_sec;
        n->ctime_nsec = tv.tv_usec * 1000;
    }
    return 0;
}

static int fs_link(FSDevice *fs, FSFile *df, FSFile *f, const char *name)
{
    FSINode *n = df->inode;
    
    if (f->inode->type == FT_DIR)
        return -P9_EPERM;
    if (inode_search(n, name))
        return -P9_EEXIST;
    inode_dir_add(fs, n, name, inode_incref(fs, f->inode));
    return 0;
}

static int fs_symlink(FSDevice *fs, FSQID *qid,
                      FSFile *f, const char *name, const char *symgt, uint32_t gid)
{
    FSINode *n1, *n = f->inode;
    
    if (inode_search(n, name))
        return -P9_EEXIST;

    n1 = inode_new(fs, FT_LNK, 0777, f->uid, gid);
    n1->u.symlink.name = strdup(symgt);
    inode_dir_add(fs, n, name, n1);
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
    if (inode_search(n, name))
        return -P9_EEXIST;
    n1 = inode_new(fs, type, mode, f->uid, gid);
    if (type == FT_CHR || type == FT_BLK) {
        n1->u.dev.major = major;
        n1->u.dev.minor = minor;
    }
    inode_dir_add(fs, n, name, n1);
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
    FSDirEntry *de, *de1;
    FSINode *n1;
    
    de = inode_search(f->inode, name);
    if (!de)
        return -P9_ENOENT;
    de1 = inode_search(new_f->inode, new_name);
    n1 = NULL;
    if (de1) {
        n1 = de1->inode;
        if (n1->type == FT_DIR)
            return -P9_EEXIST; /* XXX: handle the case */
        inode_dirent_delete_no_decref(fs, new_f->inode, de1);
    }
    inode_dir_add(fs, new_f->inode, new_name, inode_incref(fs, de->inode));
    inode_dirent_delete(fs, f->inode, de);
    if (n1)
        inode_decref(fs, n1);
    return 0;
}

static int fs_unlinkat(FSDevice *fs, FSFile *f, const char *name)
{
    FSDirEntry *de;
    FSINode *n;

    if (!strcmp(name, ".") || !strcmp(name, ".."))
        return -P9_ENOENT;
    de = inode_search(f->inode, name);
    if (!de)
        return -P9_ENOENT;
    n = de->inode;
    if (n->type == FT_DIR) {
        if (!is_empty_dir(fs, n))
            return -P9_ENOTEMPTY;
        flush_dir(fs, n);
    }
    inode_dirent_delete(fs, f->inode, de);
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

/* XXX: only used with file lists, so not all the data is released */
static void fs_mem_end(FSDevice *fs1)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;
    struct list_head *el, *el1, *el2, *el3;
    FSINode *n;
    FSDirEntry *de;

    list_for_each_safe(el, el1, &fs->inode_list) {
        n = list_entry(el, FSINode, link);
        n->refcount = 0;
        if (n->type == FT_DIR) {
            list_for_each_safe(el2, el3, &n->u.dir.de_list) {
                de = list_entry(el2, FSDirEntry, link);
                list_del(&de->link);
                free(de);
            }
            init_list_head(&n->u.dir.de_list);
        }
        inode_free(fs1, n);
    }
    assert(list_empty(&fs->inode_cache_list));
}

FSDevice *fs_mem_init(void)
{
    FSDeviceMem *fs;
    FSDevice *fs1;
    FSINode *n;

    fs = mallocz(sizeof(*fs));
    fs1 = &fs->common;

    fs->common.fs_end = fs_mem_end;
    fs->common.fs_delete = fs_delete;
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

    init_list_head(&fs->inode_list);
    fs->inode_num_alloc = 1;
    fs->block_size_log2 = FS_BLOCK_SIZE_LOG2;
    fs->block_size = 1 << fs->block_size_log2;
    fs->inode_limit = 1 << 20; /* arbitrary */
    fs->fs_max_blocks = 1 << (30 - fs->block_size_log2); /* arbitrary */

    init_list_head(&fs->inode_cache_list);
    fs->inode_cache_size_limit = DEFAULT_INODE_CACHE_SIZE;

    init_list_head(&fs->preload_list);

    init_list_head(&fs->base_url_list);

    /* create the root inode */
    n = inode_new(fs1, FT_DIR, 0777, 0, 0);
    inode_dir_add(fs1, n, ".", inode_incref(fs1, n));
    inode_dir_add(fs1, n, "..", inode_incref(fs1, n));
    fs->root_inode = n;

    return (FSDevice *)fs;
}

static BOOL fs_is_net(FSDevice *fs)
{
    return (fs->fs_end == fs_mem_end);
}

static FSBaseURL *fs_find_base_url(FSDevice *fs1,
                                   const char *base_url_id)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;
    struct list_head *el;
    FSBaseURL *bu;
    
    list_for_each(el, &fs->base_url_list) {
        bu = list_entry(el, FSBaseURL, link);
        if (!strcmp(bu->base_url_id, base_url_id))
            return bu;
    }
    return NULL;
}

static void fs_base_url_decref(FSDevice *fs, FSBaseURL *bu)
{
    assert(bu->ref_count >= 1);
    if (--bu->ref_count == 0) {
        free(bu->base_url_id);
        free(bu->url);
        free(bu->user);
        free(bu->password);
        list_del(&bu->link);
        free(bu);
    }
}

static FSBaseURL *fs_net_set_base_url(FSDevice *fs1,
                                      const char *base_url_id,
                                      const char *url,
                                      const char *user, const char *password,
                                      AES_KEY *aes_state)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;
    FSBaseURL *bu;
    
    assert(fs_is_net(fs1));
    bu = fs_find_base_url(fs1, base_url_id);
    if (!bu) {
        bu = mallocz(sizeof(*bu));
        bu->base_url_id = strdup(base_url_id);
        bu->ref_count = 1;
        list_add_tail(&bu->link, &fs->base_url_list);
    } else {
        free(bu->url);
        free(bu->user);
        free(bu->password);
    }

    bu->url = strdup(url);
    if (user)
        bu->user = strdup(user);
    else
        bu->user = NULL;
    if (password)
        bu->password = strdup(password);
    else
        bu->password = NULL;
    if (aes_state) {
        bu->encrypted = TRUE;
        bu->aes_state = *aes_state;
    } else {
        bu->encrypted = FALSE;
    }
    return bu;
}

static int fs_net_reset_base_url(FSDevice *fs1,
                                 const char *base_url_id)
{
    FSBaseURL *bu;
    
    assert(fs_is_net(fs1));
    bu = fs_find_base_url(fs1, base_url_id);
    if (!bu)
        return -P9_ENOENT;
    fs_base_url_decref(fs1, bu);
    return 0;
}

#if 0
static void fs_net_set_fs_max_size(FSDevice *fs1, uint64_t fs_max_size)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;

    assert(fs_is_net(fs1));
    fs->fs_max_blocks = to_blocks(fs, fs_max_size);
}
#endif

static int fs_net_set_url(FSDevice *fs1, FSINode *n,
                          const char *base_url_id, FSFileID file_id, uint64_t size)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;
    FSBaseURL *bu;

    assert(fs_is_net(fs1));

    bu = fs_find_base_url(fs1, base_url_id);
    if (!bu)
        return -P9_ENOENT;

    /* XXX: could accept more state */
    if (n->type != FT_REG ||
        n->u.reg.state != REG_STATE_LOCAL ||
        n->u.reg.allocated_size != 0)
        return -P9_EIO;
        
    if (size > 0) {
        n->u.reg.state = REG_STATE_UNLOADED;
        n->u.reg.base_url = bu;
        bu->ref_count++;
        n->u.reg.size = size;
        fs->fs_blocks += to_blocks(fs, size);
        n->u.reg.file_id = file_id;
    }
    return 0;
}

/***********************************************/
/* file list processing */

static int filelist_load_rec(FSDevice *fs1, const char **pp, FSINode *dir,
                             const char *path)
{
    //    FSDeviceMem *fs = (FSDeviceMem *)fs1;
    char fname[1024], lname[1024];
    int ret;
    const char *p;
    FSINodeTypeEnum type;
    uint32_t mode, uid, gid;
    uint64_t size;
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
        if (*p == '.') {
            p++;
            skip_line(&p);
            break;
        }
        if (parse_uint32_base(&mode, &p, 8) < 0) {
            fprintf(stderr, "invalid mode\n");
            return -1;
        }
        type = mode >> 12;
        mode &= 0xfff;
        
        if (parse_uint32(&uid, &p) < 0) {
            fprintf(stderr, "invalid uid\n");
            return -1;
        }

        if (parse_uint32(&gid, &p) < 0) {
            fprintf(stderr, "invalid gid\n");
            return -1;
        }

        n = inode_new(fs1, type, mode, uid, gid);
        
        size = 0;
        switch(type) {
        case FT_CHR:
        case FT_BLK:
            if (parse_uint32(&n->u.dev.major, &p) < 0) {
                fprintf(stderr, "invalid major\n");
                return -1;
            }
            if (parse_uint32(&n->u.dev.minor, &p) < 0) {
                fprintf(stderr, "invalid minor\n");
                return -1;
            }
            break;
        case FT_REG:
            if (parse_uint64(&size, &p) < 0) {
                fprintf(stderr, "invalid size\n");
                return -1;
            }
            break;
        case FT_DIR:
            inode_dir_add(fs1, n, ".", inode_incref(fs1, n));
            inode_dir_add(fs1, n, "..", inode_incref(fs1, dir));
            break;
        default:
            break;
        }
        
        /* modification time */
        if (parse_time(&n->mtime_sec, &n->mtime_nsec, &p) < 0) {
            fprintf(stderr, "invalid mtime\n");
            return -1;
        }

        if (parse_fname(fname, sizeof(fname), &p) < 0) {
            fprintf(stderr, "invalid filename\n");
            return -1;
        }
        inode_dir_add(fs1, dir, fname, n);
        
        if (type == FT_LNK) {
            if (parse_fname(lname, sizeof(lname), &p) < 0) {
                fprintf(stderr, "invalid symlink name\n");
                return -1;
            }
            n->u.symlink.name = strdup(lname);
        } else if (type == FT_REG && size > 0) {
            FSFileID file_id;
            if (parse_file_id(&file_id, &p) < 0) {
                fprintf(stderr, "invalid file id\n");
                return -1;
            }
            fs_net_set_url(fs1, n, "/", file_id, size);
#ifdef DEBUG_CACHE
            n->u.reg.filename = compose_path(path, fname);
#endif
        }

        skip_line(&p);
        
        if (type == FT_DIR) {
            char *path1;
            path1 = compose_path(path, fname);
            ret = filelist_load_rec(fs1, &p, n, path1);
            free(path1);
            if (ret)
                return ret;
        }
    }
    *pp = p;
    return 0;
}

static int filelist_load(FSDevice *fs1, const char *str)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;
    int ret;
    const char *p;
    
    if (parse_tag_version(str) != 1)
        return -1;
    p = skip_header(str);
    if (!p)
        return -1;
    ret = filelist_load_rec(fs1, &p, fs->root_inode, "");
    return ret;
}

/* get the file content from the file cache. The cache may be freed at any
   filesystem manipulation */
int fs_net_get_file(FSDevice *fs1, uint8_t **pbuf, const char *path)
{
    FSINode *n;

    n = inode_search_path(fs1, path);
    if (n->type != FT_REG ||
        (n->u.reg.state != REG_STATE_LOADED &&
         n->u.reg.state != REG_STATE_LOCAL)) {
        *pbuf = NULL;
        return P9_EIO;
    } else {
        *pbuf = n->u.reg.data;
        return n->u.reg.size;
    }
}

/************************************************************/
/* FS init from network */

static void __attribute__((format(printf, 1, 2))) fatal_error(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "Error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}

static void fs_create_cmd(FSDevice *fs)
{
    FSFile *root_fd;
    FSQID qid;
    FSINode *n;
    
    assert(!fs->fs_attach(fs, &root_fd, &qid, 0, "", ""));
    assert(!fs->fs_create(fs, &qid, root_fd, FSCMD_NAME, P9_O_RDWR | P9_O_TRUNC,
                          0666, 0));
    n = root_fd->inode;
    n->u.reg.is_fscmd = TRUE;
    fs->fs_delete(fs, root_fd);
}

typedef struct {
    FSDevice *fs;
    char *url;
    void (*start_cb)(void *opaque);
    void *start_opaque;
    
    FSFile *root_fd;
    FSFile *fd;
    int file_index;
    
} FSNetInitState;

static void fs_initial_sync(FSDevice *fs,
                            const char *url, void (*start_cb)(void *opaque),
                            void *start_opaque);
static void head_loaded(FSDevice *fs, FSFile *f, int64_t size, void *opaque);
static void filelist_loaded(FSDevice *fs, FSFile *f, int64_t size, void *opaque);
static void kernel_load_cb(FSDevice *fs, FSQID *qid, int err,
                           void *opaque);
static void preload_parse(FSDevice *fs);

#ifdef EMSCRIPTEN
static FSDevice *fs_import_fs;
#endif

FSDevice *fs_net_init(const char *url, void (*start_cb)(void *opaque),
                      void *start_opaque)
{
    FSDevice *fs;
    
    fs_wget_init();
    
    fs = fs_mem_init();
#ifdef EMSCRIPTEN
    if (!fs_import_fs)
        fs_import_fs = fs;
#endif

    fs_create_cmd(fs);

    if (url) {
        fs_initial_sync(fs, url, start_cb, start_opaque);
    }
    return fs;
}

static void fs_initial_sync(FSDevice *fs,
                            const char *url, void (*start_cb)(void *opaque),
                            void *start_opaque)
{
    FSNetInitState *s;
    FSFile *head_fd;
    FSQID qid;
    char *head_url;
    char buf[128];
    struct timeval tv;
    
    s = mallocz(sizeof(*s));
    s->fs = fs;
    s->url = strdup(url);
    s->start_cb = start_cb;
    s->start_opaque = start_opaque;
    assert(!fs->fs_attach(fs, &s->root_fd, &qid, 0, "", ""));
    
    /* avoid using cached version */
    gettimeofday(&tv, NULL);
    snprintf(buf, sizeof(buf), HEAD_FILENAME "?nocache=%" PRId64,
             (int64_t)tv.tv_sec * 1000000 + tv.tv_usec);
    head_url = compose_url(s->url, buf);
    head_fd = fs_dup(fs, s->root_fd);
    assert(!fs->fs_create(fs, &qid, head_fd, ".head",
                          P9_O_RDWR | P9_O_TRUNC, 0644, 0));
    fs_wget_file2(fs, head_fd, head_url, NULL, NULL, NULL, 0,
                  head_loaded, s, NULL);
    free(head_url);
}

static void head_loaded(FSDevice *fs, FSFile *f, int64_t size, void *opaque)
{
    FSNetInitState *s = opaque;
    char *buf, *root_url, *url;
    char fname[FILEID_SIZE_MAX];
    FSFileID root_id;
    FSFile *new_filelist_fd;
    FSQID qid;
    
    if (size < 0)
        fatal_error("could not load 'head' file (HTTP error=%d)", -(int)size);
    
    buf = malloc(size + 1);
    fs->fs_read(fs, f, 0, (uint8_t *)buf, size);
    buf[size] = '\0';
    fs->fs_delete(fs, f);
    fs->fs_unlinkat(fs, s->root_fd, ".head");

    if (parse_tag_version(buf) != 1)
        fatal_error("invalid head version");

    if (parse_tag_file_id(&root_id, buf, "RootID") < 0)
        fatal_error("expected RootID tag");
        
    /* set the Root URL in the filesystem */
    root_url = compose_url(s->url, ROOT_FILENAME);
    fs_net_set_base_url(fs, "/", root_url, NULL, NULL, NULL);
    
    new_filelist_fd = fs_dup(fs, s->root_fd);
    assert(!fs->fs_create(fs, &qid, new_filelist_fd, ".filelist.txt",
                          P9_O_RDWR | P9_O_TRUNC, 0644, 0));

    file_id_to_filename(fname, root_id);
    url = compose_url(root_url, fname);
    fs_wget_file2(fs, new_filelist_fd, url, NULL, NULL, NULL, 0,
                  filelist_loaded, s, NULL);
    free(root_url);
    free(url);
}

static void filelist_loaded(FSDevice *fs, FSFile *f, int64_t size, void *opaque)
{
    FSNetInitState *s = opaque;
    uint8_t *buf;

    if (size < 0)
        fatal_error("could not load file list (HTTP error=%d)", -(int)size);
    
    buf = malloc(size + 1);
    fs->fs_read(fs, f, 0, buf, size);
    buf[size] = '\0';
    fs->fs_delete(fs, f);
    fs->fs_unlinkat(fs, s->root_fd, ".filelist.txt");
    
    if (filelist_load(fs, (char *)buf) != 0)
        fatal_error("error while parsing file list");

    /* try to load the kernel and the preload file */
    s->file_index = 0;
    kernel_load_cb(fs, NULL, 0, s);
}


#define FILE_LOAD_COUNT 2

static const char *kernel_file_list[FILE_LOAD_COUNT] = {
    "kernel.bin",
    ".preload",
};

static void kernel_load_cb(FSDevice *fs, FSQID *qid1, int err,
                           void *opaque)
{
    FSNetInitState *s = opaque;
    FSQID qid;

    if (s->fd) {
        fs->fs_delete(fs, s->fd);
        s->fd = NULL;
    }
    
    if (s->file_index >= FILE_LOAD_COUNT) {
        /* all files are loaded */
        preload_parse(fs);
        fs->fs_delete(fs, s->root_fd);
        if (s->start_cb)
            s->start_cb(s->start_opaque);
        free(s);
    } else {
        s->fd = fs_walk_path(fs, s->root_fd, kernel_file_list[s->file_index++]);
        if (!s->fd)
            goto done;
        err = fs->fs_open(fs, &qid, s->fd, P9_O_RDONLY, kernel_load_cb, s);
        if (err <= 0) {
        done:
            kernel_load_cb(fs, NULL, 0, s);
        }
    }
}

static void preload_parse_str(FSDevice *fs1, const char *p)
{
    FSDeviceMem *fs = (FSDeviceMem *)fs1;
    char fname[1024];
    PreloadEntry *pe;
    PreloadFile *pf;
    FSINode *n;
    
    for(;;) {
        while (isspace_nolf(*p))
            p++;
        if (*p == '\n') {
            p++;
            continue;
        }
        if (*p == '\0')
            break;
        if (parse_fname(fname, sizeof(fname), &p) < 0) {
            fprintf(stderr, "invalid filename\n");
            return;
        }
        //        printf("preload file='%s\n", fname);
        n = inode_search_path(fs1, fname);
        if (!n || n->type != FT_REG || n->u.reg.state == REG_STATE_LOCAL) {
            fprintf(stderr, "invalid preload file: '%s'\n", fname);
            while (*p != '\n' && *p != '\0')
                p++;
        } else if (USE_PRELOAD) {
            pe = mallocz(sizeof(*pe));
            pe->file_id = n->u.reg.file_id;
            init_list_head(&pe->file_list);
            list_add_tail(&pe->link, &fs->preload_list);
            for(;;) {
                while (isspace_nolf(*p))
                    p++;
                if (*p == '\0' || *p == '\n')
                    break;
                if (parse_fname(fname, sizeof(fname), &p) < 0) {
                    fprintf(stderr, "invalid filename\n");
                    return;
                }
                //                printf("  adding '%s'\n", fname);
                pf = mallocz(sizeof(*pf));
                pf->name = strdup(fname);
                list_add_tail(&pf->link, &pe->file_list); 
            }
        }
    }
}

static void preload_parse(FSDevice *fs)
{
    FSINode *n;
    char *buf;
    size_t size;
    
    n = inode_search_path(fs, ".preload");
    if (!n || n->type != FT_REG || n->u.reg.state != REG_STATE_LOADED)
        return;
    /* transform to zero terminated string */
    size = n->u.reg.size;
    buf = malloc(size + 1);
    memcpy(buf, n->u.reg.data, size);
    buf[size] = '\0';
    preload_parse_str(fs, buf);
    free(buf);
}

/************************************************************/
/* FS user interface */

typedef struct CmdXHRState {
    FSFile *req_fd;
    FSFile *root_fd;
    FSFile *fd;
    FSFile *post_fd;
    AES_KEY aes_state;
} CmdXHRState;

static void fs_cmd_xhr_on_load(FSDevice *fs, FSFile *f, int64_t size,
                               void *opaque);

static int parse_hex_buf(uint8_t *buf, int buf_size, const char **pp)
{
    char buf1[1024];
    int len;
    
    if (parse_fname(buf1, sizeof(buf1), pp) < 0)
        return -1;
    len = strlen(buf1);
    if ((len & 1) != 0)
        return -1;
    len >>= 1;
    if (len > buf_size)
        return -1;
    if (decode_hex(buf, buf1, len) < 0)
        return -1;
    return len;
}

static int fs_cmd_xhr(FSDevice *fs, FSFile *f,
                      const char *p, uint32_t uid, uint32_t gid)
{
    char url[1024], post_filename[1024], filename[1024];
    char user_buf[128], *user;
    char password_buf[128], *password;
    FSQID qid;
    FSFile *fd, *root_fd, *post_fd;
    uint64_t post_data_len;
    int err, aes_key_len;
    CmdXHRState *s;
    char *name;
    AES_KEY *paes_state;
    uint8_t aes_key[FS_KEY_LEN];
    uint32_t flags;
    FSCMDRequest *req;

    /* a request is already done or in progress */
    if (f->req != NULL)
        return -P9_EIO;

    if (parse_fname(url, sizeof(url), &p) < 0)
        goto fail;
    if (parse_fname(user_buf, sizeof(user_buf), &p) < 0)
        goto fail;
    if (parse_fname(password_buf, sizeof(password_buf), &p) < 0)
        goto fail;
    if (parse_fname(post_filename, sizeof(post_filename), &p) < 0)
        goto fail;
    if (parse_fname(filename, sizeof(filename), &p) < 0)
        goto fail;
    aes_key_len = parse_hex_buf(aes_key, FS_KEY_LEN, &p);
    if (aes_key_len < 0)
        goto fail;
    if (parse_uint32(&flags, &p) < 0)
        goto fail;
    if (aes_key_len != 0 && aes_key_len != FS_KEY_LEN)
        goto fail;

    if (user_buf[0] != '\0')
        user = user_buf;
    else
        user = NULL;
    if (password_buf[0] != '\0')
        password = password_buf;
    else
        password = NULL;

    //    printf("url='%s' '%s' '%s' filename='%s'\n", url, user, password, filename);
    assert(!fs->fs_attach(fs, &root_fd, &qid, uid, "", ""));
    post_fd = NULL;

    fd = fs_walk_path1(fs, root_fd, filename, &name);
    if (!fd) {
        err = -P9_ENOENT;
        goto fail1;
    }
    /* XXX: until fs_create is fixed */
    fs->fs_unlinkat(fs, fd, name);

    err = fs->fs_create(fs, &qid, fd, name,
                        P9_O_RDWR | P9_O_TRUNC, 0600, gid);
    if (err < 0) {
        goto fail1;
    }

    if (post_filename[0] != '\0') {
        FSINode *n;
        
        post_fd = fs_walk_path(fs, root_fd, post_filename);
        if (!post_fd) {
            err = -P9_ENOENT;
            goto fail1;
        }
        err = fs->fs_open(fs, &qid, post_fd, P9_O_RDONLY, NULL, NULL);
        if (err < 0)
            goto fail1;
        n = post_fd->inode;
        assert(n->type == FT_REG && n->u.reg.state == REG_STATE_LOCAL);
        post_data_len = n->u.reg.size;
    } else {
        post_data_len = 0;
    }

    s = mallocz(sizeof(*s));
    s->root_fd = root_fd;
    s->fd = fd;
    s->post_fd = post_fd;
    if (aes_key_len != 0) {
        AES_set_decrypt_key(aes_key, FS_KEY_LEN * 8, &s->aes_state);
        paes_state = &s->aes_state;
    } else {
        paes_state = NULL;
    }

    req = mallocz(sizeof(*req));
    req->type = FS_CMD_XHR;
    req->reply_len = 0;
    req->xhr_state = s;
    s->req_fd = f;
    f->req = req;
    
    fs_wget_file2(fs, fd, url, user, password, post_fd, post_data_len,
                  fs_cmd_xhr_on_load, s, paes_state);
    return 0;
 fail1:
    if (fd)
        fs->fs_delete(fs, fd);
    if (post_fd)
        fs->fs_delete(fs, post_fd);
    fs->fs_delete(fs, root_fd);
    return err;
 fail:
    return -P9_EIO;
}

static void fs_cmd_xhr_on_load(FSDevice *fs, FSFile *f, int64_t size,
                               void *opaque)
{
    CmdXHRState *s = opaque;
    FSCMDRequest *req;
    int ret;
    
    //    printf("fs_cmd_xhr_on_load: size=%d\n", (int)size);

    if (s->fd)
        fs->fs_delete(fs, s->fd);
    if (s->post_fd)
        fs->fs_delete(fs, s->post_fd);
    fs->fs_delete(fs, s->root_fd);
    
    if (s->req_fd) {
        req = s->req_fd->req;
        if (size < 0) {
            ret = size;
        } else {
            ret = 0;
        }
        put_le32(req->reply_buf, ret);
        req->reply_len = sizeof(ret);
        req->xhr_state = NULL;
    }
    free(s);
}

static int fs_cmd_set_base_url(FSDevice *fs, const char *p)
{
    //    FSDeviceMem *fs1 = (FSDeviceMem *)fs;
    char url[1024], base_url_id[1024];
    char user_buf[128], *user;
    char password_buf[128], *password;
    AES_KEY aes_state, *paes_state;
    uint8_t aes_key[FS_KEY_LEN];
    int aes_key_len;
    
    if (parse_fname(base_url_id, sizeof(base_url_id), &p) < 0)
        goto fail;
    if (parse_fname(url, sizeof(url), &p) < 0)
        goto fail;
    if (parse_fname(user_buf, sizeof(user_buf), &p) < 0)
        goto fail;
    if (parse_fname(password_buf, sizeof(password_buf), &p) < 0)
        goto fail;
    aes_key_len = parse_hex_buf(aes_key, FS_KEY_LEN, &p);
    if (aes_key_len < 0)
        goto fail;

    if (user_buf[0] != '\0')
        user = user_buf;
    else
        user = NULL;
    if (password_buf[0] != '\0')
        password = password_buf;
    else
        password = NULL;

    if (aes_key_len != 0) {
        if (aes_key_len != FS_KEY_LEN)
            goto fail;
        AES_set_decrypt_key(aes_key, FS_KEY_LEN * 8, &aes_state);
        paes_state = &aes_state;
    } else {
        paes_state = NULL;
    }

    fs_net_set_base_url(fs, base_url_id, url, user, password,
                        paes_state);
    return 0;
 fail:
    return -P9_EINVAL;
}

static int fs_cmd_reset_base_url(FSDevice *fs, const char *p)
{
    char base_url_id[1024];
    
    if (parse_fname(base_url_id, sizeof(base_url_id), &p) < 0)
        goto fail;
    fs_net_reset_base_url(fs, base_url_id);
    return 0;
 fail:
    return -P9_EINVAL;
}

static int fs_cmd_set_url(FSDevice *fs, const char *p)
{
    char base_url_id[1024];
    char filename[1024];
    FSFileID file_id;
    uint64_t size;
    FSINode *n;
    
    if (parse_fname(filename, sizeof(filename), &p) < 0)
        goto fail;
    if (parse_fname(base_url_id, sizeof(base_url_id), &p) < 0)
        goto fail;
    if (parse_file_id(&file_id, &p) < 0)
        goto fail;
    if (parse_uint64(&size, &p) < 0)
        goto fail;
    
    n = inode_search_path(fs, filename);
    if (!n) {
        return -P9_ENOENT;
    }
    return fs_net_set_url(fs, n, base_url_id, file_id, size);
 fail:
    return -P9_EINVAL;
}

static int fs_cmd_export_file(FSDevice *fs, const char *p)
{
    char filename[1024];
    FSINode *n;
    const char *name;
    
    if (parse_fname(filename, sizeof(filename), &p) < 0)
        goto fail;
    n = inode_search_path(fs, filename);
    if (!n)
        return -P9_ENOENT;
    if (n->type != FT_REG ||
        (n->u.reg.state != REG_STATE_LOCAL &&
         n->u.reg.state != REG_STATE_LOADED))
        goto fail;
    name = strrchr(filename, '/');
    if (name)
        name++;
    else
        name = filename;
    fs_export_file(name, n->u.reg.data, n->u.reg.size);
    return 0;
 fail:
    return -P9_EIO;
}

/* PBKDF2 crypto acceleration */
static int fs_cmd_pbkdf2(FSDevice *fs, FSFile *f, const char *p)
{
    uint8_t pwd[1024];
    uint8_t salt[128];
    uint32_t iter, key_len;
    int pwd_len, salt_len;
    FSCMDRequest *req;
    
    /* a request is already done or in progress */
    if (f->req != NULL)
        return -P9_EIO;

    pwd_len = parse_hex_buf(pwd, sizeof(pwd), &p);
    if (pwd_len < 0)
        goto fail;
    salt_len = parse_hex_buf(salt, sizeof(salt), &p);
    if (pwd_len < 0)
        goto fail;
    if (parse_uint32(&iter, &p) < 0)
        goto fail;
    if (parse_uint32(&key_len, &p) < 0)
        goto fail;
    if (key_len > FS_CMD_REPLY_LEN_MAX ||
        key_len == 0)
        goto fail;
    req = mallocz(sizeof(*req));
    req->type = FS_CMD_PBKDF2;
    req->reply_len = key_len;
    pbkdf2_hmac_sha256(pwd, pwd_len, salt, salt_len, iter, key_len,
                       req->reply_buf);
    f->req = req;
    return 0;
 fail:
    return -P9_EINVAL;
}


static int fs_cmd_write(FSDevice *fs, FSFile *f, uint64_t offset,
                        const uint8_t *buf, int buf_len)
{
    char *buf1;
    const char *p;
    char cmd[64];
    int err;
    
    /* transform into a string */
    buf1 = malloc(buf_len + 1);
    memcpy(buf1, buf, buf_len);
    buf1[buf_len] = '\0';
    
    err = 0;
    p = buf1;
    if (parse_fname(cmd, sizeof(cmd), &p) < 0)
        goto fail;
    if (!strcmp(cmd, "xhr")) {
        err = fs_cmd_xhr(fs, f, p, f->uid, 0);
    } else if (!strcmp(cmd, "set_base_url")) {
        err = fs_cmd_set_base_url(fs, p);
    } else if (!strcmp(cmd, "reset_base_url")) {
        err = fs_cmd_reset_base_url(fs, p);
    } else if (!strcmp(cmd, "set_url")) {
        err = fs_cmd_set_url(fs, p);
    } else if (!strcmp(cmd, "export_file")) {
        err = fs_cmd_export_file(fs, p);
    } else if (!strcmp(cmd, "pbkdf2")) {
        err = fs_cmd_pbkdf2(fs, f, p);
    } else {
        printf("unknown command: '%s'\n", cmd);
    fail:
        err = -P9_EIO;
    }
    free(buf1);
    if (err == 0)
        return buf_len;
    else
        return err;
}

static int fs_cmd_read(FSDevice *fs, FSFile *f, uint64_t offset,
                       uint8_t *buf, int buf_len)
{
    FSCMDRequest *req;
    int l;
    
    req = f->req;
    if (!req)
        return -P9_EIO;
    l = min_int(req->reply_len, buf_len);
    memcpy(buf, req->reply_buf, l);
    return l;
}

static void fs_cmd_close(FSDevice *fs, FSFile *f)
{
    FSCMDRequest *req;
    req = f->req;

    if (req) {
        if (req->xhr_state) {
            req->xhr_state->req_fd = NULL;
        }
        free(req);
        f->req = NULL;
    }
}

/* Create a .fscmd_pwd file to avoid passing the password thru the
   Linux command line */
void fs_net_set_pwd(FSDevice *fs, const char *pwd)
{
    FSFile *root_fd;
    FSQID qid;
    
    assert(fs_is_net(fs));
    
    assert(!fs->fs_attach(fs, &root_fd, &qid, 0, "", ""));
    assert(!fs->fs_create(fs, &qid, root_fd, ".fscmd_pwd", P9_O_RDWR | P9_O_TRUNC,
                          0600, 0));
    fs->fs_write(fs, root_fd, 0, (uint8_t *)pwd, strlen(pwd));
    fs->fs_delete(fs, root_fd);
}

/* external file import */

#ifdef EMSCRIPTEN

#define IMPORT_FILE_PATH "/tmp"

void fs_import_file(const char *filename, uint8_t *buf, int buf_len)
{
    FSDevice *fs;
    FSFile *fd, *root_fd;
    FSQID qid;
    
    //    printf("importing file: %s len=%d\n", filename, buf_len);
    fs = fs_import_fs;
    if (!fs) {
        free(buf);
        return;
    }
    
    assert(!fs->fs_attach(fs, &root_fd, &qid, 1000, "", ""));
    fd = fs_walk_path(fs, root_fd, IMPORT_FILE_PATH);
    if (!fd)
        goto fail;
    fs_unlinkat(fs, root_fd, filename);
    if (fs->fs_create(fs, &qid, fd, filename, P9_O_RDWR | P9_O_TRUNC,
                      0600, 0) < 0)
        goto fail;
    fs->fs_write(fs, fd, 0, buf, buf_len);
 fail:
    if (fd)
        fs->fs_delete(fs, fd);
    if (root_fd)
        fs->fs_delete(fs, root_fd);
    free(buf);
}

#else

void fs_export_file(const char *filename,
                    const uint8_t *buf, int buf_len)
{
}

#endif
