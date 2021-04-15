/*
 * HTTP file download
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
#else
#include <curl/multi.h>
#endif

/***********************************************/
/* HTTP get */

#ifdef EMSCRIPTEN

struct XHRState {
    void *opaque;
    WGetWriteCallback *cb;
};

static int downloading_count;

void fs_wget_init(void)
{
}

extern void fs_wget_update_downloading(int flag);

static void fs_wget_update_downloading_count(int incr)
{
    int prev_state, state;
    prev_state = (downloading_count > 0);
    downloading_count += incr;
    state = (downloading_count > 0);
    if (prev_state != state)
        fs_wget_update_downloading(state);
}

static void fs_wget_onerror(unsigned int handle, void *opaque, int status,
                            const char *status_text)
{
    XHRState *s = opaque;
    if (status <= 0)
        status = -404; /* HTTP not found error */
    else
        status = -status;
    fs_wget_update_downloading_count(-1);
    if (s->cb)
        s->cb(s->opaque, status, NULL, 0);
}

static void fs_wget_onload(unsigned int handle,
                           void *opaque, void *data, unsigned int size)
{
    XHRState *s = opaque;
    fs_wget_update_downloading_count(-1);
    if (s->cb)
        s->cb(s->opaque, 0, data, size);
}

extern int emscripten_async_wget3_data(const char* url, const char* requesttype, const char *user, const char *password, const uint8_t *post_data, int post_data_len, void *arg, int free, em_async_wget2_data_onload_func onload, em_async_wget2_data_onerror_func onerror, em_async_wget2_data_onprogress_func onprogress);

XHRState *fs_wget2(const char *url, const char *user, const char *password,
                   WGetReadCallback *read_cb, uint64_t post_data_len,
                   void *opaque, WGetWriteCallback *cb, BOOL single_write)
{
    XHRState *s;
    const char *request;
    uint8_t *post_data;
    
    s = mallocz(sizeof(*s));
    s->opaque = opaque;
    s->cb = cb;

    if (post_data_len != 0) {
        request = "POST";
        post_data = malloc(post_data_len);
        read_cb(opaque, post_data, post_data_len);
    } else {
        request = "GET";
        post_data = NULL;
    }
    fs_wget_update_downloading_count(1);

    emscripten_async_wget3_data(url, request, user, password,
                                post_data, post_data_len, s, 1, fs_wget_onload,
                                fs_wget_onerror, NULL);
    if (post_data_len != 0)
        free(post_data);
    return s;
}

void fs_wget_free(XHRState *s)
{
    s->cb = NULL;
    s->opaque = NULL;
}

#else

struct XHRState {
    struct list_head link;
    CURL *eh;
    void *opaque;
    WGetWriteCallback *write_cb;
    WGetReadCallback *read_cb;

    BOOL single_write;
    DynBuf dbuf; /* used if single_write */
};

typedef struct {
    struct list_head link;
    int64_t timeout;
    void (*cb)(void *opaque);
    void *opaque;
} AsyncCallState;

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

static size_t fs_wget_write_cb(char *ptr, size_t size, size_t nmemb,
                               void *userdata)
{
    XHRState *s = userdata;
    size *= nmemb;

    if (s->single_write) {
        dbuf_write(&s->dbuf, s->dbuf.size, (void *)ptr, size);
    } else {
        s->write_cb(s->opaque, 1, ptr, size);
    }
    return size;
}

static size_t fs_wget_read_cb(char *ptr, size_t size, size_t nmemb,
                              void *userdata)
{
    XHRState *s = userdata;
    size *= nmemb;
    return s->read_cb(s->opaque, ptr, size);
}

XHRState *fs_wget2(const char *url, const char *user, const char *password,
                   WGetReadCallback *read_cb, uint64_t post_data_len,
                   void *opaque, WGetWriteCallback *write_cb, BOOL single_write)
{
    XHRState *s;
    s = mallocz(sizeof(*s));
    s->eh = curl_easy_init();
    s->opaque = opaque;
    s->write_cb = write_cb;
    s->read_cb = read_cb;
    s->single_write = single_write;
    dbuf_init(&s->dbuf);
    
    curl_easy_setopt(s->eh, CURLOPT_PRIVATE, s);
    curl_easy_setopt(s->eh, CURLOPT_WRITEDATA, s);
    curl_easy_setopt(s->eh, CURLOPT_WRITEFUNCTION, fs_wget_write_cb);
    curl_easy_setopt(s->eh, CURLOPT_HEADER, 0);
    curl_easy_setopt(s->eh, CURLOPT_URL, url);
    curl_easy_setopt(s->eh, CURLOPT_VERBOSE, 0L);
    curl_easy_setopt(s->eh, CURLOPT_ACCEPT_ENCODING, "");
    if (user) {
        curl_easy_setopt(s->eh, CURLOPT_USERNAME, user);
        curl_easy_setopt(s->eh, CURLOPT_PASSWORD, password);
    }
    if (post_data_len != 0) {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers,
                                    "Content-Type: application/octet-stream");
        curl_easy_setopt(s->eh, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(s->eh, CURLOPT_POST, 1L);
        curl_easy_setopt(s->eh, CURLOPT_POSTFIELDSIZE_LARGE,
                         (curl_off_t)post_data_len);
        curl_easy_setopt(s->eh, CURLOPT_READDATA, s);
        curl_easy_setopt(s->eh, CURLOPT_READFUNCTION, fs_wget_read_cb);
    }
    curl_multi_add_handle(curl_multi_ctx, s->eh);
    list_add_tail(&s->link, &xhr_list);
    return s;
}

void fs_wget_free(XHRState *s)
{
    dbuf_free(&s->dbuf);
    curl_easy_cleanup(s->eh);
    list_del(&s->link);
    free(s);
}

/* timeout is in ms */
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
                if (s->single_write) {
                    s->write_cb(s->opaque, 0, s->dbuf.buf, s->dbuf.size);
                } else {
                    s->write_cb(s->opaque, 0, NULL, 0);
                }
            } else {
                s->write_cb(s->opaque, -http_code, NULL, 0);
            }
            curl_multi_remove_handle(curl_multi_ctx, s->eh);
            curl_easy_cleanup(s->eh);
            dbuf_free(&s->dbuf);
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

void fs_net_event_loop(FSNetEventLoopCompletionFunc *cb, void *opaque)
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
        if (cb) {
            if (cb(opaque))
                break;
        } else {
            if (list_empty(&xhr_list))
                break;
        }
        tv.tv_sec = timeout / 1000;
        tv.tv_usec = (timeout % 1000) * 1000;
        select(fd_max + 1, &rfds, &wfds, &efds, &tv);
    }
}

#endif /* !EMSCRIPTEN */

XHRState *fs_wget(const char *url, const char *user, const char *password,
                  void *opaque, WGetWriteCallback *cb, BOOL single_write)
{
    return fs_wget2(url, user, password, NULL, 0, opaque, cb, single_write);
}

/***********************************************/
/* file decryption */

#define ENCRYPTED_FILE_HEADER_SIZE (4 + AES_BLOCK_SIZE)

#define DEC_BUF_SIZE (256 * AES_BLOCK_SIZE)

struct DecryptFileState {
    DecryptFileCB *write_cb;
    void *opaque;
    int dec_state;
    int dec_buf_pos;
    AES_KEY *aes_state;
    uint8_t iv[AES_BLOCK_SIZE];
    uint8_t dec_buf[DEC_BUF_SIZE];
};

DecryptFileState *decrypt_file_init(AES_KEY *aes_state,
                                    DecryptFileCB *write_cb,
                                    void *opaque)
{
    DecryptFileState *s;
    s = mallocz(sizeof(*s));
    s->write_cb = write_cb;
    s->opaque = opaque;
    s->aes_state = aes_state;
    return s;
}
    
int decrypt_file(DecryptFileState *s, const uint8_t *data,
                 size_t size)
{
    int l, len, ret;

    while (size != 0) {
        switch(s->dec_state) {
        case 0:
            l = min_int(size, ENCRYPTED_FILE_HEADER_SIZE - s->dec_buf_pos);
            memcpy(s->dec_buf + s->dec_buf_pos, data, l);
            s->dec_buf_pos += l;
            if (s->dec_buf_pos >= ENCRYPTED_FILE_HEADER_SIZE) {
                if (memcmp(s->dec_buf, encrypted_file_magic, 4) != 0)
                    return -1;
                memcpy(s->iv, s->dec_buf + 4, AES_BLOCK_SIZE);
                s->dec_state = 1;
                s->dec_buf_pos = 0;
            }
            break;
        case 1:
            l = min_int(size, DEC_BUF_SIZE - s->dec_buf_pos);
            memcpy(s->dec_buf + s->dec_buf_pos, data, l);
            s->dec_buf_pos += l;
            if (s->dec_buf_pos >= DEC_BUF_SIZE) {
                /* keep one block in case it is the padding */
                len = s->dec_buf_pos - AES_BLOCK_SIZE;
                AES_cbc_encrypt(s->dec_buf, s->dec_buf, len,
                                s->aes_state, s->iv, FALSE);
                ret = s->write_cb(s->opaque, s->dec_buf, len);
                if (ret < 0)
                    return ret;
                memcpy(s->dec_buf, s->dec_buf + s->dec_buf_pos - AES_BLOCK_SIZE,
                       AES_BLOCK_SIZE);
                s->dec_buf_pos = AES_BLOCK_SIZE;
            }
            break;
        default:
            abort();
        }
        data += l;
        size -= l;
    }
    return 0;
}

/* write last blocks */
int decrypt_file_flush(DecryptFileState *s)
{
    int len, pad_len, ret;

    if (s->dec_state != 1)
        return -1;
    len = s->dec_buf_pos;
    if (len == 0 || 
        (len % AES_BLOCK_SIZE) != 0)
        return -1;
    AES_cbc_encrypt(s->dec_buf, s->dec_buf, len,
                    s->aes_state, s->iv, FALSE);
    pad_len = s->dec_buf[s->dec_buf_pos - 1];
    if (pad_len < 1 || pad_len > AES_BLOCK_SIZE)
        return -1;
    len -= pad_len;
    if (len != 0) {
        ret = s->write_cb(s->opaque, s->dec_buf, len);
        if (ret < 0)
            return ret;
    }
    return 0;
}

void decrypt_file_end(DecryptFileState *s)
{
    free(s);
}

/* XHR file */

typedef struct {
    FSDevice *fs;
    FSFile *f;
    int64_t pos;
    FSWGetFileCB *cb;
    void *opaque;
    FSFile *posted_file;
    int64_t read_pos;
    DecryptFileState *dec_state;
} FSWGetFileState;

static int fs_wget_file_write_cb(void *opaque, const uint8_t *data,
                                 size_t size)
{
    FSWGetFileState *s = opaque;
    FSDevice *fs = s->fs;
    int ret;

    ret = fs->fs_write(fs, s->f, s->pos, data, size);
    if (ret < 0)
        return ret;
    s->pos += ret;
    return ret;
}

static void fs_wget_file_on_load(void *opaque, int err, void *data, size_t size)
{
    FSWGetFileState *s = opaque;
    FSDevice *fs = s->fs;
    int ret;
    int64_t ret_size;
    
    //    printf("err=%d size=%ld\n", err, size);
    if (err < 0) {
        ret_size = err;
        goto done;
    } else {
        if (s->dec_state) {
            ret = decrypt_file(s->dec_state, data, size);
            if (ret >= 0 && err == 0) {
                /* handle the end of file */
                decrypt_file_flush(s->dec_state);
            }
        } else {
            ret = fs_wget_file_write_cb(s, data, size);
        }
        if (ret < 0) {
            ret_size = ret;
            goto done;
        } else if (err == 0) {
            /* end of transfer */
            ret_size = s->pos;
        done:
            s->cb(fs, s->f, ret_size, s->opaque);
            if (s->dec_state)
                decrypt_file_end(s->dec_state);
            free(s);
        }
    }
}

static size_t fs_wget_file_read_cb(void *opaque, void *data, size_t size)
{
    FSWGetFileState *s = opaque;
    FSDevice *fs = s->fs;
    int ret;
    
    if (!s->posted_file)
        return 0;
    ret = fs->fs_read(fs, s->posted_file, s->read_pos, data, size);
    if (ret < 0)
        return 0;
    s->read_pos += ret;
    return ret;
}

void fs_wget_file2(FSDevice *fs, FSFile *f, const char *url,
                   const char *user, const char *password,
                   FSFile *posted_file, uint64_t post_data_len,
                   FSWGetFileCB *cb, void *opaque,
                   AES_KEY *aes_state)
{
    FSWGetFileState *s;
    s = mallocz(sizeof(*s));
    s->fs = fs;
    s->f = f;
    s->pos = 0;
    s->cb = cb;
    s->opaque = opaque;
    s->posted_file = posted_file;
    s->read_pos = 0;
    if (aes_state) {
        s->dec_state = decrypt_file_init(aes_state, fs_wget_file_write_cb, s);
    }
    
    fs_wget2(url, user, password, fs_wget_file_read_cb, post_data_len,
             s, fs_wget_file_on_load, FALSE);
}

/***********************************************/
/* PBKDF2 */

#ifdef USE_BUILTIN_CRYPTO

#define HMAC_BLOCK_SIZE 64

typedef struct {
    SHA256_CTX ctx;
    uint8_t K[HMAC_BLOCK_SIZE + SHA256_DIGEST_LENGTH];
} HMAC_SHA256_CTX;

void hmac_sha256_init(HMAC_SHA256_CTX *s, const uint8_t *key, int key_len)
{
    int i, l;
    
    if (key_len > HMAC_BLOCK_SIZE) {
        SHA256(key, key_len, s->K);
        l = SHA256_DIGEST_LENGTH;
    } else {
        memcpy(s->K, key, key_len);
        l = key_len;
    }
    memset(s->K + l, 0, HMAC_BLOCK_SIZE - l);
    for(i = 0; i < HMAC_BLOCK_SIZE; i++)
        s->K[i] ^= 0x36;
    SHA256_Init(&s->ctx);
    SHA256_Update(&s->ctx, s->K, HMAC_BLOCK_SIZE);
}

void hmac_sha256_update(HMAC_SHA256_CTX *s, const uint8_t *buf, int len)
{
    SHA256_Update(&s->ctx, buf, len);
}

/* out has a length of SHA256_DIGEST_LENGTH */
void hmac_sha256_final(HMAC_SHA256_CTX *s, uint8_t *out)
{
    int i;
    
    SHA256_Final(s->K + HMAC_BLOCK_SIZE, &s->ctx);
    for(i = 0; i < HMAC_BLOCK_SIZE; i++)
        s->K[i] ^= (0x36 ^ 0x5c);
    SHA256(s->K, HMAC_BLOCK_SIZE + SHA256_DIGEST_LENGTH, out);
}

#define SALT_LEN_MAX 32

void pbkdf2_hmac_sha256(const uint8_t *pwd, int pwd_len,
                        const uint8_t *salt, int salt_len,
                        int iter, int key_len, uint8_t *out)
{
    uint8_t F[SHA256_DIGEST_LENGTH], U[SALT_LEN_MAX + 4];
    HMAC_SHA256_CTX ctx;
    int it, U_len, j, l;
    uint32_t i;
    
    assert(salt_len <= SALT_LEN_MAX);
    i = 1;
    while (key_len > 0) {
        memset(F, 0, SHA256_DIGEST_LENGTH);
        memcpy(U, salt, salt_len);
        U[salt_len] = i >> 24;
        U[salt_len + 1] = i >> 16;
        U[salt_len + 2] = i >> 8;
        U[salt_len + 3] = i;
        U_len = salt_len + 4;
        for(it = 0; it < iter; it++) {
            hmac_sha256_init(&ctx, pwd, pwd_len);
            hmac_sha256_update(&ctx, U, U_len);
            hmac_sha256_final(&ctx, U);
            for(j = 0; j < SHA256_DIGEST_LENGTH; j++)
                F[j] ^= U[j];
            U_len = SHA256_DIGEST_LENGTH;
        }
        l = min_int(key_len, SHA256_DIGEST_LENGTH);
        memcpy(out, F, l);
        out += l;
        key_len -= l;
        i++;
    }
}

#else

void pbkdf2_hmac_sha256(const uint8_t *pwd, int pwd_len,
                        const uint8_t *salt, int salt_len,
                        int iter, int key_len, uint8_t *out)
{
    PKCS5_PBKDF2_HMAC((const char *)pwd, pwd_len, salt, salt_len,
                      iter, EVP_sha256(), key_len, out);
}

#endif /* !USE_BUILTIN_CRYPTO */
