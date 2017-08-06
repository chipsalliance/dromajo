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
#if defined(EMSCRIPTEN)
#define USE_BUILTIN_CRYPTO
#endif

#ifdef USE_BUILTIN_CRYPTO
#include "aes.h"
#include "sha256.h"
#else
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#endif
#ifdef _WIN32
#include <winsock2.h>
#endif

#define LOG() printf("%s:%d\n", __func__, __LINE__)

/* XHR */

/* err < 0: error (no data provided)
   err = 0: end of transfer (data can be provided too)
   err = 1: data chunk
*/
typedef void WGetWriteCallback(void *opaque, int err, void *data, size_t size);
typedef size_t WGetReadCallback(void *opaque, void *data, size_t size);
typedef struct XHRState XHRState;

XHRState *fs_wget(const char *url, const char *user, const char *password,
                  void *opaque, WGetWriteCallback *cb, BOOL single_write);
void fs_wget_free(XHRState *s);

void fs_wget_init(void);
void fs_wget_end(void);

#ifndef EMSCRIPTEN
typedef BOOL FSNetEventLoopCompletionFunc(void *opaque);
void fs_net_set_fdset(int *pfd_max, fd_set *rfds, fd_set *wfds, fd_set *efds,
                      int *ptimeout);
void fs_net_event_loop(FSNetEventLoopCompletionFunc *cb, void *opaque);
#endif

/* crypto */

extern const uint8_t encrypted_file_magic[4];

typedef int DecryptFileCB(void *opaque, const uint8_t *data, size_t len);
typedef struct DecryptFileState DecryptFileState;

DecryptFileState *decrypt_file_init(AES_KEY *aes_state,
                                    DecryptFileCB *write_cb,
                                    void *opaque);
int decrypt_file(DecryptFileState *s, const uint8_t *data,
                 size_t size);
int decrypt_file_flush(DecryptFileState *s);
void decrypt_file_end(DecryptFileState *s);

void pbkdf2_hmac_sha256(const uint8_t *pwd, int pwd_len,
                        const uint8_t *salt, int salt_len,
                        int iter, int key_len, uint8_t *out);

/* XHR file */

typedef void FSWGetFileCB(FSDevice *fs, FSFile *f, int64_t size, void *opaque);

void fs_wget_file2(FSDevice *fs, FSFile *f, const char *url,
                   const char *user, const char *password,
                   FSFile *posted_file, uint64_t post_data_len,
                   FSWGetFileCB *cb, void *opaque,
                   AES_KEY *aes_state);
