/*
 * OpenSSL compatible SHA256 header
 * 
 * Copyright (c) 2017 Fabrice Bellard
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
#ifndef SHA256_H
#define SHA256_H

#define SHA256_DIGEST_LENGTH 32

typedef struct {
    uint64_t length;
    uint32_t state[8], curlen;
    uint8_t buf[64];
} SHA256_CTX;

void SHA256_Init(SHA256_CTX *s);
void SHA256_Update(SHA256_CTX *s, const uint8_t *in, unsigned long inlen);
void SHA256_Final(uint8_t *out, SHA256_CTX *s);
void SHA256(const uint8_t *buf, int buf_len, uint8_t *out);

#endif /* SHA256_H */
