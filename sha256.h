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
