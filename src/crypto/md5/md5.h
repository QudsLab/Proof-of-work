#ifndef MD5_H
#define MD5_H

#include <stdint.h>
#include <stddef.h>

/* MD5 context structure */
typedef struct {
    uint32_t state[4];      /* State (ABCD) */
    uint32_t count[2];      /* Number of bits, modulo 2^64 (lsb first) */
    uint8_t buffer[64];     /* Input buffer */
} MD5_CTX;

/* MD5 constants */
#define MD5_DIGEST_LENGTH 16
#define MD5_BLOCK_SIZE 64

/* MD5 API functions */
void md5_init(MD5_CTX *ctx);
void md5_update(MD5_CTX *ctx, const uint8_t *data, size_t len);
void md5_final(uint8_t digest[MD5_DIGEST_LENGTH], MD5_CTX *ctx);
void md5_hash(const uint8_t *data, size_t len, uint8_t digest[MD5_DIGEST_LENGTH]);

#endif /* MD5_H */
