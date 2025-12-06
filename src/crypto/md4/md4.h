#ifndef MD4_H
#define MD4_H

#include <stdint.h>
#include <stddef.h>

/* MD4 context structure */
typedef struct {
    uint32_t state[4];      /* State (ABCD) */
    uint32_t count[2];      /* Number of bits, modulo 2^64 (lsb first) */
    uint8_t buffer[64];     /* Input buffer */
} MD4_CTX;

/* MD4 constants */
#define MD4_DIGEST_LENGTH 16
#define MD4_BLOCK_SIZE 64

/* MD4 API functions */
void md4_init(MD4_CTX *ctx);
void md4_update(MD4_CTX *ctx, const uint8_t *data, size_t len);
void md4_final(uint8_t digest[MD4_DIGEST_LENGTH], MD4_CTX *ctx);
void md4_hash(const uint8_t *data, size_t len, uint8_t digest[MD4_DIGEST_LENGTH]);

#endif /* MD4_H */
