#ifndef SHA224_H
#define SHA224_H

#include <stdint.h>
#include <stddef.h>

#define SHA224_DIGEST_LENGTH 28
#define SHA224_BLOCK_SIZE 64

typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA224_CTX;

void sha224_init(SHA224_CTX *ctx);
void sha224_update(SHA224_CTX *ctx, const uint8_t *data, size_t len);
void sha224_final(SHA224_CTX *ctx, uint8_t hash[SHA224_DIGEST_LENGTH]);
void sha224_hash(const uint8_t *data, size_t len, uint8_t hash[SHA224_DIGEST_LENGTH]);

#endif /* SHA224_H */
