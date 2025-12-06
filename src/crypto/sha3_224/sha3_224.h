#ifndef SHA3_224_H
#define SHA3_224_H

#include <stdint.h>
#include <stddef.h>

#define SHA3_224_DIGEST_LENGTH 28

typedef struct {
    uint64_t state[25];
    size_t rate;
    uint8_t buffer[200];
    size_t buf_len;
} SHA3_224_CTX;

void sha3_224_init(SHA3_224_CTX *ctx);
void sha3_224_update(SHA3_224_CTX *ctx, const uint8_t *data, size_t len);
void sha3_224_final(uint8_t digest[SHA3_224_DIGEST_LENGTH], SHA3_224_CTX *ctx);
void sha3_224_hash(const uint8_t *data, size_t len, uint8_t digest[SHA3_224_DIGEST_LENGTH]);

#endif /* SHA3_224_H */
