#ifndef SHA3_384_H
#define SHA3_384_H

#include <stdint.h>
#include <stddef.h>

#define SHA3_384_DIGEST_LENGTH 48

typedef struct {
    uint64_t state[25];
    size_t rate;
    uint8_t buffer[200];
    size_t buf_len;
} SHA3_384_CTX;

void sha3_384_init(SHA3_384_CTX *ctx);
void sha3_384_update(SHA3_384_CTX *ctx, const uint8_t *data, size_t len);
void sha3_384_final(uint8_t digest[SHA3_384_DIGEST_LENGTH], SHA3_384_CTX *ctx);
void sha3_384_hash(const uint8_t *data, size_t len, uint8_t digest[SHA3_384_DIGEST_LENGTH]);

#endif /* SHA3_384_H */
