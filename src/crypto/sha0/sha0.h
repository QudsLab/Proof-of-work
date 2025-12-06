#ifndef SHA0_H
#define SHA0_H

#include <stdint.h>
#include <stddef.h>

#define SHA0_DIGEST_LENGTH 20
#define SHA0_BLOCK_SIZE 64

typedef struct {
    uint32_t state[5];
    uint64_t count;
    uint8_t buffer[SHA0_BLOCK_SIZE];
} SHA0_CTX;

void sha0_init(SHA0_CTX *ctx);
void sha0_update(SHA0_CTX *ctx, const uint8_t *data, size_t len);
void sha0_final(uint8_t digest[SHA0_DIGEST_LENGTH], SHA0_CTX *ctx);
void sha0_hash(const uint8_t *data, size_t len, uint8_t digest[SHA0_DIGEST_LENGTH]);

#endif /* SHA0_H */
