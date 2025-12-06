#ifndef RIPEMD256_H
#define RIPEMD256_H

#include <stdint.h>
#include <stddef.h>

#define RIPEMD256_DIGEST_LENGTH 32
#define RIPEMD256_BLOCK_SIZE 64

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[RIPEMD256_BLOCK_SIZE];
} RIPEMD256_CTX;

void ripemd256_init(RIPEMD256_CTX *ctx);
void ripemd256_update(RIPEMD256_CTX *ctx, const uint8_t *data, size_t len);
void ripemd256_final(uint8_t digest[RIPEMD256_DIGEST_LENGTH], RIPEMD256_CTX *ctx);
void ripemd256_hash(const uint8_t *data, size_t len, uint8_t digest[RIPEMD256_DIGEST_LENGTH]);

#endif /* RIPEMD256_H */
