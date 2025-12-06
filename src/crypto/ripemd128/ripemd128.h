#ifndef RIPEMD128_H
#define RIPEMD128_H

#include <stdint.h>
#include <stddef.h>

#define RIPEMD128_DIGEST_LENGTH 16
#define RIPEMD128_BLOCK_SIZE 64

typedef struct {
    uint32_t state[4];
    uint64_t count;
    uint8_t buffer[RIPEMD128_BLOCK_SIZE];
} RIPEMD128_CTX;

void ripemd128_init(RIPEMD128_CTX *ctx);
void ripemd128_update(RIPEMD128_CTX *ctx, const uint8_t *data, size_t len);
void ripemd128_final(uint8_t digest[RIPEMD128_DIGEST_LENGTH], RIPEMD128_CTX *ctx);
void ripemd128_hash(const uint8_t *data, size_t len, uint8_t digest[RIPEMD128_DIGEST_LENGTH]);

#endif /* RIPEMD128_H */
