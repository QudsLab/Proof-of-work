#ifndef RIPEMD320_H
#define RIPEMD320_H

#include <stdint.h>
#include <stddef.h>

#define RIPEMD320_DIGEST_LENGTH 40
#define RIPEMD320_BLOCK_SIZE 64

typedef struct {
    uint32_t state[10];
    uint64_t count;
    uint8_t buffer[RIPEMD320_BLOCK_SIZE];
} RIPEMD320_CTX;

void ripemd320_init(RIPEMD320_CTX *ctx);
void ripemd320_update(RIPEMD320_CTX *ctx, const uint8_t *data, size_t len);
void ripemd320_final(uint8_t digest[RIPEMD320_DIGEST_LENGTH], RIPEMD320_CTX *ctx);
void ripemd320_hash(const uint8_t *data, size_t len, uint8_t digest[RIPEMD320_DIGEST_LENGTH]);

#endif /* RIPEMD320_H */
