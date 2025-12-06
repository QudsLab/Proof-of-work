#ifndef WHIRLPOOL_H
#define WHIRLPOOL_H

#include <stdint.h>
#include <stddef.h>

#define WHIRLPOOL_DIGEST_LENGTH 64
#define WHIRLPOOL_BLOCK_SIZE 64

typedef struct {
    uint64_t state[8];
    uint8_t buffer[WHIRLPOOL_BLOCK_SIZE];
    size_t buffer_len;
    uint64_t bit_count[4];
} WHIRLPOOL_CTX;

void whirlpool_init(WHIRLPOOL_CTX *ctx);
void whirlpool_update(WHIRLPOOL_CTX *ctx, const uint8_t *data, size_t len);
void whirlpool_final(uint8_t digest[WHIRLPOOL_DIGEST_LENGTH], WHIRLPOOL_CTX *ctx);
void whirlpool_hash(const uint8_t *data, size_t len, uint8_t digest[WHIRLPOOL_DIGEST_LENGTH]);

/* Variants */
void whirlpool0_hash(const uint8_t *data, size_t len, uint8_t digest[WHIRLPOOL_DIGEST_LENGTH]);
void whirlpoolt_hash(const uint8_t *data, size_t len, uint8_t digest[WHIRLPOOL_DIGEST_LENGTH]);

#endif /* WHIRLPOOL_H */
