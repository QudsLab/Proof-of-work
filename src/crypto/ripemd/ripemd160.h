#ifndef RIPEMD160_H
#define RIPEMD160_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
} RIPEMD160_CTX;

#define RIPEMD160_DIGEST_LENGTH 20
#define RIPEMD160_BLOCK_SIZE 64

void ripemd160_init(RIPEMD160_CTX *ctx);
void ripemd160_update(RIPEMD160_CTX *ctx, const uint8_t *data, size_t len);
void ripemd160_final(uint8_t digest[RIPEMD160_DIGEST_LENGTH], RIPEMD160_CTX *ctx);
void ripemd160_hash(const uint8_t *data, size_t len, uint8_t digest[RIPEMD160_DIGEST_LENGTH]);

#endif /* RIPEMD160_H */
