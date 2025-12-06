#ifndef HAS160_H
#define HAS160_H

#include <stdint.h>
#include <stddef.h>

#define HAS160_DIGEST_LENGTH 20
#define HAS160_BLOCK_SIZE 64

typedef struct {
    uint32_t state[5];
    uint64_t count;
    uint8_t buffer[HAS160_BLOCK_SIZE];
} HAS160_CTX;

void has160_init(HAS160_CTX *ctx);
void has160_update(HAS160_CTX *ctx, const uint8_t *data, size_t len);
void has160_final(uint8_t digest[HAS160_DIGEST_LENGTH], HAS160_CTX *ctx);
void has160_hash(const uint8_t *data, size_t len, uint8_t digest[HAS160_DIGEST_LENGTH]);

#endif /* HAS160_H */
