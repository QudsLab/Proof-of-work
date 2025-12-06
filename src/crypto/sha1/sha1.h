#ifndef SHA1_H
#define SHA1_H

#include <stdint.h>
#include <stddef.h>

#define SHA1_DIGEST_LENGTH 20
#define SHA1_BLOCK_SIZE 64

typedef struct {
    uint32_t state[5];
    uint64_t count;
    uint8_t buffer[SHA1_BLOCK_SIZE];
} SHA1_CTX;

void sha1_init(SHA1_CTX *ctx);
void sha1_update(SHA1_CTX *ctx, const uint8_t *data, size_t len);
void sha1_final(uint8_t digest[SHA1_DIGEST_LENGTH], SHA1_CTX *ctx);
void sha1_hash(const uint8_t *data, size_t len, uint8_t digest[SHA1_DIGEST_LENGTH]);

#endif /* SHA1_H */
