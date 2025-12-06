#ifndef SHA512_H
#define SHA512_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t state[8];
    uint64_t count[2];
    uint8_t buffer[128];
} SHA512_CTX;

#define SHA512_DIGEST_LENGTH 64
#define SHA384_DIGEST_LENGTH 48

void sha512_init(SHA512_CTX *ctx);
void sha512_update(SHA512_CTX *ctx, const uint8_t *data, size_t len);
void sha512_final(uint8_t digest[SHA512_DIGEST_LENGTH], SHA512_CTX *ctx);
void sha512_hash(const uint8_t *data, size_t len, uint8_t digest[SHA512_DIGEST_LENGTH]);

void sha384_init(SHA512_CTX *ctx);
void sha384_final(uint8_t digest[SHA384_DIGEST_LENGTH], SHA512_CTX *ctx);
void sha384_hash(const uint8_t *data, size_t len, uint8_t digest[SHA384_DIGEST_LENGTH]);

#endif /* SHA512_H */
