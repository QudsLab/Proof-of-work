#ifndef SHA3_H
#define SHA3_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t state[25];
    size_t rate;
    size_t capacity;
    size_t output_len;
    uint8_t buffer[200];
    size_t buf_len;
} SHA3_CTX;

#define SHA3_256_DIGEST_LENGTH 32
#define SHA3_512_DIGEST_LENGTH 64
#define KECCAK_256_DIGEST_LENGTH 32

void sha3_256_init(SHA3_CTX *ctx);
void sha3_512_init(SHA3_CTX *ctx);
void keccak_256_init(SHA3_CTX *ctx);

void sha3_update(SHA3_CTX *ctx, const uint8_t *data, size_t len);
void sha3_final(uint8_t *digest, SHA3_CTX *ctx);

void sha3_256_hash(const uint8_t *data, size_t len, uint8_t digest[SHA3_256_DIGEST_LENGTH]);
void sha3_512_hash(const uint8_t *data, size_t len, uint8_t digest[SHA3_512_DIGEST_LENGTH]);
void keccak_256_hash(const uint8_t *data, size_t len, uint8_t digest[KECCAK_256_DIGEST_LENGTH]);

#endif /* SHA3_H */

