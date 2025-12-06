#ifndef KECCAK_H
#define KECCAK_H

#include <stdint.h>
#include <stddef.h>

/* 
 * Keccak variants (excluding 256 which is in sha3.h)
 * Note: keccak_256 is available via sha3.h to avoid conflicts
 */

#define KECCAK_224_DIGEST_LENGTH 28
#define KECCAK_384_DIGEST_LENGTH 48
#define KECCAK_512_DIGEST_LENGTH 64

typedef struct {
    uint64_t state[25];
    size_t rate;
    size_t output_len;
    uint8_t buffer[200];
    size_t buf_len;
} KECCAK_CTX;

void keccak_224_init(KECCAK_CTX *ctx);
void keccak_384_init(KECCAK_CTX *ctx);
void keccak_512_init(KECCAK_CTX *ctx);

void keccak_update(KECCAK_CTX *ctx, const uint8_t *data, size_t len);
void keccak_final(uint8_t *digest, KECCAK_CTX *ctx);

void keccak_224_hash(const uint8_t *data, size_t len, uint8_t digest[KECCAK_224_DIGEST_LENGTH]);
void keccak_384_hash(const uint8_t *data, size_t len, uint8_t digest[KECCAK_384_DIGEST_LENGTH]);
void keccak_512_hash(const uint8_t *data, size_t len, uint8_t digest[KECCAK_512_DIGEST_LENGTH]);

#endif /* KECCAK_H */
