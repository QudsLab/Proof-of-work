#ifndef BLAKE2B_H
#define BLAKE2B_H

#include <stdint.h>
#include <stddef.h>

#define BLAKE2B_BLOCKBYTES 128
#define BLAKE2B_OUTBYTES 64
#define BLAKE2B_KEYBYTES 64

typedef struct {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t buf[BLAKE2B_BLOCKBYTES];
    size_t buflen;
    size_t outlen;
} BLAKE2B_CTX;

int blake2b_init(BLAKE2B_CTX *ctx, size_t outlen);
int blake2b_init_key(BLAKE2B_CTX *ctx, size_t outlen, const void *key, size_t keylen);
int blake2b_update(BLAKE2B_CTX *ctx, const void *in, size_t inlen);
int blake2b_final(BLAKE2B_CTX *ctx, void *out, size_t outlen);

/* Convenience functions for specific output sizes */
void blake2b_128_hash(const uint8_t *data, size_t len, uint8_t digest[16]);
void blake2b_160_hash(const uint8_t *data, size_t len, uint8_t digest[20]);
void blake2b_256_hash(const uint8_t *data, size_t len, uint8_t digest[32]);
void blake2b_384_hash(const uint8_t *data, size_t len, uint8_t digest[48]);
void blake2b_512_hash(const uint8_t *data, size_t len, uint8_t digest[64]);

#endif /* BLAKE2B_H */
