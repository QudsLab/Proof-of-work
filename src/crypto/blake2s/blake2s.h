#ifndef BLAKE2S_H
#define BLAKE2S_H

#include <stdint.h>
#include <stddef.h>

#define BLAKE2S_BLOCKBYTES 64
#define BLAKE2S_OUTBYTES 32
#define BLAKE2S_KEYBYTES 32

typedef struct {
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t buf[BLAKE2S_BLOCKBYTES];
    size_t buflen;
    size_t outlen;
} BLAKE2S_CTX;

int blake2s_init(BLAKE2S_CTX *ctx, size_t outlen);
int blake2s_init_key(BLAKE2S_CTX *ctx, size_t outlen, const void *key, size_t keylen);
int blake2s_update(BLAKE2S_CTX *ctx, const void *in, size_t inlen);
int blake2s_final(BLAKE2S_CTX *ctx, void *out, size_t outlen);

/* Convenience functions for specific output sizes */
void blake2s_128_hash(const uint8_t *data, size_t len, uint8_t digest[16]);
void blake2s_160_hash(const uint8_t *data, size_t len, uint8_t digest[20]);
void blake2s_256_hash(const uint8_t *data, size_t len, uint8_t digest[32]);

#endif /* BLAKE2S_H */
