#ifndef SHAKE_H
#define SHAKE_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t state[25];
    size_t rate;
    uint8_t buffer[200];
    size_t buf_len;
    int finalized;
} SHAKE_CTX;

void shake128_init(SHAKE_CTX *ctx);
void shake256_init(SHAKE_CTX *ctx);
void shake_update(SHAKE_CTX *ctx, const uint8_t *data, size_t len);
void shake_final(SHAKE_CTX *ctx);
void shake_squeeze(SHAKE_CTX *ctx, uint8_t *out, size_t outlen);

/* Convenience one-shot functions */
void shake128_hash(const uint8_t *data, size_t len, uint8_t *out, size_t outlen);
void shake256_hash(const uint8_t *data, size_t len, uint8_t *out, size_t outlen);

#endif /* SHAKE_H */
