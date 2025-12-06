/*
 * BLAKE2s Implementation
 * Based on RFC 7693
 */

#include "blake2s.h"
#include <string.h>

static const uint32_t blake2s_IV[8] = {
    0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL,
    0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL
};

static const uint8_t blake2s_sigma[10][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3},
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4},
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8},
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13},
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9},
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11},
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10},
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0}
};

#define ROTR32(x, y) (((x) >> (y)) | ((x) << (32 - (y))))

#define G(r, i, a, b, c, d) do { \
    a = a + b + m[blake2s_sigma[r][2*i+0]]; \
    d = ROTR32(d ^ a, 16); \
    c = c + d; \
    b = ROTR32(b ^ c, 12); \
    a = a + b + m[blake2s_sigma[r][2*i+1]]; \
    d = ROTR32(d ^ a, 8); \
    c = c + d; \
    b = ROTR32(b ^ c, 7); \
} while(0)

#define ROUND(r) do { \
    G(r, 0, v[0], v[4], v[ 8], v[12]); \
    G(r, 1, v[1], v[5], v[ 9], v[13]); \
    G(r, 2, v[2], v[6], v[10], v[14]); \
    G(r, 3, v[3], v[7], v[11], v[15]); \
    G(r, 4, v[0], v[5], v[10], v[15]); \
    G(r, 5, v[1], v[6], v[11], v[12]); \
    G(r, 6, v[2], v[7], v[ 8], v[13]); \
    G(r, 7, v[3], v[4], v[ 9], v[14]); \
} while(0)

static void blake2s_compress(BLAKE2S_CTX *ctx, const uint8_t block[64]) {
    uint32_t m[16], v[16];
    int i;

    for (i = 0; i < 16; ++i) {
        m[i] = ((uint32_t)block[i * 4 + 0]) |
               ((uint32_t)block[i * 4 + 1] << 8) |
               ((uint32_t)block[i * 4 + 2] << 16) |
               ((uint32_t)block[i * 4 + 3] << 24);
    }

    for (i = 0; i < 8; ++i) v[i] = ctx->h[i];
    v[ 8] = blake2s_IV[0]; v[ 9] = blake2s_IV[1];
    v[10] = blake2s_IV[2]; v[11] = blake2s_IV[3];
    v[12] = blake2s_IV[4] ^ ctx->t[0];
    v[13] = blake2s_IV[5] ^ ctx->t[1];
    v[14] = blake2s_IV[6] ^ ctx->f[0];
    v[15] = blake2s_IV[7] ^ ctx->f[1];

    ROUND(0); ROUND(1); ROUND(2); ROUND(3); ROUND(4);
    ROUND(5); ROUND(6); ROUND(7); ROUND(8); ROUND(9);

    for (i = 0; i < 8; ++i) ctx->h[i] ^= v[i] ^ v[i + 8];
}

int blake2s_init(BLAKE2S_CTX *ctx, size_t outlen) {
    if (outlen == 0 || outlen > BLAKE2S_OUTBYTES) return -1;

    memset(ctx, 0, sizeof(*ctx));
    for (int i = 0; i < 8; ++i) ctx->h[i] = blake2s_IV[i];
    ctx->h[0] ^= 0x01010000 ^ outlen;
    ctx->outlen = outlen;

    return 0;
}

int blake2s_init_key(BLAKE2S_CTX *ctx, size_t outlen, const void *key, size_t keylen) {
    if (outlen == 0 || outlen > BLAKE2S_OUTBYTES) return -1;
    if (keylen == 0 || keylen > BLAKE2S_KEYBYTES) return -1;

    memset(ctx, 0, sizeof(*ctx));
    for (int i = 0; i < 8; ++i) ctx->h[i] = blake2s_IV[i];
    ctx->h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;
    ctx->outlen = outlen;

    uint8_t block[BLAKE2S_BLOCKBYTES] = {0};
    memcpy(block, key, keylen);
    blake2s_update(ctx, block, BLAKE2S_BLOCKBYTES);
    memset(block, 0, BLAKE2S_BLOCKBYTES);

    return 0;
}

int blake2s_update(BLAKE2S_CTX *ctx, const void *in, size_t inlen) {
    const uint8_t *pin = (const uint8_t *)in;

    if (inlen == 0) return 0;

    size_t left = ctx->buflen;
    size_t fill = BLAKE2S_BLOCKBYTES - left;

    if (inlen > fill) {
        ctx->buflen = 0;
        memcpy(ctx->buf + left, pin, fill);
        ctx->t[0] += BLAKE2S_BLOCKBYTES;
        if (ctx->t[0] < BLAKE2S_BLOCKBYTES) ctx->t[1]++;
        blake2s_compress(ctx, ctx->buf);
        pin += fill;
        inlen -= fill;

        while (inlen > BLAKE2S_BLOCKBYTES) {
            ctx->t[0] += BLAKE2S_BLOCKBYTES;
            if (ctx->t[0] < BLAKE2S_BLOCKBYTES) ctx->t[1]++;
            blake2s_compress(ctx, pin);
            pin += BLAKE2S_BLOCKBYTES;
            inlen -= BLAKE2S_BLOCKBYTES;
        }
    }

    memcpy(ctx->buf + ctx->buflen, pin, inlen);
    ctx->buflen += inlen;

    return 0;
}

int blake2s_final(BLAKE2S_CTX *ctx, void *out, size_t outlen) {
    if (out == NULL || outlen < ctx->outlen) return -1;

    ctx->t[0] += (uint32_t)ctx->buflen;
    if (ctx->t[0] < ctx->buflen) ctx->t[1]++;
    ctx->f[0] = (uint32_t)-1;

    memset(ctx->buf + ctx->buflen, 0, BLAKE2S_BLOCKBYTES - ctx->buflen);
    blake2s_compress(ctx, ctx->buf);

    uint8_t buffer[BLAKE2S_OUTBYTES];
    for (int i = 0; i < 8; ++i) {
        buffer[i * 4 + 0] = (uint8_t)(ctx->h[i]);
        buffer[i * 4 + 1] = (uint8_t)(ctx->h[i] >> 8);
        buffer[i * 4 + 2] = (uint8_t)(ctx->h[i] >> 16);
        buffer[i * 4 + 3] = (uint8_t)(ctx->h[i] >> 24);
    }
    memcpy(out, buffer, ctx->outlen);

    return 0;
}

void blake2s_128_hash(const uint8_t *data, size_t len, uint8_t digest[16]) {
    BLAKE2S_CTX ctx;
    blake2s_init(&ctx, 16);
    blake2s_update(&ctx, data, len);
    blake2s_final(&ctx, digest, 16);
}

void blake2s_160_hash(const uint8_t *data, size_t len, uint8_t digest[20]) {
    BLAKE2S_CTX ctx;
    blake2s_init(&ctx, 20);
    blake2s_update(&ctx, data, len);
    blake2s_final(&ctx, digest, 20);
}

void blake2s_256_hash(const uint8_t *data, size_t len, uint8_t digest[32]) {
    BLAKE2S_CTX ctx;
    blake2s_init(&ctx, 32);
    blake2s_update(&ctx, data, len);
    blake2s_final(&ctx, digest, 32);
}
