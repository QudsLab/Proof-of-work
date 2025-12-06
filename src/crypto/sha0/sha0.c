/*
 * SHA-0 Implementation
 * SHA-0 is the original SHA algorithm (FIPS 180) before the fix that became SHA-1.
 * The only difference from SHA-1 is that SHA-0 does NOT rotate W[t] by 1 bit.
 */

#include "sha0.h"
#include <string.h>

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define PARITY(x, y, z) ((x) ^ (y) ^ (z))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

static const uint32_t K[4] = {
    0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6
};

static void sha0_transform(SHA0_CTX *ctx, const uint8_t block[64]) {
    uint32_t W[80];
    uint32_t a, b, c, d, e, temp;
    int t;

    for (t = 0; t < 16; t++) {
        W[t] = ((uint32_t)block[t * 4] << 24) |
               ((uint32_t)block[t * 4 + 1] << 16) |
               ((uint32_t)block[t * 4 + 2] << 8) |
               ((uint32_t)block[t * 4 + 3]);
    }
    /* SHA-0: No rotation (this is the key difference from SHA-1) */
    for (t = 16; t < 80; t++) {
        W[t] = W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];

    for (t = 0; t < 20; t++) {
        temp = ROTL32(a, 5) + CH(b, c, d) + e + K[0] + W[t];
        e = d; d = c; c = ROTL32(b, 30); b = a; a = temp;
    }
    for (t = 20; t < 40; t++) {
        temp = ROTL32(a, 5) + PARITY(b, c, d) + e + K[1] + W[t];
        e = d; d = c; c = ROTL32(b, 30); b = a; a = temp;
    }
    for (t = 40; t < 60; t++) {
        temp = ROTL32(a, 5) + MAJ(b, c, d) + e + K[2] + W[t];
        e = d; d = c; c = ROTL32(b, 30); b = a; a = temp;
    }
    for (t = 60; t < 80; t++) {
        temp = ROTL32(a, 5) + PARITY(b, c, d) + e + K[3] + W[t];
        e = d; d = c; c = ROTL32(b, 30); b = a; a = temp;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

void sha0_init(SHA0_CTX *ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->count = 0;
}

void sha0_update(SHA0_CTX *ctx, const uint8_t *data, size_t len) {
    size_t i = 0;
    size_t index = (size_t)(ctx->count & 0x3F);
    ctx->count += len;

    if (index) {
        size_t left = SHA0_BLOCK_SIZE - index;
        if (len < left) {
            memcpy(ctx->buffer + index, data, len);
            return;
        }
        memcpy(ctx->buffer + index, data, left);
        sha0_transform(ctx, ctx->buffer);
        i = left;
    }

    for (; i + SHA0_BLOCK_SIZE <= len; i += SHA0_BLOCK_SIZE) {
        sha0_transform(ctx, data + i);
    }

    if (i < len) {
        memcpy(ctx->buffer, data + i, len - i);
    }
}

void sha0_final(uint8_t digest[SHA0_DIGEST_LENGTH], SHA0_CTX *ctx) {
    uint8_t pad[SHA0_BLOCK_SIZE];
    uint64_t bits = ctx->count * 8;
    size_t index = (size_t)(ctx->count & 0x3F);
    size_t pad_len = (index < 56) ? (56 - index) : (120 - index);

    memset(pad, 0, pad_len);
    pad[0] = 0x80;
    sha0_update(ctx, pad, pad_len);

    pad[0] = (uint8_t)(bits >> 56);
    pad[1] = (uint8_t)(bits >> 48);
    pad[2] = (uint8_t)(bits >> 40);
    pad[3] = (uint8_t)(bits >> 32);
    pad[4] = (uint8_t)(bits >> 24);
    pad[5] = (uint8_t)(bits >> 16);
    pad[6] = (uint8_t)(bits >> 8);
    pad[7] = (uint8_t)(bits);
    sha0_update(ctx, pad, 8);

    for (int i = 0; i < 5; i++) {
        digest[i * 4] = (uint8_t)(ctx->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }

    memset(ctx, 0, sizeof(*ctx));
}

void sha0_hash(const uint8_t *data, size_t len, uint8_t digest[SHA0_DIGEST_LENGTH]) {
    SHA0_CTX ctx;
    sha0_init(&ctx);
    sha0_update(&ctx, data, len);
    sha0_final(digest, &ctx);
}
