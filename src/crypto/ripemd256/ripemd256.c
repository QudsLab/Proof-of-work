/*
 * RIPEMD-256 Implementation
 * Extended RIPEMD-128 with 256-bit output
 */

#include "ripemd256.h"
#include <string.h>

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define F(x, y, z) ((x) ^ (y) ^ (z))
#define G(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define H(x, y, z) (((x) | ~(y)) ^ (z))
#define I(x, y, z) (((x) & (z)) | ((y) & ~(z)))

#define FF(a, b, c, d, x, s) { (a) += F((b), (c), (d)) + (x); (a) = ROTL32((a), (s)); }
#define GG(a, b, c, d, x, s) { (a) += G((b), (c), (d)) + (x) + 0x5a827999UL; (a) = ROTL32((a), (s)); }
#define HH(a, b, c, d, x, s) { (a) += H((b), (c), (d)) + (x) + 0x6ed9eba1UL; (a) = ROTL32((a), (s)); }
#define II(a, b, c, d, x, s) { (a) += I((b), (c), (d)) + (x) + 0x8f1bbcdcUL; (a) = ROTL32((a), (s)); }

#define FFF(a, b, c, d, x, s) { (a) += F((b), (c), (d)) + (x); (a) = ROTL32((a), (s)); }
#define GGG(a, b, c, d, x, s) { (a) += G((b), (c), (d)) + (x) + 0x6d703ef3UL; (a) = ROTL32((a), (s)); }
#define HHH(a, b, c, d, x, s) { (a) += H((b), (c), (d)) + (x) + 0x5c4dd124UL; (a) = ROTL32((a), (s)); }
#define III(a, b, c, d, x, s) { (a) += I((b), (c), (d)) + (x) + 0x50a28be6UL; (a) = ROTL32((a), (s)); }

static void ripemd256_transform(RIPEMD256_CTX *ctx, const uint8_t block[64]) {
    uint32_t X[16];
    uint32_t a, b, c, d, aa, bb, cc, dd, t;

    for (int i = 0; i < 16; i++) {
        X[i] = ((uint32_t)block[i * 4]) | ((uint32_t)block[i * 4 + 1] << 8) |
               ((uint32_t)block[i * 4 + 2] << 16) | ((uint32_t)block[i * 4 + 3] << 24);
    }

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    aa = ctx->state[4]; bb = ctx->state[5]; cc = ctx->state[6]; dd = ctx->state[7];

    /* Round 1 - left */
    FF(a, b, c, d, X[ 0], 11); FF(d, a, b, c, X[ 1], 14);
    FF(c, d, a, b, X[ 2], 15); FF(b, c, d, a, X[ 3], 12);
    FF(a, b, c, d, X[ 4],  5); FF(d, a, b, c, X[ 5],  8);
    FF(c, d, a, b, X[ 6],  7); FF(b, c, d, a, X[ 7],  9);
    FF(a, b, c, d, X[ 8], 11); FF(d, a, b, c, X[ 9], 13);
    FF(c, d, a, b, X[10], 14); FF(b, c, d, a, X[11], 15);
    FF(a, b, c, d, X[12],  6); FF(d, a, b, c, X[13],  7);
    FF(c, d, a, b, X[14],  9); FF(b, c, d, a, X[15],  8);

    /* Round 1 - right */
    III(aa, bb, cc, dd, X[ 5],  8); III(dd, aa, bb, cc, X[14],  9);
    III(cc, dd, aa, bb, X[ 7],  9); III(bb, cc, dd, aa, X[ 0], 11);
    III(aa, bb, cc, dd, X[ 9], 13); III(dd, aa, bb, cc, X[ 2], 15);
    III(cc, dd, aa, bb, X[11], 15); III(bb, cc, dd, aa, X[ 4],  5);
    III(aa, bb, cc, dd, X[13],  7); III(dd, aa, bb, cc, X[ 6],  7);
    III(cc, dd, aa, bb, X[15],  8); III(bb, cc, dd, aa, X[ 8], 11);
    III(aa, bb, cc, dd, X[ 1], 14); III(dd, aa, bb, cc, X[10], 14);
    III(cc, dd, aa, bb, X[ 3], 12); III(bb, cc, dd, aa, X[12],  6);

    t = a; a = aa; aa = t;

    /* Round 2 - left */
    GG(a, b, c, d, X[ 7],  7); GG(d, a, b, c, X[ 4],  6);
    GG(c, d, a, b, X[13],  8); GG(b, c, d, a, X[ 1], 13);
    GG(a, b, c, d, X[10], 11); GG(d, a, b, c, X[ 6],  9);
    GG(c, d, a, b, X[15],  7); GG(b, c, d, a, X[ 3], 15);
    GG(a, b, c, d, X[12],  7); GG(d, a, b, c, X[ 0], 12);
    GG(c, d, a, b, X[ 9], 15); GG(b, c, d, a, X[ 5],  9);
    GG(a, b, c, d, X[ 2], 11); GG(d, a, b, c, X[14],  7);
    GG(c, d, a, b, X[11], 13); GG(b, c, d, a, X[ 8], 12);

    /* Round 2 - right */
    HHH(aa, bb, cc, dd, X[ 6],  9); HHH(dd, aa, bb, cc, X[11], 13);
    HHH(cc, dd, aa, bb, X[ 3], 15); HHH(bb, cc, dd, aa, X[ 7],  7);
    HHH(aa, bb, cc, dd, X[ 0], 12); HHH(dd, aa, bb, cc, X[13],  8);
    HHH(cc, dd, aa, bb, X[ 5],  9); HHH(bb, cc, dd, aa, X[10], 11);
    HHH(aa, bb, cc, dd, X[14],  7); HHH(dd, aa, bb, cc, X[15],  7);
    HHH(cc, dd, aa, bb, X[ 8], 12); HHH(bb, cc, dd, aa, X[12],  7);
    HHH(aa, bb, cc, dd, X[ 4],  6); HHH(dd, aa, bb, cc, X[ 9], 15);
    HHH(cc, dd, aa, bb, X[ 1], 13); HHH(bb, cc, dd, aa, X[ 2], 11);

    t = b; b = bb; bb = t;

    /* Round 3 - left */
    HH(a, b, c, d, X[ 3], 11); HH(d, a, b, c, X[10], 13);
    HH(c, d, a, b, X[14],  6); HH(b, c, d, a, X[ 4],  7);
    HH(a, b, c, d, X[ 9], 14); HH(d, a, b, c, X[15],  9);
    HH(c, d, a, b, X[ 8], 13); HH(b, c, d, a, X[ 1], 15);
    HH(a, b, c, d, X[ 2], 14); HH(d, a, b, c, X[ 7],  8);
    HH(c, d, a, b, X[ 0], 13); HH(b, c, d, a, X[ 6],  6);
    HH(a, b, c, d, X[13],  5); HH(d, a, b, c, X[11], 12);
    HH(c, d, a, b, X[ 5],  7); HH(b, c, d, a, X[12],  5);

    /* Round 3 - right */
    GGG(aa, bb, cc, dd, X[15],  9); GGG(dd, aa, bb, cc, X[ 5],  7);
    GGG(cc, dd, aa, bb, X[ 1], 15); GGG(bb, cc, dd, aa, X[ 3], 11);
    GGG(aa, bb, cc, dd, X[ 7],  8); GGG(dd, aa, bb, cc, X[14],  6);
    GGG(cc, dd, aa, bb, X[ 6],  6); GGG(bb, cc, dd, aa, X[ 9], 14);
    GGG(aa, bb, cc, dd, X[11], 12); GGG(dd, aa, bb, cc, X[ 8], 13);
    GGG(cc, dd, aa, bb, X[12],  5); GGG(bb, cc, dd, aa, X[ 2], 14);
    GGG(aa, bb, cc, dd, X[10], 13); GGG(dd, aa, bb, cc, X[ 0], 13);
    GGG(cc, dd, aa, bb, X[ 4],  7); GGG(bb, cc, dd, aa, X[13],  5);

    t = c; c = cc; cc = t;

    /* Round 4 - left */
    II(a, b, c, d, X[ 1], 11); II(d, a, b, c, X[ 9], 12);
    II(c, d, a, b, X[11], 14); II(b, c, d, a, X[10], 15);
    II(a, b, c, d, X[ 0], 14); II(d, a, b, c, X[ 8], 15);
    II(c, d, a, b, X[12],  9); II(b, c, d, a, X[ 4],  8);
    II(a, b, c, d, X[13],  9); II(d, a, b, c, X[ 3], 14);
    II(c, d, a, b, X[ 7],  5); II(b, c, d, a, X[15],  6);
    II(a, b, c, d, X[14],  8); II(d, a, b, c, X[ 5],  6);
    II(c, d, a, b, X[ 6],  5); II(b, c, d, a, X[ 2], 12);

    /* Round 4 - right */
    FFF(aa, bb, cc, dd, X[ 8], 15); FFF(dd, aa, bb, cc, X[ 6],  5);
    FFF(cc, dd, aa, bb, X[ 4],  8); FFF(bb, cc, dd, aa, X[ 1], 11);
    FFF(aa, bb, cc, dd, X[ 3], 14); FFF(dd, aa, bb, cc, X[11], 14);
    FFF(cc, dd, aa, bb, X[15],  6); FFF(bb, cc, dd, aa, X[ 0], 14);
    FFF(aa, bb, cc, dd, X[ 5],  6); FFF(dd, aa, bb, cc, X[12],  9);
    FFF(cc, dd, aa, bb, X[ 2], 12); FFF(bb, cc, dd, aa, X[13],  9);
    FFF(aa, bb, cc, dd, X[ 9], 12); FFF(dd, aa, bb, cc, X[ 7],  5);
    FFF(cc, dd, aa, bb, X[10], 15); FFF(bb, cc, dd, aa, X[14],  8);

    t = d; d = dd; dd = t;

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += aa; ctx->state[5] += bb; ctx->state[6] += cc; ctx->state[7] += dd;
}

void ripemd256_init(RIPEMD256_CTX *ctx) {
    ctx->state[0] = 0x67452301UL; ctx->state[1] = 0xefcdab89UL;
    ctx->state[2] = 0x98badcfeUL; ctx->state[3] = 0x10325476UL;
    ctx->state[4] = 0x76543210UL; ctx->state[5] = 0xfedcba98UL;
    ctx->state[6] = 0x89abcdefUL; ctx->state[7] = 0x01234567UL;
    ctx->count = 0;
}

void ripemd256_update(RIPEMD256_CTX *ctx, const uint8_t *data, size_t len) {
    size_t i = 0;
    size_t index = (size_t)(ctx->count & 0x3F);
    ctx->count += len;

    if (index) {
        size_t left = RIPEMD256_BLOCK_SIZE - index;
        if (len < left) {
            memcpy(ctx->buffer + index, data, len);
            return;
        }
        memcpy(ctx->buffer + index, data, left);
        ripemd256_transform(ctx, ctx->buffer);
        i = left;
    }

    for (; i + RIPEMD256_BLOCK_SIZE <= len; i += RIPEMD256_BLOCK_SIZE) {
        ripemd256_transform(ctx, data + i);
    }

    if (i < len) {
        memcpy(ctx->buffer, data + i, len - i);
    }
}

void ripemd256_final(uint8_t digest[RIPEMD256_DIGEST_LENGTH], RIPEMD256_CTX *ctx) {
    uint8_t pad[RIPEMD256_BLOCK_SIZE];
    uint64_t bits = ctx->count * 8;
    size_t index = (size_t)(ctx->count & 0x3F);
    size_t pad_len = (index < 56) ? (56 - index) : (120 - index);

    memset(pad, 0, pad_len);
    pad[0] = 0x80;
    ripemd256_update(ctx, pad, pad_len);

    for (int i = 0; i < 8; i++) {
        pad[i] = (uint8_t)(bits >> (i * 8));
    }
    ripemd256_update(ctx, pad, 8);

    for (int i = 0; i < 8; i++) {
        digest[i * 4] = (uint8_t)(ctx->state[i]);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i] >> 24);
    }

    memset(ctx, 0, sizeof(*ctx));
}

void ripemd256_hash(const uint8_t *data, size_t len, uint8_t digest[RIPEMD256_DIGEST_LENGTH]) {
    RIPEMD256_CTX ctx;
    ripemd256_init(&ctx);
    ripemd256_update(&ctx, data, len);
    ripemd256_final(digest, &ctx);
}
