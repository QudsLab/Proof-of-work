/*
 * RIPEMD-128 Implementation
 */

#include "ripemd128.h"
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

static void ripemd128_transform(RIPEMD128_CTX *ctx, const uint8_t block[64]) {
    uint32_t X[16];
    uint32_t aa, bb, cc, dd, aaa, bbb, ccc, ddd, t;

    for (int i = 0; i < 16; i++) {
        X[i] = ((uint32_t)block[i * 4]) | ((uint32_t)block[i * 4 + 1] << 8) |
               ((uint32_t)block[i * 4 + 2] << 16) | ((uint32_t)block[i * 4 + 3] << 24);
    }

    aa = aaa = ctx->state[0];
    bb = bbb = ctx->state[1];
    cc = ccc = ctx->state[2];
    dd = ddd = ctx->state[3];

    /* Round 1 - left */
    FF(aa, bb, cc, dd, X[ 0], 11); FF(dd, aa, bb, cc, X[ 1], 14);
    FF(cc, dd, aa, bb, X[ 2], 15); FF(bb, cc, dd, aa, X[ 3], 12);
    FF(aa, bb, cc, dd, X[ 4],  5); FF(dd, aa, bb, cc, X[ 5],  8);
    FF(cc, dd, aa, bb, X[ 6],  7); FF(bb, cc, dd, aa, X[ 7],  9);
    FF(aa, bb, cc, dd, X[ 8], 11); FF(dd, aa, bb, cc, X[ 9], 13);
    FF(cc, dd, aa, bb, X[10], 14); FF(bb, cc, dd, aa, X[11], 15);
    FF(aa, bb, cc, dd, X[12],  6); FF(dd, aa, bb, cc, X[13],  7);
    FF(cc, dd, aa, bb, X[14],  9); FF(bb, cc, dd, aa, X[15],  8);

    /* Round 2 - left */
    GG(aa, bb, cc, dd, X[ 7],  7); GG(dd, aa, bb, cc, X[ 4],  6);
    GG(cc, dd, aa, bb, X[13],  8); GG(bb, cc, dd, aa, X[ 1], 13);
    GG(aa, bb, cc, dd, X[10], 11); GG(dd, aa, bb, cc, X[ 6],  9);
    GG(cc, dd, aa, bb, X[15],  7); GG(bb, cc, dd, aa, X[ 3], 15);
    GG(aa, bb, cc, dd, X[12],  7); GG(dd, aa, bb, cc, X[ 0], 12);
    GG(cc, dd, aa, bb, X[ 9], 15); GG(bb, cc, dd, aa, X[ 5],  9);
    GG(aa, bb, cc, dd, X[ 2], 11); GG(dd, aa, bb, cc, X[14],  7);
    GG(cc, dd, aa, bb, X[11], 13); GG(bb, cc, dd, aa, X[ 8], 12);

    /* Round 3 - left */
    HH(aa, bb, cc, dd, X[ 3], 11); HH(dd, aa, bb, cc, X[10], 13);
    HH(cc, dd, aa, bb, X[14],  6); HH(bb, cc, dd, aa, X[ 4],  7);
    HH(aa, bb, cc, dd, X[ 9], 14); HH(dd, aa, bb, cc, X[15],  9);
    HH(cc, dd, aa, bb, X[ 8], 13); HH(bb, cc, dd, aa, X[ 1], 15);
    HH(aa, bb, cc, dd, X[ 2], 14); HH(dd, aa, bb, cc, X[ 7],  8);
    HH(cc, dd, aa, bb, X[ 0], 13); HH(bb, cc, dd, aa, X[ 6],  6);
    HH(aa, bb, cc, dd, X[13],  5); HH(dd, aa, bb, cc, X[11], 12);
    HH(cc, dd, aa, bb, X[ 5],  7); HH(bb, cc, dd, aa, X[12],  5);

    /* Round 4 - left */
    II(aa, bb, cc, dd, X[ 1], 11); II(dd, aa, bb, cc, X[ 9], 12);
    II(cc, dd, aa, bb, X[11], 14); II(bb, cc, dd, aa, X[10], 15);
    II(aa, bb, cc, dd, X[ 0], 14); II(dd, aa, bb, cc, X[ 8], 15);
    II(cc, dd, aa, bb, X[12],  9); II(bb, cc, dd, aa, X[ 4],  8);
    II(aa, bb, cc, dd, X[13],  9); II(dd, aa, bb, cc, X[ 3], 14);
    II(cc, dd, aa, bb, X[ 7],  5); II(bb, cc, dd, aa, X[15],  6);
    II(aa, bb, cc, dd, X[14],  8); II(dd, aa, bb, cc, X[ 5],  6);
    II(cc, dd, aa, bb, X[ 6],  5); II(bb, cc, dd, aa, X[ 2], 12);

    /* Round 1 - right */
    III(aaa, bbb, ccc, ddd, X[ 5],  8); III(ddd, aaa, bbb, ccc, X[14],  9);
    III(ccc, ddd, aaa, bbb, X[ 7],  9); III(bbb, ccc, ddd, aaa, X[ 0], 11);
    III(aaa, bbb, ccc, ddd, X[ 9], 13); III(ddd, aaa, bbb, ccc, X[ 2], 15);
    III(ccc, ddd, aaa, bbb, X[11], 15); III(bbb, ccc, ddd, aaa, X[ 4],  5);
    III(aaa, bbb, ccc, ddd, X[13],  7); III(ddd, aaa, bbb, ccc, X[ 6],  7);
    III(ccc, ddd, aaa, bbb, X[15],  8); III(bbb, ccc, ddd, aaa, X[ 8], 11);
    III(aaa, bbb, ccc, ddd, X[ 1], 14); III(ddd, aaa, bbb, ccc, X[10], 14);
    III(ccc, ddd, aaa, bbb, X[ 3], 12); III(bbb, ccc, ddd, aaa, X[12],  6);

    /* Round 2 - right */
    HHH(aaa, bbb, ccc, ddd, X[ 6],  9); HHH(ddd, aaa, bbb, ccc, X[11], 13);
    HHH(ccc, ddd, aaa, bbb, X[ 3], 15); HHH(bbb, ccc, ddd, aaa, X[ 7],  7);
    HHH(aaa, bbb, ccc, ddd, X[ 0], 12); HHH(ddd, aaa, bbb, ccc, X[13],  8);
    HHH(ccc, ddd, aaa, bbb, X[ 5],  9); HHH(bbb, ccc, ddd, aaa, X[10], 11);
    HHH(aaa, bbb, ccc, ddd, X[14],  7); HHH(ddd, aaa, bbb, ccc, X[15],  7);
    HHH(ccc, ddd, aaa, bbb, X[ 8], 12); HHH(bbb, ccc, ddd, aaa, X[12],  7);
    HHH(aaa, bbb, ccc, ddd, X[ 4],  6); HHH(ddd, aaa, bbb, ccc, X[ 9], 15);
    HHH(ccc, ddd, aaa, bbb, X[ 1], 13); HHH(bbb, ccc, ddd, aaa, X[ 2], 11);

    /* Round 3 - right */
    GGG(aaa, bbb, ccc, ddd, X[15],  9); GGG(ddd, aaa, bbb, ccc, X[ 5],  7);
    GGG(ccc, ddd, aaa, bbb, X[ 1], 15); GGG(bbb, ccc, ddd, aaa, X[ 3], 11);
    GGG(aaa, bbb, ccc, ddd, X[ 7],  8); GGG(ddd, aaa, bbb, ccc, X[14],  6);
    GGG(ccc, ddd, aaa, bbb, X[ 6],  6); GGG(bbb, ccc, ddd, aaa, X[ 9], 14);
    GGG(aaa, bbb, ccc, ddd, X[11], 12); GGG(ddd, aaa, bbb, ccc, X[ 8], 13);
    GGG(ccc, ddd, aaa, bbb, X[12],  5); GGG(bbb, ccc, ddd, aaa, X[ 2], 14);
    GGG(aaa, bbb, ccc, ddd, X[10], 13); GGG(ddd, aaa, bbb, ccc, X[ 0], 13);
    GGG(ccc, ddd, aaa, bbb, X[ 4],  7); GGG(bbb, ccc, ddd, aaa, X[13],  5);

    /* Round 4 - right */
    FFF(aaa, bbb, ccc, ddd, X[ 8], 15); FFF(ddd, aaa, bbb, ccc, X[ 6],  5);
    FFF(ccc, ddd, aaa, bbb, X[ 4],  8); FFF(bbb, ccc, ddd, aaa, X[ 1], 11);
    FFF(aaa, bbb, ccc, ddd, X[ 3], 14); FFF(ddd, aaa, bbb, ccc, X[11], 14);
    FFF(ccc, ddd, aaa, bbb, X[15],  6); FFF(bbb, ccc, ddd, aaa, X[ 0], 14);
    FFF(aaa, bbb, ccc, ddd, X[ 5],  6); FFF(ddd, aaa, bbb, ccc, X[12],  9);
    FFF(ccc, ddd, aaa, bbb, X[ 2], 12); FFF(bbb, ccc, ddd, aaa, X[13],  9);
    FFF(aaa, bbb, ccc, ddd, X[ 9], 12); FFF(ddd, aaa, bbb, ccc, X[ 7],  5);
    FFF(ccc, ddd, aaa, bbb, X[10], 15); FFF(bbb, ccc, ddd, aaa, X[14],  8);

    /* Combine */
    t = ctx->state[1] + cc + ddd;
    ctx->state[1] = ctx->state[2] + dd + aaa;
    ctx->state[2] = ctx->state[3] + aa + bbb;
    ctx->state[3] = ctx->state[0] + bb + ccc;
    ctx->state[0] = t;
}

void ripemd128_init(RIPEMD128_CTX *ctx) {
    ctx->state[0] = 0x67452301UL;
    ctx->state[1] = 0xefcdab89UL;
    ctx->state[2] = 0x98badcfeUL;
    ctx->state[3] = 0x10325476UL;
    ctx->count = 0;
}

void ripemd128_update(RIPEMD128_CTX *ctx, const uint8_t *data, size_t len) {
    size_t i = 0;
    size_t index = (size_t)(ctx->count & 0x3F);
    ctx->count += len;

    if (index) {
        size_t left = RIPEMD128_BLOCK_SIZE - index;
        if (len < left) {
            memcpy(ctx->buffer + index, data, len);
            return;
        }
        memcpy(ctx->buffer + index, data, left);
        ripemd128_transform(ctx, ctx->buffer);
        i = left;
    }

    for (; i + RIPEMD128_BLOCK_SIZE <= len; i += RIPEMD128_BLOCK_SIZE) {
        ripemd128_transform(ctx, data + i);
    }

    if (i < len) {
        memcpy(ctx->buffer, data + i, len - i);
    }
}

void ripemd128_final(uint8_t digest[RIPEMD128_DIGEST_LENGTH], RIPEMD128_CTX *ctx) {
    uint8_t pad[RIPEMD128_BLOCK_SIZE];
    uint64_t bits = ctx->count * 8;
    size_t index = (size_t)(ctx->count & 0x3F);
    size_t pad_len = (index < 56) ? (56 - index) : (120 - index);

    memset(pad, 0, pad_len);
    pad[0] = 0x80;
    ripemd128_update(ctx, pad, pad_len);

    /* Append length as little-endian */
    for (int i = 0; i < 8; i++) {
        pad[i] = (uint8_t)(bits >> (i * 8));
    }
    ripemd128_update(ctx, pad, 8);

    /* Output as little-endian */
    for (int i = 0; i < 4; i++) {
        digest[i * 4] = (uint8_t)(ctx->state[i]);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i] >> 24);
    }

    memset(ctx, 0, sizeof(*ctx));
}

void ripemd128_hash(const uint8_t *data, size_t len, uint8_t digest[RIPEMD128_DIGEST_LENGTH]) {
    RIPEMD128_CTX ctx;
    ripemd128_init(&ctx);
    ripemd128_update(&ctx, data, len);
    ripemd128_final(digest, &ctx);
}
