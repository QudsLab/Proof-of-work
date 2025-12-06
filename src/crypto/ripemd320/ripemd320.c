/*
 * RIPEMD-320 Implementation
 * Extended RIPEMD-160 with 320-bit output
 */

#include "ripemd320.h"
#include <string.h>

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define F(x, y, z) ((x) ^ (y) ^ (z))
#define G(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define H(x, y, z) (((x) | ~(y)) ^ (z))
#define I(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define J(x, y, z) ((x) ^ ((y) | ~(z)))

#define FF(a, b, c, d, e, x, s) { (a) += F((b), (c), (d)) + (x); (a) = ROTL32((a), (s)) + (e); (c) = ROTL32((c), 10); }
#define GG(a, b, c, d, e, x, s) { (a) += G((b), (c), (d)) + (x) + 0x5a827999UL; (a) = ROTL32((a), (s)) + (e); (c) = ROTL32((c), 10); }
#define HH(a, b, c, d, e, x, s) { (a) += H((b), (c), (d)) + (x) + 0x6ed9eba1UL; (a) = ROTL32((a), (s)) + (e); (c) = ROTL32((c), 10); }
#define II(a, b, c, d, e, x, s) { (a) += I((b), (c), (d)) + (x) + 0x8f1bbcdcUL; (a) = ROTL32((a), (s)) + (e); (c) = ROTL32((c), 10); }
#define JJ(a, b, c, d, e, x, s) { (a) += J((b), (c), (d)) + (x) + 0xa953fd4eUL; (a) = ROTL32((a), (s)) + (e); (c) = ROTL32((c), 10); }

#define FFF(a, b, c, d, e, x, s) { (a) += F((b), (c), (d)) + (x); (a) = ROTL32((a), (s)) + (e); (c) = ROTL32((c), 10); }
#define GGG(a, b, c, d, e, x, s) { (a) += G((b), (c), (d)) + (x) + 0x7a6d76e9UL; (a) = ROTL32((a), (s)) + (e); (c) = ROTL32((c), 10); }
#define HHH(a, b, c, d, e, x, s) { (a) += H((b), (c), (d)) + (x) + 0x6d703ef3UL; (a) = ROTL32((a), (s)) + (e); (c) = ROTL32((c), 10); }
#define III(a, b, c, d, e, x, s) { (a) += I((b), (c), (d)) + (x) + 0x5c4dd124UL; (a) = ROTL32((a), (s)) + (e); (c) = ROTL32((c), 10); }
#define JJJ(a, b, c, d, e, x, s) { (a) += J((b), (c), (d)) + (x) + 0x50a28be6UL; (a) = ROTL32((a), (s)) + (e); (c) = ROTL32((c), 10); }

static void ripemd320_transform(RIPEMD320_CTX *ctx, const uint8_t block[64]) {
    uint32_t X[16];
    uint32_t a, b, c, d, e, aa, bb, cc, dd, ee, t;

    for (int i = 0; i < 16; i++) {
        X[i] = ((uint32_t)block[i * 4]) | ((uint32_t)block[i * 4 + 1] << 8) |
               ((uint32_t)block[i * 4 + 2] << 16) | ((uint32_t)block[i * 4 + 3] << 24);
    }

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3]; e = ctx->state[4];
    aa = ctx->state[5]; bb = ctx->state[6]; cc = ctx->state[7]; dd = ctx->state[8]; ee = ctx->state[9];

    /* Round 1 */
    FF(a, b, c, d, e, X[ 0], 11); FF(e, a, b, c, d, X[ 1], 14);
    FF(d, e, a, b, c, X[ 2], 15); FF(c, d, e, a, b, X[ 3], 12);
    FF(b, c, d, e, a, X[ 4],  5); FF(a, b, c, d, e, X[ 5],  8);
    FF(e, a, b, c, d, X[ 6],  7); FF(d, e, a, b, c, X[ 7],  9);
    FF(c, d, e, a, b, X[ 8], 11); FF(b, c, d, e, a, X[ 9], 13);
    FF(a, b, c, d, e, X[10], 14); FF(e, a, b, c, d, X[11], 15);
    FF(d, e, a, b, c, X[12],  6); FF(c, d, e, a, b, X[13],  7);
    FF(b, c, d, e, a, X[14],  9); FF(a, b, c, d, e, X[15],  8);

    JJJ(aa, bb, cc, dd, ee, X[ 5],  8); JJJ(ee, aa, bb, cc, dd, X[14],  9);
    JJJ(dd, ee, aa, bb, cc, X[ 7],  9); JJJ(cc, dd, ee, aa, bb, X[ 0], 11);
    JJJ(bb, cc, dd, ee, aa, X[ 9], 13); JJJ(aa, bb, cc, dd, ee, X[ 2], 15);
    JJJ(ee, aa, bb, cc, dd, X[11], 15); JJJ(dd, ee, aa, bb, cc, X[ 4],  5);
    JJJ(cc, dd, ee, aa, bb, X[13],  7); JJJ(bb, cc, dd, ee, aa, X[ 6],  7);
    JJJ(aa, bb, cc, dd, ee, X[15],  8); JJJ(ee, aa, bb, cc, dd, X[ 8], 11);
    JJJ(dd, ee, aa, bb, cc, X[ 1], 14); JJJ(cc, dd, ee, aa, bb, X[10], 14);
    JJJ(bb, cc, dd, ee, aa, X[ 3], 12); JJJ(aa, bb, cc, dd, ee, X[12],  6);

    t = a; a = aa; aa = t;

    /* Round 2 */
    GG(e, a, b, c, d, X[ 7],  7); GG(d, e, a, b, c, X[ 4],  6);
    GG(c, d, e, a, b, X[13],  8); GG(b, c, d, e, a, X[ 1], 13);
    GG(a, b, c, d, e, X[10], 11); GG(e, a, b, c, d, X[ 6],  9);
    GG(d, e, a, b, c, X[15],  7); GG(c, d, e, a, b, X[ 3], 15);
    GG(b, c, d, e, a, X[12],  7); GG(a, b, c, d, e, X[ 0], 12);
    GG(e, a, b, c, d, X[ 9], 15); GG(d, e, a, b, c, X[ 5],  9);
    GG(c, d, e, a, b, X[ 2], 11); GG(b, c, d, e, a, X[14],  7);
    GG(a, b, c, d, e, X[11], 13); GG(e, a, b, c, d, X[ 8], 12);

    III(ee, aa, bb, cc, dd, X[ 6],  9); III(dd, ee, aa, bb, cc, X[11], 13);
    III(cc, dd, ee, aa, bb, X[ 3], 15); III(bb, cc, dd, ee, aa, X[ 7],  7);
    III(aa, bb, cc, dd, ee, X[ 0], 12); III(ee, aa, bb, cc, dd, X[13],  8);
    III(dd, ee, aa, bb, cc, X[ 5],  9); III(cc, dd, ee, aa, bb, X[10], 11);
    III(bb, cc, dd, ee, aa, X[14],  7); III(aa, bb, cc, dd, ee, X[15],  7);
    III(ee, aa, bb, cc, dd, X[ 8], 12); III(dd, ee, aa, bb, cc, X[12],  7);
    III(cc, dd, ee, aa, bb, X[ 4],  6); III(bb, cc, dd, ee, aa, X[ 9], 15);
    III(aa, bb, cc, dd, ee, X[ 1], 13); III(ee, aa, bb, cc, dd, X[ 2], 11);

    t = b; b = bb; bb = t;

    /* Round 3 */
    HH(d, e, a, b, c, X[ 3], 11); HH(c, d, e, a, b, X[10], 13);
    HH(b, c, d, e, a, X[14],  6); HH(a, b, c, d, e, X[ 4],  7);
    HH(e, a, b, c, d, X[ 9], 14); HH(d, e, a, b, c, X[15],  9);
    HH(c, d, e, a, b, X[ 8], 13); HH(b, c, d, e, a, X[ 1], 15);
    HH(a, b, c, d, e, X[ 2], 14); HH(e, a, b, c, d, X[ 7],  8);
    HH(d, e, a, b, c, X[ 0], 13); HH(c, d, e, a, b, X[ 6],  6);
    HH(b, c, d, e, a, X[13],  5); HH(a, b, c, d, e, X[11], 12);
    HH(e, a, b, c, d, X[ 5],  7); HH(d, e, a, b, c, X[12],  5);

    HHH(dd, ee, aa, bb, cc, X[15],  9); HHH(cc, dd, ee, aa, bb, X[ 5],  7);
    HHH(bb, cc, dd, ee, aa, X[ 1], 15); HHH(aa, bb, cc, dd, ee, X[ 3], 11);
    HHH(ee, aa, bb, cc, dd, X[ 7],  8); HHH(dd, ee, aa, bb, cc, X[14],  6);
    HHH(cc, dd, ee, aa, bb, X[ 6],  6); HHH(bb, cc, dd, ee, aa, X[ 9], 14);
    HHH(aa, bb, cc, dd, ee, X[11], 12); HHH(ee, aa, bb, cc, dd, X[ 8], 13);
    HHH(dd, ee, aa, bb, cc, X[12],  5); HHH(cc, dd, ee, aa, bb, X[ 2], 14);
    HHH(bb, cc, dd, ee, aa, X[10], 13); HHH(aa, bb, cc, dd, ee, X[ 0], 13);
    HHH(ee, aa, bb, cc, dd, X[ 4],  7); HHH(dd, ee, aa, bb, cc, X[13],  5);

    t = c; c = cc; cc = t;

    /* Round 4 */
    II(c, d, e, a, b, X[ 1], 11); II(b, c, d, e, a, X[ 9], 12);
    II(a, b, c, d, e, X[11], 14); II(e, a, b, c, d, X[10], 15);
    II(d, e, a, b, c, X[ 0], 14); II(c, d, e, a, b, X[ 8], 15);
    II(b, c, d, e, a, X[12],  9); II(a, b, c, d, e, X[ 4],  8);
    II(e, a, b, c, d, X[13],  9); II(d, e, a, b, c, X[ 3], 14);
    II(c, d, e, a, b, X[ 7],  5); II(b, c, d, e, a, X[15],  6);
    II(a, b, c, d, e, X[14],  8); II(e, a, b, c, d, X[ 5],  6);
    II(d, e, a, b, c, X[ 6],  5); II(c, d, e, a, b, X[ 2], 12);

    GGG(cc, dd, ee, aa, bb, X[ 8], 15); GGG(bb, cc, dd, ee, aa, X[ 6],  5);
    GGG(aa, bb, cc, dd, ee, X[ 4],  8); GGG(ee, aa, bb, cc, dd, X[ 1], 11);
    GGG(dd, ee, aa, bb, cc, X[ 3], 14); GGG(cc, dd, ee, aa, bb, X[11], 14);
    GGG(bb, cc, dd, ee, aa, X[15],  6); GGG(aa, bb, cc, dd, ee, X[ 0], 14);
    GGG(ee, aa, bb, cc, dd, X[ 5],  6); GGG(dd, ee, aa, bb, cc, X[12],  9);
    GGG(cc, dd, ee, aa, bb, X[ 2], 12); GGG(bb, cc, dd, ee, aa, X[13],  9);
    GGG(aa, bb, cc, dd, ee, X[ 9], 12); GGG(ee, aa, bb, cc, dd, X[ 7],  5);
    GGG(dd, ee, aa, bb, cc, X[10], 15); GGG(cc, dd, ee, aa, bb, X[14],  8);

    t = d; d = dd; dd = t;

    /* Round 5 */
    JJ(b, c, d, e, a, X[ 4],  9); JJ(a, b, c, d, e, X[ 0], 15);
    JJ(e, a, b, c, d, X[ 5],  5); JJ(d, e, a, b, c, X[ 9], 11);
    JJ(c, d, e, a, b, X[ 7],  6); JJ(b, c, d, e, a, X[12],  8);
    JJ(a, b, c, d, e, X[ 2], 13); JJ(e, a, b, c, d, X[10], 12);
    JJ(d, e, a, b, c, X[14],  5); JJ(c, d, e, a, b, X[ 1], 12);
    JJ(b, c, d, e, a, X[ 3], 13); JJ(a, b, c, d, e, X[ 8], 14);
    JJ(e, a, b, c, d, X[11], 11); JJ(d, e, a, b, c, X[ 6],  8);
    JJ(c, d, e, a, b, X[15],  5); JJ(b, c, d, e, a, X[13],  6);

    FFF(bb, cc, dd, ee, aa, X[12],  8); FFF(aa, bb, cc, dd, ee, X[15],  5);
    FFF(ee, aa, bb, cc, dd, X[10], 12); FFF(dd, ee, aa, bb, cc, X[ 4],  9);
    FFF(cc, dd, ee, aa, bb, X[ 1], 12); FFF(bb, cc, dd, ee, aa, X[ 5],  5);
    FFF(aa, bb, cc, dd, ee, X[ 8], 14); FFF(ee, aa, bb, cc, dd, X[ 7],  6);
    FFF(dd, ee, aa, bb, cc, X[ 6],  8); FFF(cc, dd, ee, aa, bb, X[ 2], 13);
    FFF(bb, cc, dd, ee, aa, X[13],  6); FFF(aa, bb, cc, dd, ee, X[14],  5);
    FFF(ee, aa, bb, cc, dd, X[ 0], 15); FFF(dd, ee, aa, bb, cc, X[ 3], 13);
    FFF(cc, dd, ee, aa, bb, X[ 9], 11); FFF(bb, cc, dd, ee, aa, X[11], 11);

    t = e; e = ee; ee = t;

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d; ctx->state[4] += e;
    ctx->state[5] += aa; ctx->state[6] += bb; ctx->state[7] += cc; ctx->state[8] += dd; ctx->state[9] += ee;
}

void ripemd320_init(RIPEMD320_CTX *ctx) {
    ctx->state[0] = 0x67452301UL; ctx->state[1] = 0xefcdab89UL;
    ctx->state[2] = 0x98badcfeUL; ctx->state[3] = 0x10325476UL;
    ctx->state[4] = 0xc3d2e1f0UL;
    ctx->state[5] = 0x76543210UL; ctx->state[6] = 0xfedcba98UL;
    ctx->state[7] = 0x89abcdefUL; ctx->state[8] = 0x01234567UL;
    ctx->state[9] = 0x3c2d1e0fUL;
    ctx->count = 0;
}

void ripemd320_update(RIPEMD320_CTX *ctx, const uint8_t *data, size_t len) {
    size_t i = 0;
    size_t index = (size_t)(ctx->count & 0x3F);
    ctx->count += len;

    if (index) {
        size_t left = RIPEMD320_BLOCK_SIZE - index;
        if (len < left) {
            memcpy(ctx->buffer + index, data, len);
            return;
        }
        memcpy(ctx->buffer + index, data, left);
        ripemd320_transform(ctx, ctx->buffer);
        i = left;
    }

    for (; i + RIPEMD320_BLOCK_SIZE <= len; i += RIPEMD320_BLOCK_SIZE) {
        ripemd320_transform(ctx, data + i);
    }

    if (i < len) {
        memcpy(ctx->buffer, data + i, len - i);
    }
}

void ripemd320_final(uint8_t digest[RIPEMD320_DIGEST_LENGTH], RIPEMD320_CTX *ctx) {
    uint8_t pad[RIPEMD320_BLOCK_SIZE];
    uint64_t bits = ctx->count * 8;
    size_t index = (size_t)(ctx->count & 0x3F);
    size_t pad_len = (index < 56) ? (56 - index) : (120 - index);

    memset(pad, 0, pad_len);
    pad[0] = 0x80;
    ripemd320_update(ctx, pad, pad_len);

    for (int i = 0; i < 8; i++) {
        pad[i] = (uint8_t)(bits >> (i * 8));
    }
    ripemd320_update(ctx, pad, 8);

    for (int i = 0; i < 10; i++) {
        digest[i * 4] = (uint8_t)(ctx->state[i]);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i] >> 24);
    }

    memset(ctx, 0, sizeof(*ctx));
}

void ripemd320_hash(const uint8_t *data, size_t len, uint8_t digest[RIPEMD320_DIGEST_LENGTH]) {
    RIPEMD320_CTX ctx;
    ripemd320_init(&ctx);
    ripemd320_update(&ctx, data, len);
    ripemd320_final(digest, &ctx);
}
