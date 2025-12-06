/*
 * Standalone RIPEMD-160 implementation
 * Used in Bitcoin for address generation
 * No OpenSSL dependencies
 */

#include "ripemd160.h"
#include <string.h>

#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define F(x, y, z) ((x) ^ (y) ^ (z))
#define G(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define H(x, y, z) (((x) | ~(y)) ^ (z))
#define I(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define J(x, y, z) ((x) ^ ((y) | ~(z)))

#define FF(a, b, c, d, e, x, s) { \
    (a) += F((b), (c), (d)) + (x); \
    (a) = ROL((a), (s)) + (e); \
    (c) = ROL((c), 10); \
}

#define GG(a, b, c, d, e, x, s) { \
    (a) += G((b), (c), (d)) + (x) + 0x5a827999; \
    (a) = ROL((a), (s)) + (e); \
    (c) = ROL((c), 10); \
}

#define HH(a, b, c, d, e, x, s) { \
    (a) += H((b), (c), (d)) + (x) + 0x6ed9eba1; \
    (a) = ROL((a), (s)) + (e); \
    (c) = ROL((c), 10); \
}

#define II(a, b, c, d, e, x, s) { \
    (a) += I((b), (c), (d)) + (x) + 0x8f1bbcdc; \
    (a) = ROL((a), (s)) + (e); \
    (c) = ROL((c), 10); \
}

#define JJ(a, b, c, d, e, x, s) { \
    (a) += J((b), (c), (d)) + (x) + 0xa953fd4e; \
    (a) = ROL((a), (s)) + (e); \
    (c) = ROL((c), 10); \
}

#define FFF(a, b, c, d, e, x, s) { \
    (a) += F((b), (c), (d)) + (x); \
    (a) = ROL((a), (s)) + (e); \
    (c) = ROL((c), 10); \
}

#define GGG(a, b, c, d, e, x, s) { \
    (a) += G((b), (c), (d)) + (x) + 0x7a6d76e9; \
    (a) = ROL((a), (s)) + (e); \
    (c) = ROL((c), 10); \
}

#define HHH(a, b, c, d, e, x, s) { \
    (a) += H((b), (c), (d)) + (x) + 0x6d703ef3; \
    (a) = ROL((a), (s)) + (e); \
    (c) = ROL((c), 10); \
}

#define III(a, b, c, d, e, x, s) { \
    (a) += I((b), (c), (d)) + (x) + 0x5c4dd124; \
    (a) = ROL((a), (s)) + (e); \
    (c) = ROL((c), 10); \
}

#define JJJ(a, b, c, d, e, x, s) { \
    (a) += J((b), (c), (d)) + (x) + 0x50a28be6; \
    (a) = ROL((a), (s)) + (e); \
    (c) = ROL((c), 10); \
}

static void ripemd160_transform(RIPEMD160_CTX *ctx, const uint8_t data[64]) {
    uint32_t al, bl, cl, dl, el, ar, br, cr, dr, er, t, x[16];
    int i;
    
    for (i = 0; i < 16; i++) {
        x[i] = ((uint32_t)data[i*4]) | ((uint32_t)data[i*4+1] << 8) |
               ((uint32_t)data[i*4+2] << 16) | ((uint32_t)data[i*4+3] << 24);
    }
    
    al = ar = ctx->state[0];
    bl = br = ctx->state[1];
    cl = cr = ctx->state[2];
    dl = dr = ctx->state[3];
    el = er = ctx->state[4];
    
    /* Left line */
    FF(al, bl, cl, dl, el, x[ 0], 11); FF(el, al, bl, cl, dl, x[ 1], 14);
    FF(dl, el, al, bl, cl, x[ 2], 15); FF(cl, dl, el, al, bl, x[ 3], 12);
    FF(bl, cl, dl, el, al, x[ 4],  5); FF(al, bl, cl, dl, el, x[ 5],  8);
    FF(el, al, bl, cl, dl, x[ 6],  7); FF(dl, el, al, bl, cl, x[ 7],  9);
    FF(cl, dl, el, al, bl, x[ 8], 11); FF(bl, cl, dl, el, al, x[ 9], 13);
    FF(al, bl, cl, dl, el, x[10], 14); FF(el, al, bl, cl, dl, x[11], 15);
    FF(dl, el, al, bl, cl, x[12],  6); FF(cl, dl, el, al, bl, x[13],  7);
    FF(bl, cl, dl, el, al, x[14],  9); FF(al, bl, cl, dl, el, x[15],  8);
    
    GG(el, al, bl, cl, dl, x[ 7],  7); GG(dl, el, al, bl, cl, x[ 4],  6);
    GG(cl, dl, el, al, bl, x[13],  8); GG(bl, cl, dl, el, al, x[ 1], 13);
    GG(al, bl, cl, dl, el, x[10], 11); GG(el, al, bl, cl, dl, x[ 6],  9);
    GG(dl, el, al, bl, cl, x[15],  7); GG(cl, dl, el, al, bl, x[ 3], 15);
    GG(bl, cl, dl, el, al, x[12],  7); GG(al, bl, cl, dl, el, x[ 0], 12);
    GG(el, al, bl, cl, dl, x[ 9], 15); GG(dl, el, al, bl, cl, x[ 5],  9);
    GG(cl, dl, el, al, bl, x[ 2], 11); GG(bl, cl, dl, el, al, x[14],  7);
    GG(al, bl, cl, dl, el, x[11], 13); GG(el, al, bl, cl, dl, x[ 8], 12);
    
    HH(dl, el, al, bl, cl, x[ 3], 11); HH(cl, dl, el, al, bl, x[10], 13);
    HH(bl, cl, dl, el, al, x[14],  6); HH(al, bl, cl, dl, el, x[ 4],  7);
    HH(el, al, bl, cl, dl, x[ 9], 14); HH(dl, el, al, bl, cl, x[15],  9);
    HH(cl, dl, el, al, bl, x[ 8], 13); HH(bl, cl, dl, el, al, x[ 1], 15);
    HH(al, bl, cl, dl, el, x[ 2], 14); HH(el, al, bl, cl, dl, x[ 7],  8);
    HH(dl, el, al, bl, cl, x[ 0], 13); HH(cl, dl, el, al, bl, x[ 6],  6);
    HH(bl, cl, dl, el, al, x[13],  5); HH(al, bl, cl, dl, el, x[11], 12);
    HH(el, al, bl, cl, dl, x[ 5],  7); HH(dl, el, al, bl, cl, x[12],  5);
    
    II(cl, dl, el, al, bl, x[ 1], 11); II(bl, cl, dl, el, al, x[ 9], 12);
    II(al, bl, cl, dl, el, x[11], 14); II(el, al, bl, cl, dl, x[10], 15);
    II(dl, el, al, bl, cl, x[ 0], 14); II(cl, dl, el, al, bl, x[ 8], 15);
    II(bl, cl, dl, el, al, x[12],  9); II(al, bl, cl, dl, el, x[ 4],  8);
    II(el, al, bl, cl, dl, x[13],  9); II(dl, el, al, bl, cl, x[ 3], 14);
    II(cl, dl, el, al, bl, x[ 7],  5); II(bl, cl, dl, el, al, x[15],  6);
    II(al, bl, cl, dl, el, x[14],  8); II(el, al, bl, cl, dl, x[ 5],  6);
    II(dl, el, al, bl, cl, x[ 6],  5); II(cl, dl, el, al, bl, x[ 2], 12);
    
    JJ(bl, cl, dl, el, al, x[ 4],  9); JJ(al, bl, cl, dl, el, x[ 0], 15);
    JJ(el, al, bl, cl, dl, x[ 5],  5); JJ(dl, el, al, bl, cl, x[ 9], 11);
    JJ(cl, dl, el, al, bl, x[ 7],  6); JJ(bl, cl, dl, el, al, x[12],  8);
    JJ(al, bl, cl, dl, el, x[ 2], 13); JJ(el, al, bl, cl, dl, x[10], 12);
    JJ(dl, el, al, bl, cl, x[14],  5); JJ(cl, dl, el, al, bl, x[ 1], 12);
    JJ(bl, cl, dl, el, al, x[ 3], 13); JJ(al, bl, cl, dl, el, x[ 8], 14);
    JJ(el, al, bl, cl, dl, x[11], 11); JJ(dl, el, al, bl, cl, x[ 6],  8);
    JJ(cl, dl, el, al, bl, x[15],  5); JJ(bl, cl, dl, el, al, x[13],  6);
    
    /* Right line */
    JJJ(ar, br, cr, dr, er, x[ 5],  8); JJJ(er, ar, br, cr, dr, x[14],  9);
    JJJ(dr, er, ar, br, cr, x[ 7],  9); JJJ(cr, dr, er, ar, br, x[ 0], 11);
    JJJ(br, cr, dr, er, ar, x[ 9], 13); JJJ(ar, br, cr, dr, er, x[ 2], 15);
    JJJ(er, ar, br, cr, dr, x[11], 15); JJJ(dr, er, ar, br, cr, x[ 4],  5);
    JJJ(cr, dr, er, ar, br, x[13],  7); JJJ(br, cr, dr, er, ar, x[ 6],  7);
    JJJ(ar, br, cr, dr, er, x[15],  8); JJJ(er, ar, br, cr, dr, x[ 8], 11);
    JJJ(dr, er, ar, br, cr, x[ 1], 14); JJJ(cr, dr, er, ar, br, x[10], 14);
    JJJ(br, cr, dr, er, ar, x[ 3], 12); JJJ(ar, br, cr, dr, er, x[12],  6);
    
    III(er, ar, br, cr, dr, x[ 6],  9); III(dr, er, ar, br, cr, x[11], 13);
    III(cr, dr, er, ar, br, x[ 3], 15); III(br, cr, dr, er, ar, x[ 7],  7);
    III(ar, br, cr, dr, er, x[ 0], 12); III(er, ar, br, cr, dr, x[13],  8);
    III(dr, er, ar, br, cr, x[ 5],  9); III(cr, dr, er, ar, br, x[10], 11);
    III(br, cr, dr, er, ar, x[14],  7); III(ar, br, cr, dr, er, x[15],  7);
    III(er, ar, br, cr, dr, x[ 8], 12); III(dr, er, ar, br, cr, x[12],  7);
    III(cr, dr, er, ar, br, x[ 4],  6); III(br, cr, dr, er, ar, x[ 9], 15);
    III(ar, br, cr, dr, er, x[ 1], 13); III(er, ar, br, cr, dr, x[ 2], 11);
    
    HHH(dr, er, ar, br, cr, x[15],  9); HHH(cr, dr, er, ar, br, x[ 5],  7);
    HHH(br, cr, dr, er, ar, x[ 1], 15); HHH(ar, br, cr, dr, er, x[ 3], 11);
    HHH(er, ar, br, cr, dr, x[ 7],  8); HHH(dr, er, ar, br, cr, x[14],  6);
    HHH(cr, dr, er, ar, br, x[ 6],  6); HHH(br, cr, dr, er, ar, x[ 9], 14);
    HHH(ar, br, cr, dr, er, x[11], 12); HHH(er, ar, br, cr, dr, x[ 8], 13);
    HHH(dr, er, ar, br, cr, x[12],  5); HHH(cr, dr, er, ar, br, x[ 2], 14);
    HHH(br, cr, dr, er, ar, x[10], 13); HHH(ar, br, cr, dr, er, x[ 0], 13);
    HHH(er, ar, br, cr, dr, x[ 4],  7); HHH(dr, er, ar, br, cr, x[13],  5);
    
    GGG(cr, dr, er, ar, br, x[ 8], 15); GGG(br, cr, dr, er, ar, x[ 6],  5);
    GGG(ar, br, cr, dr, er, x[ 4],  8); GGG(er, ar, br, cr, dr, x[ 1], 11);
    GGG(dr, er, ar, br, cr, x[ 3], 14); GGG(cr, dr, er, ar, br, x[11], 14);
    GGG(br, cr, dr, er, ar, x[15],  6); GGG(ar, br, cr, dr, er, x[ 0], 14);
    GGG(er, ar, br, cr, dr, x[ 5],  6); GGG(dr, er, ar, br, cr, x[12],  9);
    GGG(cr, dr, er, ar, br, x[ 2], 12); GGG(br, cr, dr, er, ar, x[13],  9);
    GGG(ar, br, cr, dr, er, x[ 9], 12); GGG(er, ar, br, cr, dr, x[ 7],  5);
    GGG(dr, er, ar, br, cr, x[10], 15); GGG(cr, dr, er, ar, br, x[14],  8);
    
    FFF(br, cr, dr, er, ar, x[12],  8); FFF(ar, br, cr, dr, er, x[15],  5);
    FFF(er, ar, br, cr, dr, x[10], 12); FFF(dr, er, ar, br, cr, x[ 4],  9);
    FFF(cr, dr, er, ar, br, x[ 1], 12); FFF(br, cr, dr, er, ar, x[ 5],  5);
    FFF(ar, br, cr, dr, er, x[ 8], 14); FFF(er, ar, br, cr, dr, x[ 7],  6);
    FFF(dr, er, ar, br, cr, x[ 6],  8); FFF(cr, dr, er, ar, br, x[ 2], 13);
    FFF(br, cr, dr, er, ar, x[13],  6); FFF(ar, br, cr, dr, er, x[14],  5);
    FFF(er, ar, br, cr, dr, x[ 0], 15); FFF(dr, er, ar, br, cr, x[ 3], 13);
    FFF(cr, dr, er, ar, br, x[ 9], 11); FFF(br, cr, dr, er, ar, x[11], 11);
    
    t = ctx->state[1] + cl + dr;
    ctx->state[1] = ctx->state[2] + dl + er;
    ctx->state[2] = ctx->state[3] + el + ar;
    ctx->state[3] = ctx->state[4] + al + br;
    ctx->state[4] = ctx->state[0] + bl + cr;
    ctx->state[0] = t;
}

void ripemd160_init(RIPEMD160_CTX *ctx) {
    ctx->count[0] = ctx->count[1] = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xc3d2e1f0;
}

void ripemd160_update(RIPEMD160_CTX *ctx, const uint8_t *data, size_t len) {
    uint32_t i, index, partLen;
    
    index = (uint32_t)((ctx->count[0] >> 3) & 0x3F);
    
    if ((ctx->count[0] += ((uint32_t)len << 3)) < ((uint32_t)len << 3))
        ctx->count[1]++;
    ctx->count[1] += ((uint32_t)len >> 29);
    
    partLen = 64 - index;
    
    if (len >= partLen) {
        memcpy(&ctx->buffer[index], data, partLen);
        ripemd160_transform(ctx, ctx->buffer);
        
        for (i = partLen; i + 63 < len; i += 64)
            ripemd160_transform(ctx, &data[i]);
        
        index = 0;
    } else {
        i = 0;
    }
    
    memcpy(&ctx->buffer[index], &data[i], len - i);
}

void ripemd160_final(uint8_t digest[RIPEMD160_DIGEST_LENGTH], RIPEMD160_CTX *ctx) {
    uint8_t bits[8];
    uint32_t index, padLen;
    static uint8_t padding[64] = { 0x80 };
    
    for (int i = 0, j = 0; i < 2; i++, j += 4) {
        bits[j]     = (uint8_t)(ctx->count[i] & 0xff);
        bits[j + 1] = (uint8_t)((ctx->count[i] >> 8) & 0xff);
        bits[j + 2] = (uint8_t)((ctx->count[i] >> 16) & 0xff);
        bits[j + 3] = (uint8_t)((ctx->count[i] >> 24) & 0xff);
    }
    
    index = (uint32_t)((ctx->count[0] >> 3) & 0x3f);
    padLen = (index < 56) ? (56 - index) : (120 - index);
    ripemd160_update(ctx, padding, padLen);
    ripemd160_update(ctx, bits, 8);
    
    for (int i = 0, j = 0; i < 5; i++, j += 4) {
        digest[j]     = (uint8_t)(ctx->state[i] & 0xff);
        digest[j + 1] = (uint8_t)((ctx->state[i] >> 8) & 0xff);
        digest[j + 2] = (uint8_t)((ctx->state[i] >> 16) & 0xff);
        digest[j + 3] = (uint8_t)((ctx->state[i] >> 24) & 0xff);
    }
    
    memset(ctx, 0, sizeof(*ctx));
}

void ripemd160_hash(const uint8_t *data, size_t len, uint8_t digest[RIPEMD160_DIGEST_LENGTH]) {
    RIPEMD160_CTX ctx;
    ripemd160_init(&ctx);
    ripemd160_update(&ctx, data, len);
    ripemd160_final(digest, &ctx);
}
