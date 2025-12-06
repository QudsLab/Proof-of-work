/*
 * Standalone MD4 implementation
 * Based on RFC 1186/1320 - The MD4 Message-Digest Algorithm
 * No OpenSSL dependencies
 */

#include "md4.h"
#include <string.h>

/* MD4 basic transformation macros */
#define F(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))

/* Rotate left macro */
#define ROTLEFT(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

/* MD4 round macros */
#define FF(a, b, c, d, x, s) { \
    (a) += F((b), (c), (d)) + (x); \
    (a) = ROTLEFT((a), (s)); \
}

#define GG(a, b, c, d, x, s) { \
    (a) += G((b), (c), (d)) + (x) + 0x5a827999; \
    (a) = ROTLEFT((a), (s)); \
}

#define HH(a, b, c, d, x, s) { \
    (a) += H((b), (c), (d)) + (x) + 0x6ed9eba1; \
    (a) = ROTLEFT((a), (s)); \
}

/* MD4 block transformation */
static void md4_transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t x[16];
    
    /* Decode input block into 32-bit words (little-endian) */
    for (int i = 0, j = 0; i < 16; i++, j += 4) {
        x[i] = ((uint32_t)block[j]) | (((uint32_t)block[j + 1]) << 8) |
               (((uint32_t)block[j + 2]) << 16) | (((uint32_t)block[j + 3]) << 24);
    }
    
    /* Round 1 */
    FF(a, b, c, d, x[ 0],  3);
    FF(d, a, b, c, x[ 1],  7);
    FF(c, d, a, b, x[ 2], 11);
    FF(b, c, d, a, x[ 3], 19);
    FF(a, b, c, d, x[ 4],  3);
    FF(d, a, b, c, x[ 5],  7);
    FF(c, d, a, b, x[ 6], 11);
    FF(b, c, d, a, x[ 7], 19);
    FF(a, b, c, d, x[ 8],  3);
    FF(d, a, b, c, x[ 9],  7);
    FF(c, d, a, b, x[10], 11);
    FF(b, c, d, a, x[11], 19);
    FF(a, b, c, d, x[12],  3);
    FF(d, a, b, c, x[13],  7);
    FF(c, d, a, b, x[14], 11);
    FF(b, c, d, a, x[15], 19);
    
    /* Round 2 */
    GG(a, b, c, d, x[ 0],  3);
    GG(d, a, b, c, x[ 4],  5);
    GG(c, d, a, b, x[ 8],  9);
    GG(b, c, d, a, x[12], 13);
    GG(a, b, c, d, x[ 1],  3);
    GG(d, a, b, c, x[ 5],  5);
    GG(c, d, a, b, x[ 9],  9);
    GG(b, c, d, a, x[13], 13);
    GG(a, b, c, d, x[ 2],  3);
    GG(d, a, b, c, x[ 6],  5);
    GG(c, d, a, b, x[10],  9);
    GG(b, c, d, a, x[14], 13);
    GG(a, b, c, d, x[ 3],  3);
    GG(d, a, b, c, x[ 7],  5);
    GG(c, d, a, b, x[11],  9);
    GG(b, c, d, a, x[15], 13);
    
    /* Round 3 */
    HH(a, b, c, d, x[ 0],  3);
    HH(d, a, b, c, x[ 8],  9);
    HH(c, d, a, b, x[ 4], 11);
    HH(b, c, d, a, x[12], 15);
    HH(a, b, c, d, x[ 2],  3);
    HH(d, a, b, c, x[10],  9);
    HH(c, d, a, b, x[ 6], 11);
    HH(b, c, d, a, x[14], 15);
    HH(a, b, c, d, x[ 1],  3);
    HH(d, a, b, c, x[ 9],  9);
    HH(c, d, a, b, x[ 5], 11);
    HH(b, c, d, a, x[13], 15);
    HH(a, b, c, d, x[ 3],  3);
    HH(d, a, b, c, x[11],  9);
    HH(c, d, a, b, x[ 7], 11);
    HH(b, c, d, a, x[15], 15);
    
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

/* Initialize MD4 context */
void md4_init(MD4_CTX *ctx) {
    ctx->count[0] = 0;
    ctx->count[1] = 0;
    
    /* Load magic initialization constants (RFC 1320) */
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
}

/* Update MD4 context with input data */
void md4_update(MD4_CTX *ctx, const uint8_t *data, size_t len) {
    uint32_t i, index, partLen;
    
    /* Compute number of bytes mod 64 */
    index = (uint32_t)((ctx->count[0] >> 3) & 0x3F);
    
    /* Update number of bits */
    if ((ctx->count[0] += ((uint32_t)len << 3)) < ((uint32_t)len << 3))
        ctx->count[1]++;
    ctx->count[1] += ((uint32_t)len >> 29);
    
    partLen = 64 - index;
    
    /* Transform as many times as possible */
    if (len >= partLen) {
        memcpy(&ctx->buffer[index], data, partLen);
        md4_transform(ctx->state, ctx->buffer);
        
        for (i = partLen; i + 63 < len; i += 64)
            md4_transform(ctx->state, &data[i]);
        
        index = 0;
    } else {
        i = 0;
    }
    
    /* Buffer remaining input */
    memcpy(&ctx->buffer[index], &data[i], len - i);
}

/* Finalize MD4 hash and produce digest */
void md4_final(uint8_t digest[MD4_DIGEST_LENGTH], MD4_CTX *ctx) {
    uint8_t bits[8];
    uint32_t index, padLen;
    static uint8_t padding[64] = { 0x80 };
    
    /* Save number of bits */
    for (int i = 0, j = 0; i < 2; i++, j += 4) {
        bits[j]     = (uint8_t)(ctx->count[i] & 0xff);
        bits[j + 1] = (uint8_t)((ctx->count[i] >> 8) & 0xff);
        bits[j + 2] = (uint8_t)((ctx->count[i] >> 16) & 0xff);
        bits[j + 3] = (uint8_t)((ctx->count[i] >> 24) & 0xff);
    }
    
    /* Pad out to 56 mod 64 */
    index = (uint32_t)((ctx->count[0] >> 3) & 0x3f);
    padLen = (index < 56) ? (56 - index) : (120 - index);
    md4_update(ctx, padding, padLen);
    
    /* Append length (before padding) */
    md4_update(ctx, bits, 8);
    
    /* Store state in digest (little-endian) */
    for (int i = 0, j = 0; i < 4; i++, j += 4) {
        digest[j]     = (uint8_t)(ctx->state[i] & 0xff);
        digest[j + 1] = (uint8_t)((ctx->state[i] >> 8) & 0xff);
        digest[j + 2] = (uint8_t)((ctx->state[i] >> 16) & 0xff);
        digest[j + 3] = (uint8_t)((ctx->state[i] >> 24) & 0xff);
    }
    
    /* Clear sensitive information */
    memset(ctx, 0, sizeof(*ctx));
}

/* Convenience function: compute MD4 hash in one call */
void md4_hash(const uint8_t *data, size_t len, uint8_t digest[MD4_DIGEST_LENGTH]) {
    MD4_CTX ctx;
    md4_init(&ctx);
    md4_update(&ctx, data, len);
    md4_final(digest, &ctx);
}
