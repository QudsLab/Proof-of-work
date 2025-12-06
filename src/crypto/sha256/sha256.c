#include "sha256.h"
#include <string.h>
// Rotate right macro - most compilers optimize this to a single instruction
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
// SHA-256 functions - using ROR instead of ROTRIGHT for better optimization
#define CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)     (ROR(x,2) ^ ROR(x,13) ^ ROR(x,22))
#define EP1(x)     (ROR(x,6) ^ ROR(x,11) ^ ROR(x,25))
#define SIG0(x)    (ROR(x,7) ^ ROR(x,18) ^ ((x) >> 3))
#define SIG1(x)    (ROR(x,17) ^ ROR(x,19) ^ ((x) >> 10))
// Round macro for maximum inlining
#define SHA256_ROUND(a,b,c,d,e,f,g,h,i) do { \
    t1 = h + EP1(e) + CH(e,f,g) + k[i] + w[i]; \
    t2 = EP0(a) + MAJ(a,b,c); \
    d += t1; \
    h = t1 + t2; \
} while(0)
// K constants aligned for better cache performance
static const uint32_t k[64] __attribute__((aligned(64))) = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};
// Highly optimized transform - inline and unrolled
static inline void sha256_transform_optimized(uint32_t state[8], const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t w[64];
    uint32_t t1, t2;
    int i;
    // Load message schedule - unrolled for better performance
    w[0]  = ((uint32_t)data[0]  << 24) | ((uint32_t)data[1]  << 16) | ((uint32_t)data[2]  << 8) | data[3];
    w[1]  = ((uint32_t)data[4]  << 24) | ((uint32_t)data[5]  << 16) | ((uint32_t)data[6]  << 8) | data[7];
    w[2]  = ((uint32_t)data[8]  << 24) | ((uint32_t)data[9]  << 16) | ((uint32_t)data[10] << 8) | data[11];
    w[3]  = ((uint32_t)data[12] << 24) | ((uint32_t)data[13] << 16) | ((uint32_t)data[14] << 8) | data[15];
    w[4]  = ((uint32_t)data[16] << 24) | ((uint32_t)data[17] << 16) | ((uint32_t)data[18] << 8) | data[19];
    w[5]  = ((uint32_t)data[20] << 24) | ((uint32_t)data[21] << 16) | ((uint32_t)data[22] << 8) | data[23];
    w[6]  = ((uint32_t)data[24] << 24) | ((uint32_t)data[25] << 16) | ((uint32_t)data[26] << 8) | data[27];
    w[7]  = ((uint32_t)data[28] << 24) | ((uint32_t)data[29] << 16) | ((uint32_t)data[30] << 8) | data[31];
    w[8]  = ((uint32_t)data[32] << 24) | ((uint32_t)data[33] << 16) | ((uint32_t)data[34] << 8) | data[35];
    w[9]  = ((uint32_t)data[36] << 24) | ((uint32_t)data[37] << 16) | ((uint32_t)data[38] << 8) | data[39];
    w[10] = ((uint32_t)data[40] << 24) | ((uint32_t)data[41] << 16) | ((uint32_t)data[42] << 8) | data[43];
    w[11] = ((uint32_t)data[44] << 24) | ((uint32_t)data[45] << 16) | ((uint32_t)data[46] << 8) | data[47];
    w[12] = ((uint32_t)data[48] << 24) | ((uint32_t)data[49] << 16) | ((uint32_t)data[50] << 8) | data[51];
    w[13] = ((uint32_t)data[52] << 24) | ((uint32_t)data[53] << 16) | ((uint32_t)data[54] << 8) | data[55];
    w[14] = ((uint32_t)data[56] << 24) | ((uint32_t)data[57] << 16) | ((uint32_t)data[58] << 8) | data[59];
    w[15] = ((uint32_t)data[60] << 24) | ((uint32_t)data[61] << 16) | ((uint32_t)data[62] << 8) | data[63];
    // Extend message schedule
    for (i = 16; i < 64; i++) {
        w[i] = SIG1(w[i-2]) + w[i-7] + SIG0(w[i-15]) + w[i-16];
    }
    // Initialize working variables
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];
    // Main compression loop - fully unrolled for maximum speed
    SHA256_ROUND(a, b, c, d, e, f, g, h, 0);
    SHA256_ROUND(h, a, b, c, d, e, f, g, 1);
    SHA256_ROUND(g, h, a, b, c, d, e, f, 2);
    SHA256_ROUND(f, g, h, a, b, c, d, e, 3);
    SHA256_ROUND(e, f, g, h, a, b, c, d, 4);
    SHA256_ROUND(d, e, f, g, h, a, b, c, 5);
    SHA256_ROUND(c, d, e, f, g, h, a, b, 6);
    SHA256_ROUND(b, c, d, e, f, g, h, a, 7);
    SHA256_ROUND(a, b, c, d, e, f, g, h, 8);
    SHA256_ROUND(h, a, b, c, d, e, f, g, 9);
    SHA256_ROUND(g, h, a, b, c, d, e, f, 10);
    SHA256_ROUND(f, g, h, a, b, c, d, e, 11);
    SHA256_ROUND(e, f, g, h, a, b, c, d, 12);
    SHA256_ROUND(d, e, f, g, h, a, b, c, 13);
    SHA256_ROUND(c, d, e, f, g, h, a, b, 14);
    SHA256_ROUND(b, c, d, e, f, g, h, a, 15);
    SHA256_ROUND(a, b, c, d, e, f, g, h, 16);
    SHA256_ROUND(h, a, b, c, d, e, f, g, 17);
    SHA256_ROUND(g, h, a, b, c, d, e, f, 18);
    SHA256_ROUND(f, g, h, a, b, c, d, e, 19);
    SHA256_ROUND(e, f, g, h, a, b, c, d, 20);
    SHA256_ROUND(d, e, f, g, h, a, b, c, 21);
    SHA256_ROUND(c, d, e, f, g, h, a, b, 22);
    SHA256_ROUND(b, c, d, e, f, g, h, a, 23);
    SHA256_ROUND(a, b, c, d, e, f, g, h, 24);
    SHA256_ROUND(h, a, b, c, d, e, f, g, 25);
    SHA256_ROUND(g, h, a, b, c, d, e, f, 26);
    SHA256_ROUND(f, g, h, a, b, c, d, e, 27);
    SHA256_ROUND(e, f, g, h, a, b, c, d, 28);
    SHA256_ROUND(d, e, f, g, h, a, b, c, 29);
    SHA256_ROUND(c, d, e, f, g, h, a, b, 30);
    SHA256_ROUND(b, c, d, e, f, g, h, a, 31);
    SHA256_ROUND(a, b, c, d, e, f, g, h, 32);
    SHA256_ROUND(h, a, b, c, d, e, f, g, 33);
    SHA256_ROUND(g, h, a, b, c, d, e, f, 34);
    SHA256_ROUND(f, g, h, a, b, c, d, e, 35);
    SHA256_ROUND(e, f, g, h, a, b, c, d, 36);
    SHA256_ROUND(d, e, f, g, h, a, b, c, 37);
    SHA256_ROUND(c, d, e, f, g, h, a, b, 38);
    SHA256_ROUND(b, c, d, e, f, g, h, a, 39);
    SHA256_ROUND(a, b, c, d, e, f, g, h, 40);
    SHA256_ROUND(h, a, b, c, d, e, f, g, 41);
    SHA256_ROUND(g, h, a, b, c, d, e, f, 42);
    SHA256_ROUND(f, g, h, a, b, c, d, e, 43);
    SHA256_ROUND(e, f, g, h, a, b, c, d, 44);
    SHA256_ROUND(d, e, f, g, h, a, b, c, 45);
    SHA256_ROUND(c, d, e, f, g, h, a, b, 46);
    SHA256_ROUND(b, c, d, e, f, g, h, a, 47);
    SHA256_ROUND(a, b, c, d, e, f, g, h, 48);
    SHA256_ROUND(h, a, b, c, d, e, f, g, 49);
    SHA256_ROUND(g, h, a, b, c, d, e, f, 50);
    SHA256_ROUND(f, g, h, a, b, c, d, e, 51);
    SHA256_ROUND(e, f, g, h, a, b, c, d, 52);
    SHA256_ROUND(d, e, f, g, h, a, b, c, 53);
    SHA256_ROUND(c, d, e, f, g, h, a, b, 54);
    SHA256_ROUND(b, c, d, e, f, g, h, a, 55);
    SHA256_ROUND(a, b, c, d, e, f, g, h, 56);
    SHA256_ROUND(h, a, b, c, d, e, f, g, 57);
    SHA256_ROUND(g, h, a, b, c, d, e, f, 58);
    SHA256_ROUND(f, g, h, a, b, c, d, e, 59);
    SHA256_ROUND(e, f, g, h, a, b, c, d, 60);
    SHA256_ROUND(d, e, f, g, h, a, b, c, 61);
    SHA256_ROUND(c, d, e, f, g, h, a, b, 62);
    SHA256_ROUND(b, c, d, e, f, g, h, a, 63);
    // Add compressed chunk to current hash value
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}
void sha256_transform_fast(uint32_t state[8], const uint8_t data[64]) {
    sha256_transform_optimized(state, data);
}
void sha256_init_state(uint32_t state[8]) {
    state[0] = 0x6a09e667;
    state[1] = 0xbb67ae85;
    state[2] = 0x3c6ef372;
    state[3] = 0xa54ff53a;
    state[4] = 0x510e527f;
    state[5] = 0x9b05688c;
    state[6] = 0x1f83d9ab;
    state[7] = 0x5be0cd19;
}
void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    sha256_init_state(ctx->state);
}
void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
    for (size_t i = 0; i < len; i++) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform_optimized(ctx->state, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}
void sha256_final(SHA256_CTX *ctx, uint8_t hash[]) {
    uint32_t i = ctx->datalen;
    // Padding
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56)
            ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64)
            ctx->data[i++] = 0x00;
        sha256_transform_optimized(ctx->state, ctx->data);
        memset(ctx->data, 0, 56);
    }
    // Append length in bits
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform_optimized(ctx->state, ctx->data);
    // Output hash - unrolled for speed
    hash[0]  = (ctx->state[0] >> 24) & 0xff;
    hash[1]  = (ctx->state[0] >> 16) & 0xff;
    hash[2]  = (ctx->state[0] >> 8)  & 0xff;
    hash[3]  = ctx->state[0] & 0xff;
    hash[4]  = (ctx->state[1] >> 24) & 0xff;
    hash[5]  = (ctx->state[1] >> 16) & 0xff;
    hash[6]  = (ctx->state[1] >> 8)  & 0xff;
    hash[7]  = ctx->state[1] & 0xff;
    hash[8]  = (ctx->state[2] >> 24) & 0xff;
    hash[9]  = (ctx->state[2] >> 16) & 0xff;
    hash[10] = (ctx->state[2] >> 8)  & 0xff;
    hash[11] = ctx->state[2] & 0xff;
    hash[12] = (ctx->state[3] >> 24) & 0xff;
    hash[13] = (ctx->state[3] >> 16) & 0xff;
    hash[14] = (ctx->state[3] >> 8)  & 0xff;
    hash[15] = ctx->state[3] & 0xff;
    hash[16] = (ctx->state[4] >> 24) & 0xff;
    hash[17] = (ctx->state[4] >> 16) & 0xff;
    hash[18] = (ctx->state[4] >> 8)  & 0xff;
    hash[19] = ctx->state[4] & 0xff;
    hash[20] = (ctx->state[5] >> 24) & 0xff;
    hash[21] = (ctx->state[5] >> 16) & 0xff;
    hash[22] = (ctx->state[5] >> 8)  & 0xff;
    hash[23] = ctx->state[5] & 0xff;
    hash[24] = (ctx->state[6] >> 24) & 0xff;
    hash[25] = (ctx->state[6] >> 16) & 0xff;
    hash[26] = (ctx->state[6] >> 8)  & 0xff;
    hash[27] = ctx->state[6] & 0xff;
    hash[28] = (ctx->state[7] >> 24) & 0xff;
    hash[29] = (ctx->state[7] >> 16) & 0xff;
    hash[30] = (ctx->state[7] >> 8)  & 0xff;
    hash[31] = ctx->state[7] & 0xff;
}
void sha256(const uint8_t data[], size_t len, uint8_t hash[]) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, hash);
}
// Double SHA-256 optimized for POW
void sha256_double_hash(const uint8_t data[], size_t len, uint8_t hash[]) {
    uint8_t temp[32];
    sha256(data, len, temp);
    sha256(temp, 32, hash);
}
// Midstate for POW optimization
void sha256_midstate(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
    sha256_init(ctx);
    sha256_update(ctx, data, len);
}
// Continue from midstate
void sha256_final_from_midstate(SHA256_CTX *ctx, const uint8_t remaining[], size_t len, uint8_t hash[]) {
    SHA256_CTX temp = *ctx;
    sha256_update(&temp, remaining, len);
    sha256_final(&temp, hash);
}