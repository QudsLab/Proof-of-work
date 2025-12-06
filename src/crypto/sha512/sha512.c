/*
 * Standalone SHA-512/SHA-384 implementation
 * Based on FIPS 180-4 Secure Hash Standard
 * No OpenSSL dependencies
 */

#include "sha512.h"
#include <string.h>

#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIGMA0(x) (ROR64(x,28) ^ ROR64(x,34) ^ ROR64(x,39))
#define SIGMA1(x) (ROR64(x,14) ^ ROR64(x,18) ^ ROR64(x,41))
#define sigma0(x) (ROR64(x, 1) ^ ROR64(x, 8) ^ ((x) >> 7))
#define sigma1(x) (ROR64(x,19) ^ ROR64(x,61) ^ ((x) >> 6))

static const uint64_t K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static void sha512_transform(SHA512_CTX *ctx, const uint8_t data[128]) {
    uint64_t a, b, c, d, e, f, g, h, W[80], T1, T2;
    int i;
    
    for (i = 0; i < 16; i++) {
        W[i] = ((uint64_t)data[i*8] << 56) | ((uint64_t)data[i*8+1] << 48) |
               ((uint64_t)data[i*8+2] << 40) | ((uint64_t)data[i*8+3] << 32) |
               ((uint64_t)data[i*8+4] << 24) | ((uint64_t)data[i*8+5] << 16) |
               ((uint64_t)data[i*8+6] << 8) | ((uint64_t)data[i*8+7]);
    }
    
    for (i = 16; i < 80; i++) {
        W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16];
    }
    
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    
    for (i = 0; i < 80; i++) {
        T1 = h + SIGMA1(e) + CH(e,f,g) + K[i] + W[i];
        T2 = SIGMA0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }
    
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

void sha512_init(SHA512_CTX *ctx) {
    ctx->count[0] = ctx->count[1] = 0;
    ctx->state[0] = 0x6a09e667f3bcc908ULL;
    ctx->state[1] = 0xbb67ae8584caa73bULL;
    ctx->state[2] = 0x3c6ef372fe94f82bULL;
    ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->state[4] = 0x510e527fade682d1ULL;
    ctx->state[5] = 0x9b05688c2b3e6c1fULL;
    ctx->state[6] = 0x1f83d9abfb41bd6bULL;
    ctx->state[7] = 0x5be0cd19137e2179ULL;
}

void sha384_init(SHA512_CTX *ctx) {
    ctx->count[0] = ctx->count[1] = 0;
    ctx->state[0] = 0xcbbb9d5dc1059ed8ULL;
    ctx->state[1] = 0x629a292a367cd507ULL;
    ctx->state[2] = 0x9159015a3070dd17ULL;
    ctx->state[3] = 0x152fecd8f70e5939ULL;
    ctx->state[4] = 0x67332667ffc00b31ULL;
    ctx->state[5] = 0x8eb44a8768581511ULL;
    ctx->state[6] = 0xdb0c2e0d64f98fa7ULL;
    ctx->state[7] = 0x47b5481dbefa4fa4ULL;
}

void sha512_update(SHA512_CTX *ctx, const uint8_t *data, size_t len) {
    size_t i, index, partLen;
    
    index = (size_t)((ctx->count[0] >> 3) & 0x7F);
    
    if ((ctx->count[0] += (len << 3)) < (len << 3))
        ctx->count[1]++;
    ctx->count[1] += (len >> 61);
    
    partLen = 128 - index;
    
    if (len >= partLen) {
        memcpy(&ctx->buffer[index], data, partLen);
        sha512_transform(ctx, ctx->buffer);
        
        for (i = partLen; i + 127 < len; i += 128)
            sha512_transform(ctx, &data[i]);
        
        index = 0;
    } else {
        i = 0;
    }
    
    memcpy(&ctx->buffer[index], &data[i], len - i);
}

void sha512_final(uint8_t digest[SHA512_DIGEST_LENGTH], SHA512_CTX *ctx) {
    uint8_t bits[16];
    size_t index, padLen;
    static uint8_t padding[128] = { 0x80 };
    
    for (int i = 0; i < 8; i++) {
        bits[i] = (ctx->count[1] >> (56 - i*8)) & 0xff;
        bits[i+8] = (ctx->count[0] >> (56 - i*8)) & 0xff;
    }
    
    index = (size_t)((ctx->count[0] >> 3) & 0x7f);
    padLen = (index < 112) ? (112 - index) : (240 - index);
    sha512_update(ctx, padding, padLen);
    sha512_update(ctx, bits, 16);
    
    for (int i = 0; i < 8; i++) {
        digest[i*8]   = (ctx->state[i] >> 56) & 0xff;
        digest[i*8+1] = (ctx->state[i] >> 48) & 0xff;
        digest[i*8+2] = (ctx->state[i] >> 40) & 0xff;
        digest[i*8+3] = (ctx->state[i] >> 32) & 0xff;
        digest[i*8+4] = (ctx->state[i] >> 24) & 0xff;
        digest[i*8+5] = (ctx->state[i] >> 16) & 0xff;
        digest[i*8+6] = (ctx->state[i] >> 8) & 0xff;
        digest[i*8+7] = ctx->state[i] & 0xff;
    }
    
    memset(ctx, 0, sizeof(*ctx));
}

void sha384_final(uint8_t digest[SHA384_DIGEST_LENGTH], SHA512_CTX *ctx) {
    uint8_t temp[SHA512_DIGEST_LENGTH];
    sha512_final(temp, ctx);
    memcpy(digest, temp, SHA384_DIGEST_LENGTH);
}

void sha512_hash(const uint8_t *data, size_t len, uint8_t digest[SHA512_DIGEST_LENGTH]) {
    SHA512_CTX ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, data, len);
    sha512_final(digest, &ctx);
}

void sha384_hash(const uint8_t *data, size_t len, uint8_t digest[SHA384_DIGEST_LENGTH]) {
    SHA512_CTX ctx;
    sha384_init(&ctx);
    sha512_update(&ctx, data, len);
    sha384_final(digest, &ctx);
}
