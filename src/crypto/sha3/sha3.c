/*
 * Standalone SHA-3/Keccak implementation
 * Based on FIPS 202 SHA-3 Standard
 */

#include "sha3.h"
#include <string.h>

#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

static const uint64_t keccak_round_constants[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static void keccak_theta(uint64_t *A) {
    uint64_t C[5], D[5];
    int i;
    
    for (i = 0; i < 5; i++) {
        C[i] = A[i] ^ A[i + 5] ^ A[i + 10] ^ A[i + 15] ^ A[i + 20];
    }
    
    for (i = 0; i < 5; i++) {
        D[i] = C[(i + 4) % 5] ^ ROTL64(C[(i + 1) % 5], 1);
    }
    
    for (i = 0; i < 25; i++) {
        A[i] ^= D[i % 5];
    }
}

static void keccak_rho(uint64_t *A) {
    static const int rho_offsets[25] = {
        0, 1, 62, 28, 27,
        36, 44, 6, 55, 20,
        3, 10, 43, 25, 39,
        41, 45, 15, 21, 8,
        18, 2, 61, 56, 14
    };
    
    for (int i = 0; i < 25; i++) {
        A[i] = ROTL64(A[i], rho_offsets[i]);
    }
}

static void keccak_pi(uint64_t *A) {
    uint64_t A1 = A[1];
    A[1] = A[6]; A[6] = A[9]; A[9] = A[22]; A[22] = A[14];
    A[14] = A[20]; A[20] = A[2]; A[2] = A[12]; A[12] = A[13];
    A[13] = A[19]; A[19] = A[23]; A[23] = A[15]; A[15] = A[4];
    A[4] = A[24]; A[24] = A[21]; A[21] = A[8]; A[8] = A[16];
    A[16] = A[5]; A[5] = A[3]; A[3] = A[18]; A[18] = A[17];
    A[17] = A[11]; A[11] = A[7]; A[7] = A[10]; A[10] = A1;
}

static void keccak_chi(uint64_t *A) {
    uint64_t B[5];
    int i, j;
    
    for (j = 0; j < 25; j += 5) {
        for (i = 0; i < 5; i++) {
            B[i] = A[j + i];
        }
        for (i = 0; i < 5; i++) {
            A[j + i] = B[i] ^ ((~B[(i + 1) % 5]) & B[(i + 2) % 5]);
        }
    }
}

static void keccak_f1600(uint64_t *state) {
    int round;
    
    for (round = 0; round < 24; round++) {
        keccak_theta(state);
        keccak_rho(state);
        keccak_pi(state);
        keccak_chi(state);
        state[0] ^= keccak_round_constants[round];
    }
}

void sha3_256_init(SHA3_CTX *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->rate = 136;  /* (1600 - 512) / 8 */
    ctx->capacity = 64;
    ctx->output_len = 32;
}

void sha3_512_init(SHA3_CTX *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->rate = 72;   /* (1600 - 1024) / 8 */
    ctx->capacity = 128;
    ctx->output_len = 64;
}

void keccak_256_init(SHA3_CTX *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->rate = 136;  /* (1600 - 512) / 8 */
    ctx->capacity = 64;
    ctx->output_len = 32;
}

void sha3_update(SHA3_CTX *ctx, const uint8_t *data, size_t len) {
    size_t i;
    
    for (i = 0; i < len; i++) {
        ctx->buffer[ctx->buf_len++] = data[i];
        if (ctx->buf_len == ctx->rate) {
            /* XOR buffer into state */
            for (size_t j = 0; j < ctx->rate / 8; j++) {
                uint64_t lane = 0;
                for (int k = 0; k < 8; k++) {
                    lane |= (uint64_t)ctx->buffer[j * 8 + k] << (8 * k);
                }
                ctx->state[j] ^= lane;
            }
            keccak_f1600(ctx->state);
            ctx->buf_len = 0;
        }
    }
}

void sha3_final(uint8_t *digest, SHA3_CTX *ctx) {
    /* SHA-3 padding: append 0x06, then 0x00s, then 0x80 */
    memset(ctx->buffer + ctx->buf_len, 0, ctx->rate - ctx->buf_len);
    ctx->buffer[ctx->buf_len] = 0x06;
    ctx->buffer[ctx->rate - 1] |= 0x80;
    
    /* XOR final block into state */
    for (size_t j = 0; j < ctx->rate / 8; j++) {
        uint64_t lane = 0;
        for (int k = 0; k < 8; k++) {
            lane |= (uint64_t)ctx->buffer[j * 8 + k] << (8 * k);
        }
        ctx->state[j] ^= lane;
    }
    keccak_f1600(ctx->state);
    
    /* Extract output (little-endian) */
    for (size_t i = 0; i < ctx->output_len; i++) {
        digest[i] = (uint8_t)(ctx->state[i / 8] >> (8 * (i % 8)));
    }
    
    memset(ctx, 0, sizeof(*ctx));
}

void sha3_256_hash(const uint8_t *data, size_t len, uint8_t digest[SHA3_256_DIGEST_LENGTH]) {
    SHA3_CTX ctx;
    sha3_256_init(&ctx);
    sha3_update(&ctx, data, len);
    sha3_final(digest, &ctx);
}

void sha3_512_hash(const uint8_t *data, size_t len, uint8_t digest[SHA3_512_DIGEST_LENGTH]) {
    SHA3_CTX ctx;
    sha3_512_init(&ctx);
    sha3_update(&ctx, data, len);
    sha3_final(digest, &ctx);
}

void keccak_256_hash(const uint8_t *data, size_t len, uint8_t digest[KECCAK_256_DIGEST_LENGTH]) {
    SHA3_CTX ctx;
    keccak_256_init(&ctx);
    sha3_update(&ctx, data, len);
    
    /* Keccak padding: 0x01 instead of 0x06 */
    memset(ctx.buffer + ctx.buf_len, 0, ctx.rate - ctx.buf_len);
    ctx.buffer[ctx.buf_len] = 0x01;
    ctx.buffer[ctx.rate - 1] |= 0x80;
    
    for (size_t j = 0; j < ctx.rate / 8; j++) {
        uint64_t lane = 0;
        for (int k = 0; k < 8; k++) {
            lane |= (uint64_t)ctx.buffer[j * 8 + k] << (8 * k);
        }
        ctx.state[j] ^= lane;
    }
    keccak_f1600(ctx.state);
    
    for (size_t i = 0; i < ctx.output_len; i++) {
        digest[i] = (uint8_t)(ctx.state[i / 8] >> (8 * (i % 8)));
    }
    
    memset(&ctx, 0, sizeof(ctx));
}
