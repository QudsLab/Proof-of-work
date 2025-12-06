/*
 * SHA3-384 Implementation
 * Based on Keccak-f[1600] with rate=832, capacity=768
 */

#include "sha3_384.h"
#include <string.h>

#define KECCAK_ROUNDS 24

static const uint64_t keccak_rc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int keccak_rho[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const int keccak_pi[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

static void keccak_f1600(uint64_t state[25]) {
    uint64_t t, bc[5];
    int i, j, r;

    for (r = 0; r < KECCAK_ROUNDS; r++) {
        for (i = 0; i < 5; i++)
            bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5) state[j + i] ^= t;
        }

        t = state[1];
        for (i = 0; i < 24; i++) {
            j = keccak_pi[i];
            bc[0] = state[j];
            state[j] = ROTL64(t, keccak_rho[i]);
            t = bc[0];
        }

        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++) bc[i] = state[j + i];
            for (i = 0; i < 5; i++) state[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }

        state[0] ^= keccak_rc[r];
    }
}

void sha3_384_init(SHA3_384_CTX *ctx) {
    memset(ctx->state, 0, sizeof(ctx->state));
    ctx->rate = 104; /* (1600 - 768) / 8 = 104 bytes */
    ctx->buf_len = 0;
}

void sha3_384_update(SHA3_384_CTX *ctx, const uint8_t *data, size_t len) {
    size_t i;

    for (i = 0; i < len; i++) {
        ctx->buffer[ctx->buf_len++] = data[i];
        if (ctx->buf_len == ctx->rate) {
            for (size_t j = 0; j < ctx->rate / 8; j++) {
                ctx->state[j] ^= ((uint64_t *)ctx->buffer)[j];
            }
            keccak_f1600(ctx->state);
            ctx->buf_len = 0;
        }
    }
}

void sha3_384_final(uint8_t digest[SHA3_384_DIGEST_LENGTH], SHA3_384_CTX *ctx) {
    ctx->buffer[ctx->buf_len++] = 0x06;
    memset(ctx->buffer + ctx->buf_len, 0, ctx->rate - ctx->buf_len);
    ctx->buffer[ctx->rate - 1] |= 0x80;

    for (size_t j = 0; j < ctx->rate / 8; j++) {
        ctx->state[j] ^= ((uint64_t *)ctx->buffer)[j];
    }
    keccak_f1600(ctx->state);

    memcpy(digest, ctx->state, SHA3_384_DIGEST_LENGTH);
    memset(ctx, 0, sizeof(*ctx));
}

void sha3_384_hash(const uint8_t *data, size_t len, uint8_t digest[SHA3_384_DIGEST_LENGTH]) {
    SHA3_384_CTX ctx;
    sha3_384_init(&ctx);
    sha3_384_update(&ctx, data, len);
    sha3_384_final(digest, &ctx);
}
