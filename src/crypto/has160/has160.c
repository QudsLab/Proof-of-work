/*
 * HAS-160 Implementation
 * Korean cryptographic hash function (TTAS.KO-12.0011/R1)
 * Based on RHash reference implementation
 */

#include "has160.h"
#include <string.h>

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* HAS-160 step macros */
#define STEP_F1(A, B, C, D, E, msg, rot) \
    E += ROTL32(A, rot) + (D ^ (B & (C ^ D))) + msg; \
    B = ROTL32(B, 10);

#define STEP_F2(A, B, C, D, E, msg, rot) \
    E += ROTL32(A, rot) + (B ^ C ^ D) + msg + 0x5A827999; \
    B = ROTL32(B, 17);

#define STEP_F3(A, B, C, D, E, msg, rot) \
    E += ROTL32(A, rot) + (C ^ (B | ~D)) + msg + 0x6ED9EBA1; \
    B = ROTL32(B, 25);

#define STEP_F4(A, B, C, D, E, msg, rot) \
    E += ROTL32(A, rot) + (B ^ C ^ D) + msg + 0x8F1BBCDC; \
    B = ROTL32(B, 30);

static void has160_transform(HAS160_CTX *ctx, const uint8_t block[64]) {
    uint32_t X[32];
    uint32_t A, B, C, D, E;
    int j;

    /* Load block as little-endian */
    for (j = 0; j < 16; j++) {
        X[j] = ((uint32_t)block[j * 4]) | 
               ((uint32_t)block[j * 4 + 1] << 8) |
               ((uint32_t)block[j * 4 + 2] << 16) | 
               ((uint32_t)block[j * 4 + 3] << 24);
    }

    /* Message expansion */
    X[16] = X[0] ^ X[1] ^ X[2] ^ X[3];
    X[17] = X[4] ^ X[5] ^ X[6] ^ X[7];
    X[18] = X[8] ^ X[9] ^ X[10] ^ X[11];
    X[19] = X[12] ^ X[13] ^ X[14] ^ X[15];
    X[20] = X[3] ^ X[6] ^ X[9] ^ X[12];
    X[21] = X[2] ^ X[5] ^ X[8] ^ X[15];
    X[22] = X[1] ^ X[4] ^ X[11] ^ X[14];
    X[23] = X[0] ^ X[7] ^ X[10] ^ X[13];
    X[24] = X[5] ^ X[7] ^ X[12] ^ X[14];
    X[25] = X[0] ^ X[2] ^ X[9] ^ X[11];
    X[26] = X[4] ^ X[6] ^ X[13] ^ X[15];
    X[27] = X[1] ^ X[3] ^ X[8] ^ X[10];
    X[28] = X[2] ^ X[7] ^ X[8] ^ X[13];
    X[29] = X[3] ^ X[4] ^ X[9] ^ X[14];
    X[30] = X[0] ^ X[5] ^ X[10] ^ X[15];
    X[31] = X[1] ^ X[6] ^ X[11] ^ X[12];

    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];

    /* Round 1 (steps 1-20) */
    STEP_F1(A,B,C,D,E,X[18], 5); STEP_F1(E,A,B,C,D,X[ 0],11);
    STEP_F1(D,E,A,B,C,X[ 1], 7); STEP_F1(C,D,E,A,B,X[ 2],15);
    STEP_F1(B,C,D,E,A,X[ 3], 6); STEP_F1(A,B,C,D,E,X[19],13);
    STEP_F1(E,A,B,C,D,X[ 4], 8); STEP_F1(D,E,A,B,C,X[ 5],14);
    STEP_F1(C,D,E,A,B,X[ 6], 7); STEP_F1(B,C,D,E,A,X[ 7],12);
    STEP_F1(A,B,C,D,E,X[16], 9); STEP_F1(E,A,B,C,D,X[ 8],11);
    STEP_F1(D,E,A,B,C,X[ 9], 8); STEP_F1(C,D,E,A,B,X[10],15);
    STEP_F1(B,C,D,E,A,X[11], 6); STEP_F1(A,B,C,D,E,X[17],12);
    STEP_F1(E,A,B,C,D,X[12], 9); STEP_F1(D,E,A,B,C,X[13],14);
    STEP_F1(C,D,E,A,B,X[14], 5); STEP_F1(B,C,D,E,A,X[15],13);

    /* Round 2 (steps 21-40) */
    STEP_F2(A,B,C,D,E,X[22], 5); STEP_F2(E,A,B,C,D,X[ 3],11);
    STEP_F2(D,E,A,B,C,X[ 6], 7); STEP_F2(C,D,E,A,B,X[ 9],15);
    STEP_F2(B,C,D,E,A,X[12], 6); STEP_F2(A,B,C,D,E,X[23],13);
    STEP_F2(E,A,B,C,D,X[15], 8); STEP_F2(D,E,A,B,C,X[ 2],14);
    STEP_F2(C,D,E,A,B,X[ 5], 7); STEP_F2(B,C,D,E,A,X[ 8],12);
    STEP_F2(A,B,C,D,E,X[20], 9); STEP_F2(E,A,B,C,D,X[11],11);
    STEP_F2(D,E,A,B,C,X[14], 8); STEP_F2(C,D,E,A,B,X[ 1],15);
    STEP_F2(B,C,D,E,A,X[ 4], 6); STEP_F2(A,B,C,D,E,X[21],12);
    STEP_F2(E,A,B,C,D,X[ 7], 9); STEP_F2(D,E,A,B,C,X[10],14);
    STEP_F2(C,D,E,A,B,X[13], 5); STEP_F2(B,C,D,E,A,X[ 0],13);

    /* Round 3 (steps 41-60) */
    STEP_F3(A,B,C,D,E,X[26], 5); STEP_F3(E,A,B,C,D,X[12],11);
    STEP_F3(D,E,A,B,C,X[ 5], 7); STEP_F3(C,D,E,A,B,X[14],15);
    STEP_F3(B,C,D,E,A,X[ 7], 6); STEP_F3(A,B,C,D,E,X[27],13);
    STEP_F3(E,A,B,C,D,X[ 0], 8); STEP_F3(D,E,A,B,C,X[ 9],14);
    STEP_F3(C,D,E,A,B,X[ 2], 7); STEP_F3(B,C,D,E,A,X[11],12);
    STEP_F3(A,B,C,D,E,X[24], 9); STEP_F3(E,A,B,C,D,X[ 4],11);
    STEP_F3(D,E,A,B,C,X[13], 8); STEP_F3(C,D,E,A,B,X[ 6],15);
    STEP_F3(B,C,D,E,A,X[15], 6); STEP_F3(A,B,C,D,E,X[25],12);
    STEP_F3(E,A,B,C,D,X[ 8], 9); STEP_F3(D,E,A,B,C,X[ 1],14);
    STEP_F3(C,D,E,A,B,X[10], 5); STEP_F3(B,C,D,E,A,X[ 3],13);

    /* Round 4 (steps 61-80) */
    STEP_F4(A,B,C,D,E,X[30], 5); STEP_F4(E,A,B,C,D,X[ 7],11);
    STEP_F4(D,E,A,B,C,X[ 2], 7); STEP_F4(C,D,E,A,B,X[13],15);
    STEP_F4(B,C,D,E,A,X[ 8], 6); STEP_F4(A,B,C,D,E,X[31],13);
    STEP_F4(E,A,B,C,D,X[ 3], 8); STEP_F4(D,E,A,B,C,X[14],14);
    STEP_F4(C,D,E,A,B,X[ 9], 7); STEP_F4(B,C,D,E,A,X[ 4],12);
    STEP_F4(A,B,C,D,E,X[28], 9); STEP_F4(E,A,B,C,D,X[15],11);
    STEP_F4(D,E,A,B,C,X[10], 8); STEP_F4(C,D,E,A,B,X[ 5],15);
    STEP_F4(B,C,D,E,A,X[ 0], 6); STEP_F4(A,B,C,D,E,X[29],12);
    STEP_F4(E,A,B,C,D,X[11], 9); STEP_F4(D,E,A,B,C,X[ 6],14);
    STEP_F4(C,D,E,A,B,X[ 1], 5); STEP_F4(B,C,D,E,A,X[12],13);

    ctx->state[0] += A;
    ctx->state[1] += B;
    ctx->state[2] += C;
    ctx->state[3] += D;
    ctx->state[4] += E;
}

void has160_init(HAS160_CTX *ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xc3d2e1f0;
    ctx->count = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

void has160_update(HAS160_CTX *ctx, const uint8_t *data, size_t len) {
    size_t index = (size_t)(ctx->count & 0x3F);
    ctx->count += len;

    if (index) {
        size_t left = HAS160_BLOCK_SIZE - index;
        if (len < left) {
            memcpy(ctx->buffer + index, data, len);
            return;
        }
        memcpy(ctx->buffer + index, data, left);
        has160_transform(ctx, ctx->buffer);
        data += left;
        len -= left;
    }

    while (len >= HAS160_BLOCK_SIZE) {
        has160_transform(ctx, data);
        data += HAS160_BLOCK_SIZE;
        len -= HAS160_BLOCK_SIZE;
    }

    if (len) {
        memcpy(ctx->buffer, data, len);
    }
}

void has160_final(uint8_t digest[HAS160_DIGEST_LENGTH], HAS160_CTX *ctx) {
    uint64_t bits = ctx->count * 8;
    size_t index = (size_t)(ctx->count & 0x3F);

    /* Padding */
    ctx->buffer[index++] = 0x80;
    if (index > 56) {
        memset(ctx->buffer + index, 0, HAS160_BLOCK_SIZE - index);
        has160_transform(ctx, ctx->buffer);
        index = 0;
    }
    memset(ctx->buffer + index, 0, 56 - index);

    /* Append length as little-endian */
    for (int i = 0; i < 8; i++) {
        ctx->buffer[56 + i] = (uint8_t)(bits >> (i * 8));
    }
    has160_transform(ctx, ctx->buffer);

    /* Output as little-endian */
    for (int i = 0; i < 5; i++) {
        digest[i * 4] = (uint8_t)(ctx->state[i]);
        digest[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 8);
        digest[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 16);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i] >> 24);
    }

    memset(ctx, 0, sizeof(*ctx));
}

void has160_hash(const uint8_t *data, size_t len, uint8_t digest[HAS160_DIGEST_LENGTH]) {
    HAS160_CTX ctx;
    has160_init(&ctx);
    has160_update(&ctx, data, len);
    has160_final(digest, &ctx);
}
