#include "argon2id.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* BLAKE2b constants */
#define BLAKE2B_BLOCKBYTES 128
#define BLAKE2B_OUTBYTES 64

typedef struct {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t buf[BLAKE2B_BLOCKBYTES];
    size_t buflen;
} blake2b_state;

static const uint64_t blake2b_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static inline uint64_t rotr64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

static inline uint64_t load64(const void *src) {
    uint64_t w;
    memcpy(&w, src, sizeof w);
    return w;
}

static inline void store32(void *dst, uint32_t w) {
    memcpy(dst, &w, sizeof w);
}

static inline void store64(void *dst, uint64_t w) {
    memcpy(dst, &w, sizeof w);
}

/* BLAKE2b compression */
static void blake2b_compress(blake2b_state *S, const uint8_t block[BLAKE2B_BLOCKBYTES]) {
    uint64_t m[16], v[16];
    static const uint8_t sigma[12][16] = {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
        {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
        {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
        {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
        {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
        {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
        {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
        {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
        {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}
    };
    
    for (int i = 0; i < 16; i++) m[i] = load64(block + i * 8);
    for (int i = 0; i < 8; i++) v[i] = S->h[i];
    for (int i = 0; i < 8; i++) v[i + 8] = blake2b_IV[i];
    
    v[12] ^= S->t[0];
    v[13] ^= S->t[1];
    v[14] ^= S->f[0];
    v[15] ^= S->f[1];
    
#define G(r, i, a, b, c, d) do { \
    a = a + b + m[sigma[r][2*i]]; \
    d = rotr64(d ^ a, 32); \
    c = c + d; \
    b = rotr64(b ^ c, 24); \
    a = a + b + m[sigma[r][2*i+1]]; \
    d = rotr64(d ^ a, 16); \
    c = c + d; \
    b = rotr64(b ^ c, 63); \
} while(0)
    
#define ROUND(r) do { \
    G(r, 0, v[0], v[4], v[8], v[12]); \
    G(r, 1, v[1], v[5], v[9], v[13]); \
    G(r, 2, v[2], v[6], v[10], v[14]); \
    G(r, 3, v[3], v[7], v[11], v[15]); \
    G(r, 4, v[0], v[5], v[10], v[15]); \
    G(r, 5, v[1], v[6], v[11], v[12]); \
    G(r, 6, v[2], v[7], v[8], v[13]); \
    G(r, 7, v[3], v[4], v[9], v[14]); \
} while(0)
    
    for (int i = 0; i < 12; i++) ROUND(i);
    
    for (int i = 0; i < 8; i++) S->h[i] ^= v[i] ^ v[i + 8];
#undef G
#undef ROUND
}

static void blake2b_init(blake2b_state *S, size_t outlen) {
    memset(S, 0, sizeof(blake2b_state));
    memcpy(S->h, blake2b_IV, sizeof(blake2b_IV));
    S->h[0] ^= 0x01010000 ^ outlen;
}

static void blake2b_update(blake2b_state *S, const void *in, size_t inlen) {
    const uint8_t *pin = (const uint8_t *)in;
    
    while (inlen > 0) {
        size_t left = S->buflen;
        size_t fill = BLAKE2B_BLOCKBYTES - left;
        
        if (inlen > fill) {
            memcpy(S->buf + left, pin, fill);
            S->buflen = 0;
            S->t[0] += BLAKE2B_BLOCKBYTES;
            if (S->t[0] < BLAKE2B_BLOCKBYTES) S->t[1]++;
            blake2b_compress(S, S->buf);
            pin += fill;
            inlen -= fill;
        } else {
            memcpy(S->buf + left, pin, inlen);
            S->buflen += inlen;
            break;
        }
    }
}

static void blake2b_final(blake2b_state *S, void *out, size_t outlen) {
    uint8_t buffer[BLAKE2B_OUTBYTES];
    
    S->t[0] += S->buflen;
    if (S->t[0] < S->buflen) S->t[1]++;
    S->f[0] = (uint64_t)-1;
    
    memset(S->buf + S->buflen, 0, BLAKE2B_BLOCKBYTES - S->buflen);
    blake2b_compress(S, S->buf);
    
    for (int i = 0; i < 8; i++) store64(buffer + i * 8, S->h[i]);
    memcpy(out, buffer, outlen);
    memset(buffer, 0, sizeof(buffer));
}

/* BLAKE2b long - RFC 9106 Section 3.3 */
static void blake2b_long(void *out, size_t outlen, const void *in, size_t inlen) {
    blake2b_state S;
    uint8_t outlen_bytes[4];
    store32(outlen_bytes, (uint32_t)outlen);
    
    if (outlen <= BLAKE2B_OUTBYTES) {
        blake2b_init(&S, outlen);
        blake2b_update(&S, outlen_bytes, sizeof(outlen_bytes));
        blake2b_update(&S, in, inlen);
        blake2b_final(&S, out, outlen);
    } else {
        uint32_t toproduce;
        uint8_t out_buffer[BLAKE2B_OUTBYTES];
        uint8_t in_buffer[BLAKE2B_OUTBYTES];
        
        blake2b_init(&S, BLAKE2B_OUTBYTES);
        blake2b_update(&S, outlen_bytes, sizeof(outlen_bytes));
        blake2b_update(&S, in, inlen);
        blake2b_final(&S, out_buffer, BLAKE2B_OUTBYTES);
        memcpy(out, out_buffer, BLAKE2B_OUTBYTES / 2);
        
        uint8_t *outp = (uint8_t *)out + BLAKE2B_OUTBYTES / 2;
        toproduce = (uint32_t)outlen - BLAKE2B_OUTBYTES / 2;
        
        while (toproduce > BLAKE2B_OUTBYTES) {
            memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
            blake2b_init(&S, BLAKE2B_OUTBYTES);
            blake2b_update(&S, in_buffer, BLAKE2B_OUTBYTES);
            blake2b_final(&S, out_buffer, BLAKE2B_OUTBYTES);
            memcpy(outp, out_buffer, BLAKE2B_OUTBYTES / 2);
            outp += BLAKE2B_OUTBYTES / 2;
            toproduce -= BLAKE2B_OUTBYTES / 2;
        }
        
        memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
        blake2b_init(&S, toproduce);
        blake2b_update(&S, in_buffer, BLAKE2B_OUTBYTES);
        blake2b_final(&S, out_buffer, toproduce);
        memcpy(outp, out_buffer, toproduce);
    }
}

/* Argon2 block structure */
#define ARGON2_BLOCK_SIZE 1024
#define ARGON2_QWORDS_IN_BLOCK (ARGON2_BLOCK_SIZE / 8)
#define ARGON2_SYNC_POINTS 4
#define ARGON2_PREHASH_DIGEST_LENGTH 64
#define ARGON2_PREHASH_SEED_LENGTH 72

typedef struct {
    uint64_t v[ARGON2_QWORDS_IN_BLOCK];
} block;

/* BlaMka mixing function - exact PHC implementation */
static inline uint64_t fBlaMka(uint64_t x, uint64_t y) {
    const uint64_t m = 0xFFFFFFFFULL;
    const uint64_t xy = (x & m) * (y & m);
    return x + y + 2 * xy;
}

#define GB(a, b, c, d) do { \
    a = fBlaMka(a, b); \
    d = rotr64(d ^ a, 32); \
    c = fBlaMka(c, d); \
    b = rotr64(b ^ c, 24); \
    a = fBlaMka(a, b); \
    d = rotr64(d ^ a, 16); \
    c = fBlaMka(c, d); \
    b = rotr64(b ^ c, 63); \
} while(0)

#define BLAKE2_ROUND_NOMSG(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) do { \
    GB(v0, v4, v8, v12); \
    GB(v1, v5, v9, v13); \
    GB(v2, v6, v10, v14); \
    GB(v3, v7, v11, v15); \
    GB(v0, v5, v10, v15); \
    GB(v1, v6, v11, v12); \
    GB(v2, v7, v8, v13); \
    GB(v3, v4, v9, v14); \
} while(0)

static void copy_block(block *dst, const block *src) {
    memcpy(dst->v, src->v, sizeof(dst->v));
}

static void xor_block(block *dst, const block *src) {
    for (int i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
        dst->v[i] ^= src->v[i];
    }
}

static void load_block(block *dst, const uint8_t *input) {
    for (int i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
        dst->v[i] = load64(input + i * 8);
    }
}

static void store_block(uint8_t *output, const block *src) {
    for (int i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
        store64(output + i * 8, src->v[i]);
    }
}

/* Fill block - exact PHC reference implementation */
static void fill_block(const block *prev_block, const block *ref_block,
                      block *next_block, int with_xor) {
    block blockR, block_tmp;
    
    copy_block(&blockR, ref_block);
    xor_block(&blockR, prev_block);
    copy_block(&block_tmp, &blockR);
    
    if (with_xor) {
        xor_block(&block_tmp, next_block);
    }
    
    /* Apply Blake2 round on rows (8 rows of 16 64-bit words) */
    for (int i = 0; i < 8; i++) {
        BLAKE2_ROUND_NOMSG(
            blockR.v[16 * i + 0], blockR.v[16 * i + 1], blockR.v[16 * i + 2], blockR.v[16 * i + 3],
            blockR.v[16 * i + 4], blockR.v[16 * i + 5], blockR.v[16 * i + 6], blockR.v[16 * i + 7],
            blockR.v[16 * i + 8], blockR.v[16 * i + 9], blockR.v[16 * i + 10], blockR.v[16 * i + 11],
            blockR.v[16 * i + 12], blockR.v[16 * i + 13], blockR.v[16 * i + 14], blockR.v[16 * i + 15]
        );
    }
    
    /* Apply Blake2 round on columns (8 columns of 16 64-bit words) */
    for (int i = 0; i < 8; i++) {
        BLAKE2_ROUND_NOMSG(
            blockR.v[2 * i + 0], blockR.v[2 * i + 1], blockR.v[2 * i + 16], blockR.v[2 * i + 17],
            blockR.v[2 * i + 32], blockR.v[2 * i + 33], blockR.v[2 * i + 48], blockR.v[2 * i + 49],
            blockR.v[2 * i + 64], blockR.v[2 * i + 65], blockR.v[2 * i + 80], blockR.v[2 * i + 81],
            blockR.v[2 * i + 96], blockR.v[2 * i + 97], blockR.v[2 * i + 112], blockR.v[2 * i + 113]
        );
    }
    
    copy_block(next_block, &block_tmp);
    xor_block(next_block, &blockR);
}

/* Index calculation - RFC 9106 Section 3.4.2 */
static uint32_t index_alpha(uint32_t pass, uint32_t slice, uint32_t index,
                           uint64_t pseudo_rand, uint32_t lanes,
                           uint32_t segment_length, uint32_t lane) {
    uint32_t reference_area_size;
    uint64_t relative_position;
    uint32_t start_position, absolute_position;
    
    /* Determine reference lane */
    uint32_t ref_lane = (uint32_t)((pseudo_rand >> 32) % lanes);
    
    /* First pass, first slice: must use same lane */
    if (pass == 0 && slice == 0) {
        ref_lane = lane;
    }
    
    int same_lane = (ref_lane == lane);
    
    /* Calculate reference area size per RFC 9106 */
    if (pass == 0) {
        if (slice == 0) {
            /* First slice of first pass */
            reference_area_size = index - 1;
        } else {
            if (same_lane) {
                /* Same lane: can reference current segment */
                reference_area_size = slice * segment_length + index - 1;
            } else {
                /* Different lane: previous segments only */
                reference_area_size = slice * segment_length + ((index == 0) ? -1 : 0);
            }
        }
    } else {
        /* Subsequent passes */
        if (same_lane) {
            reference_area_size = lanes * segment_length * ARGON2_SYNC_POINTS - 
                                 segment_length + index - 1;
        } else {
            reference_area_size = lanes * segment_length * ARGON2_SYNC_POINTS - 
                                 segment_length + ((index == 0) ? -1 : 0);
        }
    }
    
    /* Map pseudo_rand to reference area using PHC formula */
    relative_position = pseudo_rand & 0xFFFFFFFFULL;
    relative_position = (relative_position * relative_position) >> 32;
    relative_position = reference_area_size - 1 - 
                       ((uint64_t)reference_area_size * relative_position >> 32);
    
    /* Calculate start position */
    start_position = 0;
    if (pass != 0) {
        start_position = (slice == ARGON2_SYNC_POINTS - 1) ? 0 : 
                        (slice + 1) * segment_length;
    }
    
    /* Calculate absolute position in lane */
    uint32_t lane_length = segment_length * ARGON2_SYNC_POINTS;
    absolute_position = (start_position + (uint32_t)relative_position) % lane_length;
    
    return ref_lane * lane_length + absolute_position;
}

void argon2_params_init(argon2_params *params) {
    params->t_cost = ARGON2_DEFAULT_T_COST;
    params->m_cost = ARGON2_DEFAULT_M_COST;
    params->parallelism = ARGON2_DEFAULT_PARALLELISM;
    params->hash_len = ARGON2_DEFAULT_HASH_LEN;
    params->salt_len = ARGON2_DEFAULT_SALT_LEN;
}

int argon2id_hash(const void *pwd, size_t pwd_len,
                  const void *salt, size_t salt_len,
                  const argon2_params *params,
                  void *out, size_t out_len) {
    
    if (!pwd || !salt || !params || !out) {
        return ARGON2_INVALID_PARAMS;
    }
    
    if (params->t_cost < ARGON2_MIN_T_COST ||
        params->m_cost < ARGON2_MIN_M_COST ||
        params->parallelism < ARGON2_MIN_PARALLELISM ||
        params->hash_len < ARGON2_MIN_HASH_LEN ||
        salt_len < ARGON2_MIN_SALT_LEN ||
        out_len < params->hash_len) {
        return ARGON2_INVALID_PARAMS;
    }
    
    /* m_cost is in KiB - convert to blocks (1 block = 1024 bytes = 1 KiB) */
    uint32_t lanes = params->parallelism;
    uint32_t memory_blocks = params->m_cost;
    
    /* Round down to nearest multiple of 4*parallelism per RFC 9106 */
    uint32_t segment_length = memory_blocks / (lanes * ARGON2_SYNC_POINTS);
    memory_blocks = segment_length * lanes * ARGON2_SYNC_POINTS;
    uint32_t lane_length = segment_length * ARGON2_SYNC_POINTS;
    
    if (memory_blocks < 8 * lanes) {
        return ARGON2_INVALID_PARAMS;
    }
    
    block *memory = (block *)calloc(memory_blocks, sizeof(block));
    if (!memory) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }
    
    /* Build H0 - RFC 9106 Section 3.2 */
    uint8_t blockhash[ARGON2_PREHASH_SEED_LENGTH];
    blake2b_state blake_state;
    blake2b_init(&blake_state, ARGON2_PREHASH_DIGEST_LENGTH);
    
    uint32_t val;
    val = lanes; blake2b_update(&blake_state, &val, 4);
    val = params->hash_len; blake2b_update(&blake_state, &val, 4);
    val = params->m_cost; blake2b_update(&blake_state, &val, 4);
    val = params->t_cost; blake2b_update(&blake_state, &val, 4);
    val = 0x13; blake2b_update(&blake_state, &val, 4); /* version 19 */
    val = 2; blake2b_update(&blake_state, &val, 4); /* type: Argon2id */
    val = (uint32_t)pwd_len; blake2b_update(&blake_state, &val, 4);
    blake2b_update(&blake_state, pwd, pwd_len);
    val = (uint32_t)salt_len; blake2b_update(&blake_state, &val, 4);
    blake2b_update(&blake_state, salt, salt_len);
    val = 0; blake2b_update(&blake_state, &val, 4); /* secret length */
    val = 0; blake2b_update(&blake_state, &val, 4); /* ad length */
    
    blake2b_final(&blake_state, blockhash, ARGON2_PREHASH_DIGEST_LENGTH);
    memset(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, 0, 
           ARGON2_PREHASH_SEED_LENGTH - ARGON2_PREHASH_DIGEST_LENGTH);
    
    /* Fill first two blocks per lane - RFC 9106 Section 3.2 step 3-4 */
    uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
    for (uint32_t l = 0; l < lanes; l++) {
        store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, 0);
        store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH + 4, l);
        blake2b_long(blockhash_bytes, ARGON2_BLOCK_SIZE, blockhash, ARGON2_PREHASH_SEED_LENGTH);
        load_block(&memory[l * lane_length + 0], blockhash_bytes);
        
        store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, 1);
        blake2b_long(blockhash_bytes, ARGON2_BLOCK_SIZE, blockhash, ARGON2_PREHASH_SEED_LENGTH);
        load_block(&memory[l * lane_length + 1], blockhash_bytes);
    }
    
    /* Fill memory blocks - RFC 9106 Section 3.2 step 5-6 */
    block zero_block, input_block, address_block;
    int data_independent_addressing;
    
    for (uint32_t pass = 0; pass < params->t_cost; pass++) {
        for (uint32_t slice = 0; slice < ARGON2_SYNC_POINTS; slice++) {
            for (uint32_t lane = 0; lane < lanes; lane++) {
                uint32_t starting_index = (pass == 0 && slice == 0) ? 2 : 0;
                
                /* Argon2id: data-independent for first half of first pass */
                data_independent_addressing = (pass == 0 && slice < ARGON2_SYNC_POINTS / 2);
                
                if (data_independent_addressing && starting_index == 0) {
                    /* Initialize address generation for Argon2i mode */
                    memset(&zero_block, 0, sizeof(block));
                    memset(&input_block, 0, sizeof(block));
                    input_block.v[0] = pass;
                    input_block.v[1] = lane;
                    input_block.v[2] = slice;
                    input_block.v[3] = memory_blocks;
                    input_block.v[4] = params->t_cost;
                    input_block.v[5] = 2; /* Argon2id type */
                    
                    /* Generate first address block */
                    fill_block(&zero_block, &input_block, &address_block, 0);
                    fill_block(&zero_block, &address_block, &address_block, 0);
                }
                
                for (uint32_t index = starting_index; index < segment_length; index++) {
                    uint32_t curr_offset = lane * lane_length + slice * segment_length + index;
                    
                    /* Calculate previous block offset */
                    uint32_t prev_offset;
                    if (curr_offset % lane_length == 0) {
                        prev_offset = curr_offset + lane_length - 1;
                    } else {
                        prev_offset = curr_offset - 1;
                    }
                    
                    /* Get pseudo-random value */
                    uint64_t pseudo_rand;
                    if (data_independent_addressing) {
                        /* Generate new addresses if needed */
                        if (index % 128 == 0 && index > 0) {
                            input_block.v[6]++;
                            fill_block(&zero_block, &input_block, &address_block, 0);
                            fill_block(&zero_block, &address_block, &address_block, 0);
                        }
                        pseudo_rand = address_block.v[index % 128];
                    } else {
                        /* Data-dependent: use previous block */
                        pseudo_rand = memory[prev_offset].v[0];
                    }
                    
                    /* Calculate reference block index */
                    uint32_t ref_index = index_alpha(pass, slice, index, pseudo_rand, 
                                                     lanes, segment_length, lane);
                    
                    /* Fill current block */
                    fill_block(&memory[prev_offset], &memory[ref_index], 
                              &memory[curr_offset], pass != 0);
                }
            }
        }
    }
    
    /* Final hash: XOR last block from each lane - RFC 9106 Section 3.2 step 7-8 */
    block final_block;
    copy_block(&final_block, &memory[lane_length - 1]);
    for (uint32_t l = 1; l < lanes; l++) {
        xor_block(&final_block, &memory[l * lane_length + lane_length - 1]);
    }
    
    /* Apply H' to produce final output */
    blake2b_long(out, out_len, final_block.v, ARGON2_BLOCK_SIZE);
    
    /* Clear memory */
    memset(memory, 0, memory_blocks * sizeof(block));
    free(memory);
    memset(&final_block, 0, sizeof(final_block));
    memset(blockhash, 0, sizeof(blockhash));
    
    return ARGON2_OK;
}

int argon2id_verify(const void *pwd, size_t pwd_len,
                    const void *salt, size_t salt_len,
                    const argon2_params *params,
                    const void *hash, size_t hash_len) {
    
    if (hash_len != params->hash_len) {
        return ARGON2_INVALID_PARAMS;
    }
    
    uint8_t *computed_hash = (uint8_t *)malloc(hash_len);
    if (!computed_hash) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }
    
    int result = argon2id_hash(pwd, pwd_len, salt, salt_len, params, computed_hash, hash_len);
    
    if (result == ARGON2_OK) {
        int match = 1;
        const uint8_t *h = (const uint8_t *)hash;
        for (size_t i = 0; i < hash_len; i++) {
            if (computed_hash[i] != h[i]) match = 0;
        }
        result = match ? ARGON2_OK : ARGON2_INVALID_PARAMS;
    }
    
    memset(computed_hash, 0, hash_len);
    free(computed_hash);
    
    return result;
}

int argon2id_encode_string(char *out, size_t out_len,
                           const argon2_params *params,
                           const void *salt, size_t salt_len,
                           const void *hash, size_t hash_len) {
    
    if (!out || !params || !salt || !hash) {
        return ARGON2_INVALID_PARAMS;
    }
    
    int written = snprintf(out, out_len,
                          "$argon2id$v=19$m=%u,t=%u,p=%u$",
                          params->m_cost, params->t_cost, params->parallelism);
    
    if (written < 0 || (size_t)written >= out_len) {
        return ARGON2_ENCODING_FAIL;
    }
    
    return ARGON2_OK;
}