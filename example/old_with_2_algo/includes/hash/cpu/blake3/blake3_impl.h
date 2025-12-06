#ifndef BLAKE3_IMPL_H
#define BLAKE3_IMPL_H
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "blake3.h"

#ifdef __cplusplus
extern "C" {
#endif

// Internal flags
enum blake3_flags {
    CHUNK_START = 1 << 0,
    CHUNK_END = 1 << 1,
    PARENT = 1 << 2,
    ROOT = 1 << 3,
    KEYED_HASH = 1 << 4,
    DERIVE_KEY_CONTEXT = 1 << 5,
    DERIVE_KEY_MATERIAL = 1 << 6,
};

// Inline macro
#if defined(_MSC_VER)
#define INLINE static __forceinline
#else
#define INLINE static inline __attribute__((always_inline))
#endif

// Platform detection
#if (defined(__x86_64__) || defined(_M_X64)) && !defined(_M_ARM64EC)
#define IS_X86
#define IS_X86_64
#endif
#if (defined(__i386__) || defined(_M_IX86))
#define IS_X86
#define IS_X86_32
#endif
#if defined(__aarch64__) || defined(_M_ARM64) || defined(_M_ARM64EC)
#define IS_AARCH64
#endif

#define MAX_SIMD_DEGREE 1
#define MAX_SIMD_DEGREE_OR_2 2

// IV constant
static const uint32_t IV[8] = {
    0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
    0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL,
};

// Utility functions
INLINE uint32_t rotr32(uint32_t w, uint32_t c) {
    return (w >> c) | (w << (32 - c));
}

INLINE uint32_t counter_low(uint64_t counter) {
    return (uint32_t)counter;
}

INLINE uint32_t counter_high(uint64_t counter) {
    return (uint32_t)(counter >> 32);
}

INLINE uint32_t load32(const void *src) {
    const uint8_t *p = (const uint8_t *)src;
    return ((uint32_t)(p[0]) << 0) | ((uint32_t)(p[1]) << 8) |
           ((uint32_t)(p[2]) << 16) | ((uint32_t)(p[3]) << 24);
}

INLINE void load_key_words(const uint8_t key[BLAKE3_KEY_LEN], uint32_t key_words[8]) {
    for (int i = 0; i < 8; i++) {
        key_words[i] = load32(&key[i * 4]);
    }
}

INLINE void load_block_words(const uint8_t block[BLAKE3_BLOCK_LEN], uint32_t block_words[16]) {
    for (int i = 0; i < 16; i++) {
        block_words[i] = load32(&block[i * 4]);
    }
}

INLINE void store32(void *dst, uint32_t w) {
    uint8_t *p = (uint8_t *)dst;
    p[0] = (uint8_t)(w >> 0);
    p[1] = (uint8_t)(w >> 8);
    p[2] = (uint8_t)(w >> 16);
    p[3] = (uint8_t)(w >> 24);
}

INLINE void store_cv_words(uint8_t bytes_out[32], const uint32_t cv_words[8]) {
    for (int i = 0; i < 8; i++) {
        store32(&bytes_out[i * 4], cv_words[i]);
    }
}

INLINE unsigned int popcnt(uint64_t x) {
#if defined(_MSC_VER) && defined(IS_X86_64)
    return (unsigned int)__popcnt64(x);
#elif defined(__GNUC__) || defined(__clang__)
    return (unsigned int)__builtin_popcountll(x);
#else
    unsigned int count = 0;
    while (x) {
        count += x & 1;
        x >>= 1;
    }
    return count;
#endif
}

INLINE unsigned int highest_one(uint64_t x) {
#if defined(_MSC_VER) && defined(IS_X86_64)
    unsigned long index;
    _BitScanReverse64(&index, x);
    return (unsigned int)index;
#elif defined(__GNUC__) || defined(__clang__)
    return 63 - __builtin_clzll(x);
#else
    unsigned int c = 0;
    if (x == 0) return 0;
    while ((x >>= 1) != 0) c++;
    return c;
#endif
}

INLINE uint64_t round_down_to_power_of_2(uint64_t x) {
    return 1ULL << highest_one(x);
}

// Internal function declarations
void blake3_compress_in_place(uint32_t cv[8], const uint8_t block[BLAKE3_BLOCK_LEN],
                               uint8_t block_len, uint64_t counter, uint8_t flags);
void blake3_compress_xof(const uint32_t cv[8], const uint8_t block[BLAKE3_BLOCK_LEN],
                          uint8_t block_len, uint64_t counter, uint8_t flags, uint8_t out[64]);
void blake3_hash_many(const uint8_t *const *inputs, size_t num_inputs, size_t blocks,
                       const uint32_t key[8], uint64_t counter, bool increment_counter,
                       uint8_t flags, uint8_t flags_start, uint8_t flags_end, uint8_t *out);
size_t blake3_simd_degree(void);
size_t blake3_compress_subtree_wide(const uint8_t *input, size_t input_len,
                                     const uint32_t key[8], uint64_t chunk_counter,
                                     uint8_t flags, uint8_t *out, bool use_tbb);

#ifdef __cplusplus
}
#endif

#endif /* BLAKE3_IMPL_H */
