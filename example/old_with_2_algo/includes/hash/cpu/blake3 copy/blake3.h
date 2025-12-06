#ifndef BLAKE3_IMPL_H
#define BLAKE3_IMPL_H
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "blake3.h"
#ifdef __cplusplus
extern "C"
{
#endif
    // Internal flags
    enum blake3_flags
    {
        CHUNK_START = 1 << 0,
        CHUNK_END = 1 << 1,
        PARENT = 1 << 2,
        ROOT = 1 << 3,
        KEYED_HASH = 1 << 4,
        DERIVE_KEY_CONTEXT = 1 << 5,
        DERIVE_KEY_MATERIAL = 1 << 6,
    };
// Inline macro for different compilers
#if defined(_MSC_VER)
#define INLINE static __forceinline
#else
#define INLINE static inline __attribute__((always_inline))
#endif
#ifdef __cplusplus
#define NOEXCEPT noexcept
#else
#define NOEXCEPT
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
#if defined(IS_X86)
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#if !defined(_MSC_VER) && !defined(__APPLE__) && !defined(__ANDROID__)
#include <cpuid.h>
#endif
#endif
#if !defined(BLAKE3_USE_NEON)
#if defined(IS_AARCH64) && !(defined(__ARM_NEON) || defined(__ARM_NEON__) || defined(__ARM_NEON_FP))
#define BLAKE3_USE_NEON 0
#else
#define BLAKE3_USE_NEON 1
#endif
#endif
#if !defined(BLAKE3_NO_SSE2) && !defined(BLAKE3_NO_SSE41) && !defined(BLAKE3_NO_AVX2) && !defined(BLAKE3_NO_AVX512)
#if defined(IS_X86)
#define MAX_SIMD_DEGREE 16
#elif defined(BLAKE3_USE_NEON) && BLAKE3_USE_NEON
#define MAX_SIMD_DEGREE 4
#else
#define MAX_SIMD_DEGREE 1
#endif
#else
#define MAX_SIMD_DEGREE 1
#endif
// Always at least 2 for the minimal tree
#define MAX_SIMD_DEGREE_OR_2 (MAX_SIMD_DEGREE > 2 ? MAX_SIMD_DEGREE : 2)
    // Portable implementations
    INLINE uint32_t rotr32(uint32_t w, uint32_t c)
    {
        return (w >> c) | (w << (32 - c));
    }
    // Utility functions
    INLINE uint32_t counter_low(uint64_t counter)
    {
        return (uint32_t)counter;
    }
    INLINE uint32_t counter_high(uint64_t counter)
    {
        return (uint32_t)(counter >> 32);
    }
    INLINE uint32_t load32(const void *src)
    {
        const uint8_t *p = (const uint8_t *)src;
        return ((uint32_t)(p[0]) << 0) |
                ((uint32_t)(p[1]) << 8) |
                ((uint32_t)(p[2]) << 16) |
                ((uint32_t)(p[3]) << 24);
    }
    INLINE void load_key_words(const uint8_t key[BLAKE3_KEY_LEN],
                                uint32_t key_words[8])
    {
        key_words[0] = load32(&key[0 * 4]);
        key_words[1] = load32(&key[1 * 4]);
        key_words[2] = load32(&key[2 * 4]);
        key_words[3] = load32(&key[3 * 4]);
        key_words[4] = load32(&key[4 * 4]);
        key_words[5] = load32(&key[5 * 4]);
        key_words[6] = load32(&key[6 * 4]);
        key_words[7] = load32(&key[7 * 4]);
    }
    INLINE void load_block_words(const uint8_t block[BLAKE3_BLOCK_LEN],
                                uint32_t block_words[16])
    {
        block_words[0] = load32(&block[0 * 4]);
        block_words[1] = load32(&block[1 * 4]);
        block_words[2] = load32(&block[2 * 4]);
        block_words[3] = load32(&block[3 * 4]);
        block_words[4] = load32(&block[4 * 4]);
        block_words[5] = load32(&block[5 * 4]);
        block_words[6] = load32(&block[6 * 4]);
        block_words[7] = load32(&block[7 * 4]);
        block_words[8] = load32(&block[8 * 4]);
        block_words[9] = load32(&block[9 * 4]);
        block_words[10] = load32(&block[10 * 4]);
        block_words[11] = load32(&block[11 * 4]);
        block_words[12] = load32(&block[12 * 4]);
        block_words[13] = load32(&block[13 * 4]);
        block_words[14] = load32(&block[14 * 4]);
        block_words[15] = load32(&block[15 * 4]);
    }
    INLINE void store32(void *dst, uint32_t w)
    {
        uint8_t *p = (uint8_t *)dst;
        p[0] = (uint8_t)(w >> 0);
        p[1] = (uint8_t)(w >> 8);
        p[2] = (uint8_t)(w >> 16);
        p[3] = (uint8_t)(w >> 24);
    }
    INLINE void store_cv_words(uint8_t bytes_out[32], const uint32_t cv_words[8])
    {
        store32(&bytes_out[0 * 4], cv_words[0]);
        store32(&bytes_out[1 * 4], cv_words[1]);
        store32(&bytes_out[2 * 4], cv_words[2]);
        store32(&bytes_out[3 * 4], cv_words[3]);
        store32(&bytes_out[4 * 4], cv_words[4]);
        store32(&bytes_out[5 * 4], cv_words[5]);
        store32(&bytes_out[6 * 4], cv_words[6]);
        store32(&bytes_out[7 * 4], cv_words[7]);
    }
    // Portable popcnt implementation
    INLINE unsigned int popcnt(uint64_t x)
    {
#if defined(_MSC_VER) && defined(IS_X86_64)
        return (unsigned int)__popcnt64(x);
#elif defined(__GNUC__) || defined(__clang__)
    return (unsigned int)__builtin_popcountll(x);
#else
    // Fallback
    unsigned int count = 0;
    while (x)
    {
        count += x & 1;
        x >>= 1;
    }
    return count;
#endif
    }
    // Portable count_trailing_zeros
    INLINE unsigned int highest_one(uint64_t x)
    {
#if defined(_MSC_VER) && defined(IS_X86_64)
        unsigned long index;
        _BitScanReverse64(&index, x);
        return (unsigned int)index;
#elif defined(__GNUC__) || defined(__clang__)
    return 63 - __builtin_clzll(x);
#else
    unsigned int c = 0;
    if (x == 0)
        return 0;
    while ((x >>= 1) != 0)
        c++;
    return c;
#endif
    }
    INLINE uint64_t round_down_to_power_of_2(uint64_t x)
    {
        return 1ULL << highest_one(x);
    }
    // Function declarations
    void blake3_compress_in_place(uint32_t cv[8],
                                    const uint8_t block[BLAKE3_BLOCK_LEN],
                                    uint8_t block_len, uint64_t counter,
                                    uint8_t flags);
    void blake3_compress_xof(const uint32_t cv[8],
                                const uint8_t block[BLAKE3_BLOCK_LEN],
                                uint8_t block_len, uint64_t counter,
                                uint8_t flags, uint8_t out[64]);
    void blake3_hash_many(const uint8_t *const *inputs, size_t num_inputs,
                            size_t blocks, const uint32_t key[8], uint64_t counter,
                            bool increment_counter, uint8_t flags,
                            uint8_t flags_start, uint8_t flags_end, uint8_t *out);
    size_t blake3_simd_degree(void);
    // Platform-specific implementations
    void blake3_compress_in_place_portable(uint32_t cv[8],
                                            const uint8_t block[BLAKE3_BLOCK_LEN],
                                            uint8_t block_len, uint64_t counter,
                                            uint8_t flags);
    void blake3_compress_xof_portable(const uint32_t cv[8],
                                        const uint8_t block[BLAKE3_BLOCK_LEN],
                                        uint8_t block_len, uint64_t counter,
                                        uint8_t flags, uint8_t out[64]);
    void blake3_hash_many_portable(const uint8_t *const *inputs, size_t num_inputs,
                                    size_t blocks, const uint32_t key[8],
                                    uint64_t counter, bool increment_counter,
                                    uint8_t flags, uint8_t flags_start,
                                    uint8_t flags_end, uint8_t *out);
#if defined(IS_X86)
#if !defined(BLAKE3_NO_SSE2)
    void blake3_compress_in_place_sse2(uint32_t cv[8],
                                        const uint8_t block[BLAKE3_BLOCK_LEN],
                                        uint8_t block_len, uint64_t counter,
                                        uint8_t flags);
    void blake3_compress_xof_sse2(const uint32_t cv[8],
                                    const uint8_t block[BLAKE3_BLOCK_LEN],
                                    uint8_t block_len, uint64_t counter,
                                    uint8_t flags, uint8_t out[64]);
    void blake3_hash_many_sse2(const uint8_t *const *inputs, size_t num_inputs,
                                size_t blocks, const uint32_t key[8],
                                uint64_t counter, bool increment_counter,
                                uint8_t flags, uint8_t flags_start,
                                uint8_t flags_end, uint8_t *out);
#endif
#if !defined(BLAKE3_NO_SSE41)
    void blake3_compress_in_place_sse41(uint32_t cv[8],
                                        const uint8_t block[BLAKE3_BLOCK_LEN],
                                        uint8_t block_len, uint64_t counter,
                                        uint8_t flags);
    void blake3_compress_xof_sse41(const uint32_t cv[8],
                                    const uint8_t block[BLAKE3_BLOCK_LEN],
                                    uint8_t block_len, uint64_t counter,
                                    uint8_t flags, uint8_t out[64]);
    void blake3_hash_many_sse41(const uint8_t *const *inputs, size_t num_inputs,
                                size_t blocks, const uint32_t key[8],
                                uint64_t counter, bool increment_counter,
                                uint8_t flags, uint8_t flags_start,
                                uint8_t flags_end, uint8_t *out);
#endif
#if !defined(BLAKE3_NO_AVX2)
    void blake3_hash_many_avx2(const uint8_t *const *inputs, size_t num_inputs,
                                size_t blocks, const uint32_t key[8],
                                uint64_t counter, bool increment_counter,
                                uint8_t flags, uint8_t flags_start,
                                uint8_t flags_end, uint8_t *out);
#endif
#if !defined(BLAKE3_NO_AVX512)
    void blake3_compress_in_place_avx512(uint32_t cv[8],
                                        const uint8_t block[BLAKE3_BLOCK_LEN],
                                        uint8_t block_len, uint64_t counter,
                                        uint8_t flags);
    void blake3_compress_xof_avx512(const uint32_t cv[8],
                                    const uint8_t block[BLAKE3_BLOCK_LEN],
                                    uint8_t block_len, uint64_t counter,
                                    uint8_t flags, uint8_t out[64]);
    void blake3_hash_many_avx512(const uint8_t *const *inputs, size_t num_inputs,
                                    size_t blocks, const uint32_t key[8],
                                    uint64_t counter, bool increment_counter,
                                    uint8_t flags, uint8_t flags_start,
                                    uint8_t flags_end, uint8_t *out);
#endif
#endif // IS_X86
#if defined(IS_AARCH64) && defined(BLAKE3_USE_NEON) && BLAKE3_USE_NEON
    void blake3_hash_many_neon(const uint8_t *const *inputs, size_t num_inputs,
                                size_t blocks, const uint32_t key[8],
                                uint64_t counter, bool increment_counter,
                                uint8_t flags, uint8_t flags_start,
                                uint8_t flags_end, uint8_t *out);
#endif
#ifdef __cplusplus
}
#endif
#endif // BLAKE3_IMPL_H