#ifndef SHA256_H
#define SHA256_H
#include <stdint.h>
#include <stddef.h>
#define SHA256_BLOCK_SIZE 32
typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
    uint32_t state[8];
} SHA256_CTX;
// Standard API
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t hash[]);
void sha256(const uint8_t data[], size_t len, uint8_t hash[]);
// Fast POW-optimized functions
void sha256_transform_fast(uint32_t state[8], const uint8_t data[64]);
void sha256_double_hash(const uint8_t data[], size_t len, uint8_t hash[]);
void sha256_init_state(uint32_t state[8]);
// Midstate optimization for POW (when prefix doesn't change)
void sha256_midstate(SHA256_CTX *ctx, const uint8_t data[], size_t len);
void sha256_final_from_midstate(SHA256_CTX *ctx, const uint8_t remaining[], size_t len, uint8_t hash[]);
#endif // SHA256_H