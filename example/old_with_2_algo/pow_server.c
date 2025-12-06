#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "export.h"
#include "sha256.h"
#include "blake3.h"

int has_leading_zeros(uint8_t hash[32], int difficulty) {
    int zeros = 0;
    for (int i = 0; i < 32; i++) {
        for (int bit = 7; bit >= 0; bit--) {
            if ((hash[i] >> bit) & 1) return zeros >= difficulty;
            zeros++;
            if (zeros >= difficulty) return 1;
        }
    }
    return zeros >= difficulty;
}

// Verify PoW using SHA256 only
EXPORT int verify_pow_sha256(const char *input, int nonce, int difficulty) {
    char combined[4096];
    uint8_t hash[32];
    size_t len = strlen(input);
    memcpy(combined, input, len);
    int n = snprintf(combined + len, sizeof(combined) - len, "%d", nonce);
    
    sha256((uint8_t*)combined, len + n, hash);
    return has_leading_zeros(hash, difficulty);
}

// Verify PoW using BLAKE3 only
EXPORT int verify_pow_blake3(const char *input, int nonce, int difficulty) {
    char combined[4096];
    uint8_t hash[32];
    size_t len = strlen(input);
    memcpy(combined, input, len);
    int n = snprintf(combined + len, sizeof(combined) - len, "%d", nonce);
    
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, combined, len + n);
    blake3_hasher_finalize(&hasher, hash, 32);
    
    return has_leading_zeros(hash, difficulty);
}

// Verify PoW using BOTH SHA256 and BLAKE3 (combined - both must pass)
EXPORT int verify_pow_combined(const char *input, int nonce, int difficulty) {
    char combined[4096];
    uint8_t hash_sha256[32];
    uint8_t hash_blake3[32];
    size_t len = strlen(input);
    memcpy(combined, input, len);
    int n = snprintf(combined + len, sizeof(combined) - len, "%d", nonce);
    
    // Compute SHA256 hash
    sha256((uint8_t*)combined, len + n, hash_sha256);
    
    // Compute BLAKE3 hash
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, combined, len + n);
    blake3_hasher_finalize(&hasher, hash_blake3, 32);
    
    // Both hashes must meet difficulty
    return has_leading_zeros(hash_sha256, difficulty) && has_leading_zeros(hash_blake3, difficulty);
}

// Backward compatibility alias (defaults to combined)
EXPORT int verify_pow(const char *input, int nonce, int difficulty) {
    return verify_pow_combined(input, nonce, difficulty);
}
