#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "export.h"
#include "sha256.h"
#include "blake3.h"

// Hash-based PoW output structure
typedef struct {
    int nonce;
    uint8_t hash_sha256[32];
    uint8_t hash_blake3[32];
} PoWResult;

// Check leading zeros
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

// Generate PoW using SHA256 only
EXPORT PoWResult generate_pow_sha256(const char *input, int difficulty, int min_nonce, int max_nonce) {
    PoWResult result;
    result.nonce = -1;
    memset(result.hash_sha256, 0, 32);
    memset(result.hash_blake3, 0, 32);
    uint8_t hash[32];
    char combined[4096];
    size_t len = strlen(input);
    memcpy(combined, input, len);
    for (int nonce = min_nonce; nonce <= max_nonce; nonce++) {
        int n = snprintf(combined + len, sizeof(combined) - len, "%d", nonce);
        sha256((uint8_t*)combined, len + n, hash);
        if (has_leading_zeros(hash, difficulty)) {
            result.nonce = nonce;
            memcpy(result.hash_sha256, hash, 32);
            break;
        }
    }
    return result;
}

// Generate PoW using BLAKE3 only
EXPORT PoWResult generate_pow_blake3(const char *input, int difficulty, int min_nonce, int max_nonce) {
    PoWResult result;
    result.nonce = -1;
    memset(result.hash_sha256, 0, 32);
    memset(result.hash_blake3, 0, 32);
    uint8_t hash[32];
    char combined[4096];
    size_t len = strlen(input);
    memcpy(combined, input, len);
    
    for (int nonce = min_nonce; nonce <= max_nonce; nonce++) {
        int n = snprintf(combined + len, sizeof(combined) - len, "%d", nonce);
        
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, combined, len + n);
        blake3_hasher_finalize(&hasher, hash, 32);
        
        if (has_leading_zeros(hash, difficulty)) {
            result.nonce = nonce;
            memcpy(result.hash_blake3, hash, 32);
            break;
        }
    }
    return result;
}

// Generate PoW using BOTH SHA256 and BLAKE3 (combined - both must pass)
EXPORT PoWResult generate_pow_combined(const char *input, int difficulty, int min_nonce, int max_nonce) {
    PoWResult result;
    result.nonce = -1;
    memset(result.hash_sha256, 0, 32);
    memset(result.hash_blake3, 0, 32);
    uint8_t hash_sha256[32];
    uint8_t hash_blake3[32];
    char combined[4096];
    size_t len = strlen(input);
    memcpy(combined, input, len);
    
    for (int nonce = min_nonce; nonce <= max_nonce; nonce++) {
        int n = snprintf(combined + len, sizeof(combined) - len, "%d", nonce);
        
        // Compute SHA256 hash
        sha256((uint8_t*)combined, len + n, hash_sha256);
        
        // Compute BLAKE3 hash
        blake3_hasher hasher;
        blake3_hasher_init(&hasher);
        blake3_hasher_update(&hasher, combined, len + n);
        blake3_hasher_finalize(&hasher, hash_blake3, 32);
        
        // Check if BOTH hashes meet difficulty
        if (has_leading_zeros(hash_sha256, difficulty) && has_leading_zeros(hash_blake3, difficulty)) {
            result.nonce = nonce;
            memcpy(result.hash_sha256, hash_sha256, 32);
            memcpy(result.hash_blake3, hash_blake3, 32);
            break;
        }
    }
    return result;
}

// Backward compatibility alias (defaults to combined)
EXPORT PoWResult generate_pow(const char *input, int difficulty, int min_nonce, int max_nonce) {
    return generate_pow_combined(input, difficulty, min_nonce, max_nonce);
}
