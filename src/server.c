#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "export.h"

// Include all hash headers
#include "crypto/md2/md2.h"
#include "crypto/md4/md4.h"
#include "crypto/md5/md5.h"
#include "crypto/sha0/sha0.h"
#include "crypto/sha1/sha1.h"
#include "crypto/sha224/sha224.h"
#include "crypto/sha256/sha256.h"
#include "crypto/sha512/sha512.h"
#include "crypto/sha3/sha3.h"
#include "crypto/sha3_224/sha3_224.h"
#include "crypto/sha3_384/sha3_384.h"
#include "crypto/keccak/keccak.h"
#include "crypto/shake/shake.h"
#include "crypto/ripemd/ripemd160.h"
#include "crypto/ripemd128/ripemd128.h"
#include "crypto/ripemd256/ripemd256.h"
#include "crypto/ripemd320/ripemd320.h"
#include "crypto/blake2b/blake2b.h"
#include "crypto/blake2s/blake2s.h"
#include "crypto/whirlpool/whirlpool.h"
#include "crypto/has160/has160.h"
#include "crypto/nt/nt.h"

// Hash algorithm enumeration (must match client)
typedef enum {
    HASH_MD4, HASH_NT, HASH_MD5, HASH_HAS160,
    HASH_RIPEMD256, HASH_RIPEMD128,
    HASH_BLAKE2S_128, HASH_BLAKE2S_160, HASH_BLAKE2S_256,
    HASH_BLAKE2B_512, HASH_RIPEMD320,
    HASH_BLAKE2B_128, HASH_BLAKE2B_384, HASH_RIPEMD160,
    HASH_BLAKE2B_160, HASH_BLAKE2B_256,
    HASH_SHA256, HASH_SHA0, HASH_SHA1, HASH_SHA224,
    HASH_SHA512, HASH_SHA384,
    HASH_WHIRLPOOL,
    HASH_SHA3_224, HASH_SHAKE256, HASH_SHA3_384,
    HASH_SHAKE128, HASH_KECCAK384, HASH_KECCAK256,
    HASH_SHA3_256, HASH_SHA3_512, HASH_KECCAK512, HASH_KECCAK224,
    HASH_MD2,
    HASH_COUNT
} HashAlgorithm;

// Compute hash based on algorithm
void compute_hash(HashAlgorithm algo, const uint8_t *data, size_t len, uint8_t *digest, int *digest_size) {
    memset(digest, 0, 128);
    
    switch(algo) {
        case HASH_MD2: 
            md2_hash(data, len, digest); 
            *digest_size = 16;
            break;
        case HASH_MD4: 
            md4_hash(data, len, digest); 
            *digest_size = 16;
            break;
        case HASH_MD5: 
            md5_hash(data, len, digest); 
            *digest_size = 16;
            break;
        case HASH_SHA0: 
            sha0_hash(data, len, digest); 
            *digest_size = 20;
            break;
        case HASH_SHA1: 
            sha1_hash(data, len, digest); 
            *digest_size = 20;
            break;
        case HASH_SHA224: 
            sha224_hash(data, len, digest); 
            *digest_size = 28;
            break;
        case HASH_SHA256: 
            sha256(data, len, digest); 
            *digest_size = 32;
            break;
        case HASH_SHA384: 
            sha384_hash(data, len, digest); 
            *digest_size = 48;
            break;
        case HASH_SHA512: 
            sha512_hash(data, len, digest); 
            *digest_size = 64;
            break;
        case HASH_SHA3_224: 
            sha3_224_hash(data, len, digest); 
            *digest_size = 28;
            break;
        case HASH_SHA3_256: 
            sha3_256_hash(data, len, digest); 
            *digest_size = 32;
            break;
        case HASH_SHA3_384: 
            sha3_384_hash(data, len, digest); 
            *digest_size = 48;
            break;
        case HASH_SHA3_512: 
            sha3_512_hash(data, len, digest); 
            *digest_size = 64;
            break;
        case HASH_KECCAK224: 
            keccak_224_hash(data, len, digest); 
            *digest_size = 28;
            break;
        case HASH_KECCAK256: 
            keccak_256_hash(data, len, digest); 
            *digest_size = 32;
            break;
        case HASH_KECCAK384: 
            keccak_384_hash(data, len, digest); 
            *digest_size = 48;
            break;
        case HASH_KECCAK512: 
            keccak_512_hash(data, len, digest); 
            *digest_size = 64;
            break;
        case HASH_SHAKE128: 
            shake128_hash(data, len, digest, 32); 
            *digest_size = 32;
            break;
        case HASH_SHAKE256: 
            shake256_hash(data, len, digest, 64); 
            *digest_size = 64;
            break;
        case HASH_RIPEMD128: 
            ripemd128_hash(data, len, digest); 
            *digest_size = 16;
            break;
        case HASH_RIPEMD160: 
            ripemd160_hash(data, len, digest); 
            *digest_size = 20;
            break;
        case HASH_RIPEMD256: 
            ripemd256_hash(data, len, digest); 
            *digest_size = 32;
            break;
        case HASH_RIPEMD320: 
            ripemd320_hash(data, len, digest); 
            *digest_size = 40;
            break;
        case HASH_BLAKE2B_128: 
            blake2b_128_hash(data, len, digest); 
            *digest_size = 16;
            break;
        case HASH_BLAKE2B_160: 
            blake2b_160_hash(data, len, digest); 
            *digest_size = 20;
            break;
        case HASH_BLAKE2B_256: 
            blake2b_256_hash(data, len, digest); 
            *digest_size = 32;
            break;
        case HASH_BLAKE2B_384: 
            blake2b_384_hash(data, len, digest); 
            *digest_size = 48;
            break;
        case HASH_BLAKE2B_512: 
            blake2b_512_hash(data, len, digest); 
            *digest_size = 64;
            break;
        case HASH_BLAKE2S_128: 
            blake2s_128_hash(data, len, digest); 
            *digest_size = 16;
            break;
        case HASH_BLAKE2S_160: 
            blake2s_160_hash(data, len, digest); 
            *digest_size = 20;
            break;
        case HASH_BLAKE2S_256: 
            blake2s_256_hash(data, len, digest); 
            *digest_size = 32;
            break;
        case HASH_WHIRLPOOL: 
            whirlpool_hash(data, len, digest); 
            *digest_size = 64;
            break;
        case HASH_HAS160: 
            has160_hash(data, len, digest); 
            *digest_size = 20;
            break;
        case HASH_NT: 
            nt_hash((const char *)data, digest); 
            *digest_size = 16;
            break;
        default: 
            *digest_size = 0;
            break;
    }
}

// Check leading zeros
int has_leading_zeros(uint8_t *hash, int hash_size, int difficulty) {
    int zeros = 0;
    for (int i = 0; i < hash_size; i++) {
        for (int bit = 7; bit >= 0; bit--) {
            if ((hash[i] >> bit) & 1) return zeros >= difficulty;
            zeros++;
            if (zeros >= difficulty) return 1;
        }
    }
    return zeros >= difficulty;
}

// Verify PoW for a single hash algorithm
EXPORT int verify_pow_single(const char *input, int nonce, HashAlgorithm algo, int difficulty) {
    char combined[4096];
    uint8_t hash[128];
    int hash_size;
    size_t len = strlen(input);
    memcpy(combined, input, len);
    int n = snprintf(combined + len, sizeof(combined) - len, "%d", nonce);
    
    compute_hash(algo, (uint8_t*)combined, len + n, hash, &hash_size);
    return has_leading_zeros(hash, hash_size, difficulty);
}

// Verify PoW for multiple hash algorithms (all must pass)
EXPORT int verify_pow_multi(const char *input, int nonce, HashAlgorithm *algos, int num_algos, int difficulty) {
    char combined[4096];
    size_t len = strlen(input);
    memcpy(combined, input, len);
    int n = snprintf(combined + len, sizeof(combined) - len, "%d", nonce);
    
    if (num_algos > 10) num_algos = 10;
    
    for (int i = 0; i < num_algos; i++) {
        uint8_t hash[128];
        int hash_size;
        compute_hash(algos[i], (uint8_t*)combined, len + n, hash, &hash_size);
        
        if (!has_leading_zeros(hash, hash_size, difficulty)) {
            return 0; // One failed, all must pass
        }
    }
    
    return 1; // All passed
}

// Get hash algorithm by name
EXPORT int get_hash_algo_by_name(const char *name) {
    if (strcmp(name, "MD4") == 0) return HASH_MD4;
    if (strcmp(name, "NT") == 0) return HASH_NT;
    if (strcmp(name, "MD5") == 0) return HASH_MD5;
    if (strcmp(name, "HAS-160") == 0) return HASH_HAS160;
    if (strcmp(name, "RIPEMD-256") == 0) return HASH_RIPEMD256;
    if (strcmp(name, "RIPEMD-128") == 0) return HASH_RIPEMD128;
    if (strcmp(name, "BLAKE2s-128") == 0) return HASH_BLAKE2S_128;
    if (strcmp(name, "BLAKE2s-160") == 0) return HASH_BLAKE2S_160;
    if (strcmp(name, "BLAKE2s-256") == 0) return HASH_BLAKE2S_256;
    if (strcmp(name, "BLAKE2b-512") == 0) return HASH_BLAKE2B_512;
    if (strcmp(name, "RIPEMD-320") == 0) return HASH_RIPEMD320;
    if (strcmp(name, "BLAKE2b-128") == 0) return HASH_BLAKE2B_128;
    if (strcmp(name, "BLAKE2b-384") == 0) return HASH_BLAKE2B_384;
    if (strcmp(name, "RIPEMD-160") == 0) return HASH_RIPEMD160;
    if (strcmp(name, "BLAKE2b-160") == 0) return HASH_BLAKE2B_160;
    if (strcmp(name, "BLAKE2b-256") == 0) return HASH_BLAKE2B_256;
    if (strcmp(name, "SHA2-256") == 0 || strcmp(name, "SHA256") == 0) return HASH_SHA256;
    if (strcmp(name, "SHA-0") == 0) return HASH_SHA0;
    if (strcmp(name, "SHA-1") == 0 || strcmp(name, "SHA1") == 0) return HASH_SHA1;
    if (strcmp(name, "SHA2-224") == 0) return HASH_SHA224;
    if (strcmp(name, "SHA2-512") == 0) return HASH_SHA512;
    if (strcmp(name, "SHA2-384") == 0) return HASH_SHA384;
    if (strcmp(name, "Whirlpool") == 0) return HASH_WHIRLPOOL;
    if (strcmp(name, "SHA3-224") == 0) return HASH_SHA3_224;
    if (strcmp(name, "SHAKE-256") == 0) return HASH_SHAKE256;
    if (strcmp(name, "SHA3-384") == 0) return HASH_SHA3_384;
    if (strcmp(name, "SHAKE-128") == 0) return HASH_SHAKE128;
    if (strcmp(name, "Keccak-384") == 0) return HASH_KECCAK384;
    if (strcmp(name, "Keccak-256") == 0) return HASH_KECCAK256;
    if (strcmp(name, "SHA3-256") == 0) return HASH_SHA3_256;
    if (strcmp(name, "SHA3-512") == 0) return HASH_SHA3_512;
    if (strcmp(name, "Keccak-512") == 0) return HASH_KECCAK512;
    if (strcmp(name, "Keccak-224") == 0) return HASH_KECCAK224;
    if (strcmp(name, "MD2") == 0) return HASH_MD2;
    return -1;
}
