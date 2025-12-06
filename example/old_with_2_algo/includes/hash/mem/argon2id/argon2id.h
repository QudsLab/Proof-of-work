#ifndef ARGON2ID_H
#define ARGON2ID_H

#include <stdint.h>
#include <stddef.h>

/* Argon2 return codes */
#define ARGON2_OK 0
#define ARGON2_MEMORY_ALLOCATION_ERROR -1
#define ARGON2_INVALID_PARAMS -2
#define ARGON2_ENCODING_FAIL -3

/* Argon2 parameters structure */
typedef struct {
    uint32_t t_cost;      /* Number of iterations */
    uint32_t m_cost;      /* Memory size in KiB */
    uint32_t parallelism; /* Number of parallel threads */
    uint32_t hash_len;    /* Desired hash length in bytes */
    uint32_t salt_len;    /* Salt length in bytes */
} argon2_params;

/* Default parameters (OWASP recommendations) */
#define ARGON2_DEFAULT_T_COST 3
#define ARGON2_DEFAULT_M_COST 65536  /* 64 MiB in KiB */
#define ARGON2_DEFAULT_PARALLELISM 4
#define ARGON2_DEFAULT_HASH_LEN 32
#define ARGON2_DEFAULT_SALT_LEN 16

/* Note: m_cost is in KiB (kibibytes). For CLI compatibility:
 * If using argon2 CLI with -m N, that means 2^N KiB
 * So CLI "-m 16" = 2^16 KiB = 65536 KiB = 64 MiB
 * Use params->m_cost = 65536 for that setting */

/* Minimum and maximum values */
#define ARGON2_MIN_T_COST 1
#define ARGON2_MIN_M_COST 8
#define ARGON2_MIN_PARALLELISM 1
#define ARGON2_MIN_HASH_LEN 4
#define ARGON2_MIN_SALT_LEN 8

#define ARGON2_MAX_T_COST 0xFFFFFFFF
#define ARGON2_MAX_M_COST 0xFFFFFFFF
#define ARGON2_MAX_PARALLELISM 0xFFFFFF
#define ARGON2_MAX_HASH_LEN 0xFFFFFFFF
#define ARGON2_MAX_SALT_LEN 0xFFFFFFFF

/**
 * Hash a password using Argon2id
 * 
 * @param pwd Password to hash
 * @param pwd_len Password length
 * @param salt Salt bytes
 * @param salt_len Salt length
 * @param params Argon2 parameters
 * @param out Output buffer for hash
 * @param out_len Length of output buffer
 * @return ARGON2_OK on success, error code otherwise
 */
int argon2id_hash(const void *pwd, size_t pwd_len,
                  const void *salt, size_t salt_len,
                  const argon2_params *params,
                  void *out, size_t out_len);

/**
 * Verify a password against an Argon2id hash
 * 
 * @param pwd Password to verify
 * @param pwd_len Password length
 * @param salt Salt bytes used in original hash
 * @param salt_len Salt length
 * @param params Argon2 parameters used in original hash
 * @param hash Hash to verify against
 * @param hash_len Hash length
 * @return ARGON2_OK if password matches, error code otherwise
 */
int argon2id_verify(const void *pwd, size_t pwd_len,
                    const void *salt, size_t salt_len,
                    const argon2_params *params,
                    const void *hash, size_t hash_len);

/**
 * Encode Argon2id hash to string format
 * 
 * @param out Output string buffer
 * @param out_len Length of output buffer
 * @param params Argon2 parameters
 * @param salt Salt bytes
 * @param salt_len Salt length
 * @param hash Hash bytes
 * @param hash_len Hash length
 * @return ARGON2_OK on success, error code otherwise
 */
int argon2id_encode_string(char *out, size_t out_len,
                           const argon2_params *params,
                           const void *salt, size_t salt_len,
                           const void *hash, size_t hash_len);

/**
 * Initialize parameters with default values
 * 
 * @param params Parameters structure to initialize
 */
void argon2_params_init(argon2_params *params);

#endif /* ARGON2ID_H */