#ifndef BLAKE3_H
#define BLAKE3_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BLAKE3_VERSION_STRING "1.5.0"
#define BLAKE3_KEY_LEN 32
#define BLAKE3_OUT_LEN 32
#define BLAKE3_BLOCK_LEN 64
#define BLAKE3_CHUNK_LEN 1024
#define BLAKE3_MAX_DEPTH 54

// Internal chunk state
typedef struct {
  uint32_t cv[8];
  uint64_t chunk_counter;
  uint8_t buf[BLAKE3_BLOCK_LEN];
  uint8_t buf_len;
  uint8_t blocks_compressed;
  uint8_t flags;
} blake3_chunk_state;

// Main hasher context
typedef struct {
  uint32_t key[8];
  blake3_chunk_state chunk;
  uint8_t cv_stack[(BLAKE3_MAX_DEPTH + 1) * BLAKE3_OUT_LEN];
  uint8_t cv_stack_len;
} blake3_hasher;

// Public API
const char *llvm_blake3_version(void);

void llvm_blake3_hasher_init(blake3_hasher *self);
void llvm_blake3_hasher_init_keyed(blake3_hasher *self,
                                   const uint8_t key[BLAKE3_KEY_LEN]);
void llvm_blake3_hasher_init_derive_key(blake3_hasher *self,
                                        const char *context);
void llvm_blake3_hasher_init_derive_key_raw(blake3_hasher *self,
                                            const void *context,
                                            size_t context_len);

void llvm_blake3_hasher_update(blake3_hasher *self, const void *input,
                               size_t input_len);

void llvm_blake3_hasher_finalize(const blake3_hasher *self, uint8_t *out,
                                 size_t out_len);
void llvm_blake3_hasher_finalize_seek(const blake3_hasher *self, uint64_t seek,
                                      uint8_t *out, size_t out_len);

void llvm_blake3_hasher_reset(blake3_hasher *self);

// Compatibility aliases (non-LLVM prefix)
#define blake3_version llvm_blake3_version
#define blake3_hasher_init llvm_blake3_hasher_init
#define blake3_hasher_init_keyed llvm_blake3_hasher_init_keyed
#define blake3_hasher_init_derive_key llvm_blake3_hasher_init_derive_key
#define blake3_hasher_update llvm_blake3_hasher_update
#define blake3_hasher_finalize llvm_blake3_hasher_finalize
#define blake3_hasher_finalize_seek llvm_blake3_hasher_finalize_seek
#define blake3_hasher_reset llvm_blake3_hasher_reset

#ifdef __cplusplus
}
#endif

#endif /* BLAKE3_H */