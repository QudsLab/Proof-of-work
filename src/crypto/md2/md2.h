#ifndef MD2_H
#define MD2_H

#include <stdint.h>
#include <stddef.h>

/* MD2 context structure */
typedef struct {
    uint8_t state[16];      /* State */
    uint8_t checksum[16];   /* Checksum */
    uint8_t buffer[16];     /* Input buffer */
    uint32_t count;         /* Number of bytes in buffer */
} MD2_CTX;

/* MD2 constants */
#define MD2_DIGEST_LENGTH 16
#define MD2_BLOCK_SIZE 16

/* MD2 API functions */
void md2_init(MD2_CTX *ctx);
void md2_update(MD2_CTX *ctx, const uint8_t *data, size_t len);
void md2_final(uint8_t digest[MD2_DIGEST_LENGTH], MD2_CTX *ctx);
void md2_hash(const uint8_t *data, size_t len, uint8_t digest[MD2_DIGEST_LENGTH]);

#endif /* MD2_H */
