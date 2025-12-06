#ifndef NT_HASH_H
#define NT_HASH_H

#include <stdint.h>
#include <stddef.h>

#define NT_HASH_LENGTH 16

/* NT Hash (NTLM Hash) - Windows password hash using MD4 */
void nt_hash(const char *password, uint8_t digest[NT_HASH_LENGTH]);
void nt_hash_unicode(const uint8_t *password_utf16le, size_t len, uint8_t digest[NT_HASH_LENGTH]);

#endif /* NT_HASH_H */
