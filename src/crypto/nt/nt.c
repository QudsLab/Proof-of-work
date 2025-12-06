/*
 * NT Hash (NTLM Hash) Implementation
 * Windows password hash - MD4 of UTF-16LE password
 */

#include "nt.h"
#include "../md4/md4.h"
#include <string.h>

void nt_hash_unicode(const uint8_t *password_utf16le, size_t len, uint8_t digest[NT_HASH_LENGTH]) {
    md4_hash(password_utf16le, len, digest);
}

void nt_hash(const char *password, uint8_t digest[NT_HASH_LENGTH]) {
    /* Convert ASCII to UTF-16LE (simple conversion, assumes ASCII input) */
    size_t len = strlen(password);
    uint8_t utf16[512]; /* Max 256 characters */
    
    if (len > 256) len = 256;
    
    for (size_t i = 0; i < len; i++) {
        utf16[i * 2] = (uint8_t)password[i];
        utf16[i * 2 + 1] = 0;
    }
    
    nt_hash_unicode(utf16, len * 2, digest);
}
