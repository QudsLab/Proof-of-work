# Enhanced Proof-of-Work System

## Overview

This is a comprehensive Proof-of-Work (PoW) implementation supporting **34 cryptographic hash algorithms** with both single-hash and multi-hash PoW generation and verification.

## Features

✓ **34 Hash Algorithms Supported**
- MD2, MD4, MD5, NT Hash, HAS-160
- RIPEMD-128/160/256/320
- BLAKE2b-128/160/256/384/512
- BLAKE2s-128/160/256
- SHA-0, SHA-1, SHA2-224/256/384/512
- SHA3-224/256/384/512
- Keccak-224/256/384/512
- SHAKE-128/256
- Whirlpool

✓ **Flexible Nonce Ranges** - Start from any nonce value, not just 0

✓ **Multi-Hash PoW** - Require nonce to satisfy multiple hash algorithms simultaneously

✓ **Optimized Algorithm Ordering** - Algorithms ordered by efficiency for faster multi-hash PoW

✓ **Python Utilities** - Easy-to-use client and server helper modules

## Files

### Core C Implementation
- `pow_client_new.c` - Client-side PoW generation with all algorithms
- `pow_server_new.c` - Server-side PoW verification
- `export.h` - Export definitions for DLL functions

### Python Utilities
- `pow_utils_client.py` - Client helper functions for PoW generation
- `pow_utils_server.py` - Server helper functions for PoW verification
- `pow_test_new.py` - Comprehensive test suite

### Build System
- `pow_build_new.ps1` - PowerShell build script for Windows

### Generated Libraries
- `bin/dll/client.dll` - Client DLL
- `bin/dll/server.dll` - Server DLL
- `bin/lib/client.lib` - Client import library
- `bin/lib/server.lib` - Server import library

## Building

### Windows (PowerShell)

```powershell
.\pow_build_new.ps1
```

This will:
1. Clean previous builds
2. Collect all hash algorithm sources
3. Build client.dll and server.dll
4. Run the comprehensive test suite

### Requirements
- GCC (MinGW-w64 recommended for Windows)
- Python 3.x
- All hash algorithm source files in `crypto/` directory

## Usage

### Python Client (Generate PoW)

```python
from pow_utils_client import PoWClient, create_multi_pow_challenge

client = PoWClient()

# Single hash PoW
result = client.generate_single("hello world", "SHA2-256", difficulty=12)
if result['success']:
    print(f"Nonce: {result['nonce']}")
    print(f"Hash: {client.hash_to_hex(result['hash'])}")

# Multi-hash PoW (4 algorithms)
algos = create_multi_pow_challenge(4, difficulty=12)
result = client.generate_multi("hello world", algos, difficulty=12)
if result['success']:
    print(f"Nonce: {result['nonce']}")
    for i, algo in enumerate(result['algorithms']):
        print(f"{algo}: {client.hash_to_hex(result['hashes'][i])}")

# Custom nonce range
result = client.generate_single("hello world", "MD5", difficulty=12, 
                               min_nonce=1000, max_nonce=100000000)
```

### Python Server (Verify PoW)

```python
from pow_utils_server import PoWServer

server = PoWServer()

# Verify single hash
valid = server.verify_single("hello world", nonce=12345, 
                            algo_name="SHA2-256", difficulty=12)
print(f"Valid: {valid}")

# Verify multi-hash
algos = ["MD4", "NT", "MD5", "HAS-160"]
valid = server.verify_multi("hello world", nonce=12345, 
                           algo_names=algos, difficulty=12)
print(f"Valid: {valid}")

# Verify challenge format
challenge = {
    'text': 'hello world',
    'nonce': 12345,
    'algorithms': algos,
    'difficulty': 12
}
valid = server.verify_challenge(challenge)
```

### Direct C API

#### Client DLL Functions

```c
// Single hash PoW
PoWResult generate_pow_single(
    const char *input, 
    HashAlgorithm algo, 
    int difficulty, 
    int min_nonce, 
    int max_nonce
);

// Multi-hash PoW
MultiPoWResult generate_pow_multi(
    const char *input, 
    HashAlgorithm *algos, 
    int num_algos, 
    int difficulty, 
    int min_nonce, 
    int max_nonce
);

// Get algorithm ID by name
int get_hash_algo_by_name(const char *name);
```

#### Server DLL Functions

```c
// Verify single hash PoW
int verify_pow_single(
    const char *input, 
    int nonce, 
    HashAlgorithm algo, 
    int difficulty
);

// Verify multi-hash PoW
int verify_pow_multi(
    const char *input, 
    int nonce, 
    HashAlgorithm *algos, 
    int num_algos, 
    int difficulty
);

// Get algorithm ID by name
int get_hash_algo_by_name(const char *name);
```

## Algorithm Ordering

For multi-hash PoW, algorithms are ordered by efficiency (fastest to slowest):

1. MD4 (fastest)
2. NT Hash
3. MD5
4. HAS-160
5. RIPEMD-256/128
6. BLAKE2s variants
7. BLAKE2b variants
8. RIPEMD-160/320
9. SHA-2 family
10. Whirlpool
11. SHA-3 family
12. Keccak variants
13. SHAKE variants
14. MD2 (slowest)

This ordering ensures efficient multi-hash PoW generation.

## Testing

Run the comprehensive test suite:

```powershell
python pow_test_new.py
```

The test suite includes:
- Single hash algorithm tests (5 examples)
- Multi-hash PoW tests (4, 5, and 6 algorithm combinations)
- Custom nonce range tests
- Edge cases and validation tests

## How Multi-Hash PoW Works

In multi-hash PoW, a nonce is only valid if **ALL** specified hash algorithms produce outputs with the required number of leading zero bits.

Example:
```python
algos = ["MD4", "MD5", "SHA2-256"]
difficulty = 12  # Require 12 leading zero bits

# The nonce must satisfy:
# - MD4(input + nonce) has ≥12 leading zero bits AND
# - MD5(input + nonce) has ≥12 leading zero bits AND
# - SHA256(input + nonce) has ≥12 leading zero bits
```

This creates a significantly harder challenge than single-hash PoW, as the probability of success decreases exponentially with each added algorithm.

## Difficulty Explanation

Difficulty represents the number of **leading zero bits** required in the hash output:

- `difficulty = 8` → 2 hex zeros (00xxxxxx...)
- `difficulty = 12` → 3 hex zeros (000xxxxx...)
- `difficulty = 16` → 4 hex zeros (0000xxxx...)
- `difficulty = 20` → 5 hex zeros (00000xxx...)

Higher difficulty = exponentially more computation required.

## Performance Tips

1. **Use faster algorithms first** - The system tries algorithms in order
2. **Adjust difficulty** - Start with lower difficulty for testing
3. **Limit max_nonce** - Set reasonable limits to avoid infinite loops
4. **Use multi-threading** - C implementation can be parallelized

## Troubleshooting

### Build Errors
- Ensure all hash algorithm source files exist in `crypto/` directory
- Verify GCC is installed and in PATH
- Check for missing header files

### Python Import Errors
- Ensure DLLs are built in `bin/dll/` directory
- Verify Python ctypes can find the DLLs
- Check DLL architecture matches Python (32-bit vs 64-bit)

### Verification Failures
- Ensure input text matches exactly (including encoding)
- Verify nonce value is correct
- Check algorithm names match exactly (case-sensitive)
- Confirm difficulty value is consistent

## License

See LICENSE file for details.

## Contributing

Contributions welcome! Please ensure:
- Code follows existing style
- All tests pass
- New algorithms are properly integrated
- Documentation is updated

## Migration from Old System

If migrating from the previous 2-algorithm system:

### Old Code
```python
result = client.generate_pow_sha256(text, difficulty, 0, max_nonce)
valid = server.verify_pow_sha256(text, nonce, difficulty)
```

### New Code
```python
result = client.generate_single(text, "SHA2-256", difficulty, 0, max_nonce)
valid = server.verify_single(text, nonce, "SHA2-256", difficulty)
```

The new system provides more flexibility while maintaining compatibility through algorithm selection.
