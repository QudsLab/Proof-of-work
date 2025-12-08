# Proof-of-Work Library

A high-performance Proof-of-Work library with support for 34 hash algorithms, optimized for cryptographic challenges and distributed systems.

## Features

- **34 Hash Algorithms**: MD2, MD4, MD5, SHA-0, SHA-1, SHA2 (224/256/384/512), SHA3 (224/256/384/512), BLAKE2 (b/s), Whirlpool, RIPEMD (128/160/256/320), Keccak, SHAKE, HAS-160, and NT hashing
- **Multi-Algorithm Support**: Generate and verify PoW across multiple hash algorithms simultaneously
- **Cross-Platform Binaries**: Precompiled for Windows (x86/x64), Linux (x86_64/ARM64), macOS (Intel/Apple Silicon), and Android (4 ABIs)
- **High Performance**: Optimized C implementation with ctypes Python bindings
- **Easy Integration**: Simple Python API for PoW generation and verification

## Installation

### From PyPI

```bash
pip install proof-of-work
```

### Development Installation

```bash
git clone https://github.com/QudsLab/Proof-of-work.git
cd Proof-of-work
pip install -e .
```

## Quick Start

### Single Algorithm PoW

```python
from python.utils_client import PoWClient

# Initialize client with DLL path
client = PoWClient("path/to/client.dll")

# Generate PoW with single algorithm
result = client.generate_single(
    text=b"hello world",
    algorithm="SHA2-256",
    difficulty=12,
    nonce_start=0,
    nonce_end=100000000
)

print(f"Nonce: {result['nonce']}")
print(f"Hash: {result['hash'].hex()}")
print(f"Success: {result['success']}")
```

### Multi-Algorithm PoW

```python
from python.utils_client import PoWClient, create_multi_pow_challenge

# Generate PoW with multiple algorithms
challenge = create_multi_pow_challenge(
    algorithms=["MD5", "SHA2-256", "BLAKE2b-512"],
    difficulty=10,
    nonce_count=100000000
)

result = client.generate_multi(challenge)
print(f"All algorithms satisfied: {all(r['success'] for r in result)}")
```

### Verify PoW

```python
from python.utils_server import PoWServer

# Initialize server with DLL path
server = PoWServer("path/to/server.dll")

# Verify single algorithm PoW
is_valid = server.verify_single(
    nonce=12345,
    hash_bytes=b"...",
    algorithm="SHA2-256",
    difficulty=12
)

# Verify multi-algorithm PoW
is_valid = server.verify_multi(
    result=result,
    challenge=challenge
)
```

## Supported Algorithms

| ID | Algorithm | Output Size |
|----|-----------|-------------|
| 0 | MD4 | 128 bits |
| 1 | NT | 128 bits |
| 2 | MD5 | 128 bits |
| 3 | HAS-160 | 160 bits |
| 4 | RIPEMD-256 | 256 bits |
| 5 | RIPEMD-128 | 128 bits |
| 6 | BLAKE2s-128 | 128 bits |
| 7 | BLAKE2s-160 | 160 bits |
| 8 | BLAKE2s-256 | 256 bits |
| 9 | BLAKE2b-512 | 512 bits |
| 10 | RIPEMD-320 | 320 bits |
| 11 | BLAKE2b-128 | 128 bits |
| 12 | BLAKE2b-384 | 384 bits |
| 13 | RIPEMD-160 | 160 bits |
| 14 | BLAKE2b-160 | 160 bits |
| 15 | BLAKE2b-256 | 256 bits |
| 16 | SHA2-256 | 256 bits |
| 17 | SHA-0 | 160 bits |
| 18 | SHA-1 | 160 bits |
| 19 | SHA2-224 | 224 bits |
| 20 | SHA2-512 | 512 bits |
| 21 | SHA2-384 | 384 bits |
| 22 | Whirlpool | 512 bits |
| 23 | SHA3-224 | 224 bits |
| 24 | SHAKE-256 | Variable |
| 25 | SHA3-384 | 384 bits |
| 26 | SHAKE-128 | Variable |
| 27 | Keccak-384 | 384 bits |
| 28 | Keccak-256 | 256 bits |
| 29 | SHA3-256 | 256 bits |
| 30 | SHA3-512 | 512 bits |
| 31 | Keccak-512 | 512 bits |
| 32 | Keccak-224 | 224 bits |
| 33 | MD2 | 128 bits |

## Architecture

```
Proof-of-work/
├── src/                           # C source code
│   ├── client.c                  # Client implementation
│   ├── server.c                  # Server implementation
│   ├── export.h                  # C API definitions
│   └── crypto/                   # Hash algorithm implementations
│       ├── blake2b/, blake2s/
│       ├── sha1/, sha2/, sha3/
│       ├── md5/, md4/, md2/
│       ├── ripemd/
│       └── ... (other algorithms)
├── python/                        # Python bindings
│   ├── main.py                   # Test suite
│   ├── utils_client.py           # Client ctypes wrapper
│   └── utils_server.py           # Server ctypes wrapper
├── bin/                          # Precompiled binaries
│   ├── windows/64/dll/
│   ├── linux/64/lib/
│   ├── macos/64/lib/
│   └── android/*/lib/
└── generate_metadata.py          # Build metadata generator
```

## Building from Source

### Windows (PowerShell)

```powershell
.\build_win64.ps1
```

### Linux/macOS

```bash
cd src/crypto
gcc -shared -fPIC -o libclient.so client.c blake2b/*.c sha256/*.c ... -Isrc
gcc -shared -fPIC -o libserver.so server.c blake2b/*.c sha256/*.c ... -Isrc
```

### Android

```bash
$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang \
  -shared -fPIC -o libclient.so client.c ... -Isrc
```

## Testing

```bash
cd python
python main.py win 64
python main.py linux 64
python main.py macos 64
python main.py android armv7
```

## CI/CD

- **Binary Building**: Automated via GitHub Actions on each push and daily schedule
- **Multi-Platform**: Windows, Linux, macOS, Android with multiple architectures
- **Auto-Commit**: Binaries automatically committed to repository
- **PyPI Publishing**: Release tags trigger automatic PyPI publication

## Documentation

- [Binary Checksums](https://github.com/QudsLab/Proof-of-work/tree/main/bin)
- [Build Instructions](https://github.com/QudsLab/Proof-of-work/blob/main/POW_README.md)
- [Benchmark Results](https://github.com/QudsLab/Proof-of-work/blob/main/BENCHMARK.md)

## Requirements

- Python 3.8+
- Platform-specific binary (Windows DLL, Linux/Android .so, or macOS .dylib)

## License

MIT License - See [LICENSE](LICENSE) file for details

## Contributing

Contributions are welcome! Please open issues or submit pull requests on [GitHub](https://github.com/QudsLab/Proof-of-work).

## Support

For issues, questions, or suggestions:
- GitHub Issues: https://github.com/QudsLab/Proof-of-work/issues
- Email: contact@qudslab.com

## Citation

If you use this library in your research, please cite:

```bibtex
@software{qudslab_pow,
  title = {Proof-of-Work Library},
  author = {QudsLab},
  url = {https://github.com/QudsLab/Proof-of-work},
  year = {2024}
}
```
