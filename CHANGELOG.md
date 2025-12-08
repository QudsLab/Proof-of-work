# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-12-08

### Added
- Initial PyPI release
- Support for 34 hash algorithms (MD2, MD4, MD5, SHA-0, SHA-1, SHA2, SHA3, BLAKE2, Whirlpool, RIPEMD, Keccak, SHAKE, HAS-160, NT)
- Multi-algorithm Proof-of-Work generation and verification
- Cross-platform precompiled binaries (Windows x86/x64, Linux x86_64/ARM64, macOS Intel/Apple Silicon, Android 4 ABIs)
- Python ctypes bindings for client and server libraries
- Comprehensive test suite
- GitHub Actions CI/CD for automated binary building
- Automated PyPI publishing workflow

### Features
- `PoWClient` class for single and multi-algorithm PoW generation
- `PoWServer` class for PoW verification
- Helper functions for challenge creation
- Configurable difficulty levels
- Hash verification with MD5 and SHA256 checksums
- Binary metadata generation with JSON and Markdown output

### Documentation
- Quick start guide
- Algorithm reference table
- Architecture overview
- Building instructions for all platforms
- Complete API documentation

[1.0.0]: https://github.com/QudsLab/Proof-of-work/releases/tag/v1.0.0
