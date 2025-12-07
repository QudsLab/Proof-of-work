# Proof-of-Work Binaries

**Repository**: [QudsLab/Proof-of-work](https://github.com/QudsLab/Proof-of-work)
**Generated**: 2025-12-07 11:45 UTC

This directory contains pre-built binaries for multiple platforms.

## Metadata Files

- `binaries.json` - Runtime binaries (DLLs, .so, .dylib, .wasm)
- `c_lib.json` - Development libraries (for C/C++ linking)

## Summary

| Platform | Variant | Client | Server |
|----------|---------|--------|--------|
| Windows | 32 | 2 | 2 |
| Windows | 64 | 2 | 2 |
| Linux | 64 | 2 | 2 |
| Linux | arm64 | 2 | 2 |
| Macos | 64 | 2 | 2 |
| Macos | arm64 | 2 | 2 |
| Android | arm64 | 2 | 2 |
| Android | armv7 | 2 | 2 |
| Android | x86 | 2 | 2 |
| Android | x86_64 | 2 | 2 |
| Wasm | wasm | 4 | 4 |

## Download Links

All binaries are available via direct GitHub raw URLs.
See `binaries.json` and `c_lib.json` for complete download links and checksums.

## Usage

### Download via curl
```bash
# Example: Download Windows x64 client DLL
curl -O https://raw.githubusercontent.com/QudsLab/Proof-of-work/main/bin/win/64/client/client.dll
```

### Download via wget
```bash
# Example: Download Linux x64 client library
wget https://raw.githubusercontent.com/QudsLab/Proof-of-work/main/bin/linux/64/client/libclient.so
```

### Verify checksums
```bash
# Linux/macOS
sha256sum client.dll
md5sum client.dll

# Windows PowerShell
Get-FileHash client.dll -Algorithm SHA256
Get-FileHash client.dll -Algorithm MD5
```

## Structure

```
bin/
├── binaries.json (runtime binaries metadata)
├── c_lib.json (development libraries metadata)
├── README.md
└── {os}/
    └── {variant}/
        ├── client/
        │   └── [runtime files]
        └── server/
            └── [runtime files]
```
