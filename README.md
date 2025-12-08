# Proof-of-Work (PoW) System

<div align="center">

![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![macOS](https://img.shields.io/badge/macOS-000000?style=for-the-badge&logo=apple&logoColor=white)
![Android](https://img.shields.io/badge/Android-3DDC84?style=for-the-badge&logo=android&logoColor=white)
![WASM](https://img.shields.io/badge/WebAssembly-654FF0?style=for-the-badge&logo=webassembly&logoColor=white)

![Language C](https://img.shields.io/badge/C-00599C?style=for-the-badge&logo=c&logoColor=white)
![Language Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Language JS](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![License](https://img.shields.io/badge/License-AGPL%20v3-blue?style=for-the-badge)

[![Benchmakr](https://img.shields.io/badge/Benchmark-FF0000?style=for-the-badge&logo=Benchmark&logoColor=white)](https://qudslab.com/r/Proof-of-work/)

</div>


A high-performance, cross-platform Proof-of-Work system implemented in C with bindings for **Python**, **JavaScript**, and **WebAssembly**. It supports **34 cryptographic hash algorithms** and features a unique **Multi-Hash PoW** mechanism for enhanced security.

## 🚀 Features

- **Cross-Platform**: Runs on Windows, Linux, macOS, Android, and Web browsers (WASM).
- **Extensive Algorithm Support**: Includes 34 hash algorithms (legacy and modern).
- **Multi-Hash PoW**: Require a nonce to satisfy multiple hash algorithms simultaneously, exponentially increasing difficulty.
- **Optimized Ordering**: Algorithms are automatically ordered by efficiency for faster verification.
- **Flexible Nonce Ranges**: Support for custom start/end nonce values, enabling distributed mining.
- **High Performance**: Core logic written in optimized C.

## 🛡️ Supported Platforms

The system is built and tested on the following platforms via GitHub Actions:

| Platform       | Variants                          |
| :------------- | :-------------------------------- |
| **Windows**    | `x64`, `x86`                      |
| **Linux**      | `x86_64`, `aarch64`               |
| **macOS**      | `x86_64`, `arm64` (Apple Silicon) |
| **Android**    | `armv7`, `arm64`, `x86`, `x86_64` |
| **Web / WASM** | `wasm` (JavaScript bindings)      |

## 🛡️ Supported Algorithms

| Family     | Algorithms                                                           |
| :--------- | :------------------------------------------------------------------- |
| **MD**     | MD2, MD4, MD5                                                        |
| **SHA**    | SHA-0, SHA-1, SHA-2 (224, 256, 384, 512), SHA-3 (224, 256, 384, 512) |
| **BLAKE**  | BLAKE2b (128-512), BLAKE2s (128-256)                                 |
| **RIPEMD** | RIPEMD-128, RIPEMD-160, RIPEMD-256, RIPEMD-320                       |
| **Keccak** | Keccak (224, 256, 384, 512), SHAKE (128, 256)                        |
| **Other**  | Whirlpool, HAS-160, NT Hash                                          |

## 🛠️ Build & Install

### Prerequisites

- **Toolchain**: GCC (Windows/Linux/macOS), Android NDK (Android), Emscripten (WASM)
- **Python**: 3.x (for scripts and bindings)
- **Node.js**: (Optional, for running WASM tests)

### Building from Source

The project includes an automated GitHub Actions workflow (`.github/workflows/build-binaries.yml`) that builds all artifacts.

**Windows Local Build:**

```powershell
.\build_win64.ps1
```

**Cross-Platform Builds (GitHub Actions):**
The CI pipeline automatically attempts to build for all supported platforms on every push. You can download the latest artifacts from the "Actions" tab in the GitHub repository.

### Artifact Locations (Automated Build)

- `bin/win/` - Windows DLLs (`client.dll`, `server.dll`)
- `bin/linux/` - Linux Shared Objects (`libclient.so`, `libserver.so`)
- `bin/macos/` - macOS Dynamic Libraries (`libclient.dylib`, `libserver.dylib`)
- `bin/android/` - Android Shared Libraries (`libclient.so`, `libserver.so`)
- `bin/wasm/` - WebAssembly modules (`client.js`, `client.wasm`, etc.)

## 📦 Usage

### Python Client (Generate PoW)

```python
import os
from python.utils_client import PoWClient, create_multi_pow_challenge

# Path to the compiled Client DLL (adjust path as needed)
# e.g., "bin/win/64/dll/client.dll" or "bin/linux/64/libclient.so"
client_dll_path = "path/to/client.dll"

# Initialize client with explicit DLL path
client = PoWClient(dll_path=client_dll_path)

# 1. Single Hash PoW
# Find a nonce for "hello world" using SHA2-256 with 12 bits of difficulty
result = client.generate_single(b"hello world", "SHA2-256", difficulty=12)
if result['success']:
    print(f"Goal met! Nonce: {result['nonce']}")
    print(f"Hash: {client.hash_to_hex(result['hash'])}")

# 2. Multi-Hash PoW (Advanced)
# Require nonce to satisfy 4 different algorithms simultaneously
algos = ["MD5", "SHA2-256", "BLAKE2s-256", "RIPEMD-160"]
result = client.generate_multi(b"hello world", algos, difficulty=12)
if result['success']:
    print(f"Multi-PoW Solved! Nonce: {result['nonce']}")
```

### Python Server (Verify PoW)

```python
import os
from python.utils_server import PoWServer

# Path to the compiled Server DLL (adjust path as needed)
# e.g., "bin/win/64/dll/server.dll" or "bin/linux/64/libserver.so"
server_dll_path = "path/to/server.dll"

# Initialize server with explicit DLL path
server = PoWServer(dll_path=server_dll_path)

# Verify the single hash result
is_valid = server.verify_single(
    b"hello world",
    nonce=12345,
    algo_name="SHA2-256",
    difficulty=12
)
print(f"Valid: {is_valid}")

# Verify the multi-hash result
is_valid_multi = server.verify_multi(
    b"hello world",
    nonce=67890,
    algo_names=["MD5", "SHA2-256", "BLAKE2s-256", "RIPEMD-160"],
    difficulty=12
)
```

## 🧩 Difficulty Levels

Difficulty corresponds to the number of **leading zero bits** required in the hash output.

- `8` = 2 hex zeros (`00...`)
- `12` = 3 hex zeros (`000...`)
- `16` = 4 hex zeros (`0000...`)
- `20` = 5 hex zeros (`00000...`)

**Note:** Multi-hash PoW is exponentially harder than single-hash PoW for the same difficulty setting.

## 🧪 Testing

To run the full test suite (Single vs Multi-hash scenarios, edge cases):

```powershell
python python/main.py win 64
```

## 📂 Project Structure

- `src/` - Core C implementation and hash algorithms (`crypto/`)
- `python/` - Python wrappers (`utils_client.py`, `utils_server.py`) and tests
- `bin/` - Compiled binaries (`win/`, `linux/`, `macos/`, `android/`, `wasm/`)
- `.github/workflows/` - CI/CD pipeline definition

## 📄 License

This project is licensed under the **GNU Affero General Public License v3.0** - see the [LICENSE](LICENSE) file for details.
