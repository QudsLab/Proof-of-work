@echo off
REM Build script for standalone hash implementations

echo Building standalone hash implementations...
echo ==========================================
echo.

REM Compile (suppress warnings with -w flag)
gcc -w -O2 -I. crypto/md2/md2.c crypto/md4/md4.c crypto/md5/md5.c crypto/sha0/sha0.c crypto/sha1/sha1.c crypto/sha224/sha224.c crypto/sha256/sha256.c crypto/sha512/sha512.c crypto/sha3/sha3.c crypto/sha3_224/sha3_224.c crypto/sha3_384/sha3_384.c crypto/keccak/keccak.c crypto/shake/shake.c crypto/ripemd/ripemd160.c crypto/ripemd128/ripemd128.c crypto/ripemd256/ripemd256.c crypto/ripemd320/ripemd320.c crypto/blake2b/blake2b.c crypto/blake2s/blake2s.c crypto/whirlpool/whirlpool.c crypto/has160/has160.c crypto/nt/nt.c crypto/main.c -o hash_test.exe 2>nul

if %ERRORLEVEL% EQU 0 (
    echo Build successful!
    echo.
    echo Running tests...
    echo ==========================================
    echo.
    
    hash_test.exe
    
    if %ERRORLEVEL% EQU 0 (
        echo.
        echo ==========================================
        echo All tests passed!
    ) else (
        echo.
        echo Tests failed!
        exit /b 1
    )
) else (
    echo Build failed!
    exit /b 1
)
