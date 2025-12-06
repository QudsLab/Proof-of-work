# Build script for standalone hash implementations
Write-Host "Building standalone hash implementations..." -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# All hash algorithm source files (sha384 is included in sha512.c)
$sources = @(
    "crypto/md2/md2.c",
    "crypto/md4/md4.c",
    "crypto/md5/md5.c",
    "crypto/sha0/sha0.c",
    "crypto/sha1/sha1.c",
    "crypto/sha224/sha224.c",
    "crypto/sha256/sha256.c",
    "crypto/sha512/sha512.c",
    "crypto/sha3/sha3.c",
    "crypto/sha3_224/sha3_224.c",
    "crypto/sha3_384/sha3_384.c",
    "crypto/keccak/keccak.c",
    "crypto/shake/shake.c",
    "crypto/ripemd/ripemd160.c",
    "crypto/ripemd128/ripemd128.c",
    "crypto/ripemd256/ripemd256.c",
    "crypto/ripemd320/ripemd320.c",
    "crypto/blake2b/blake2b.c",
    "crypto/blake2s/blake2s.c",
    "crypto/whirlpool/whirlpool.c",
    "crypto/has160/has160.c",
    "crypto/nt/nt.c",
    "crypto/main.c"
)

gcc -w -O2 -I. $sources -o hash_test.exe 2>$null

if ($LASTEXITCODE -eq 0) {
    Write-Host "Build successful!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Running tests..." -ForegroundColor Yellow
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host ""
    & .\hash_test.exe
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "==========================================" -ForegroundColor Cyan
        Write-Host "All tests passed!" -ForegroundColor Green
    } else {
        Write-Host ""
        Write-Host "Tests failed!" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}
