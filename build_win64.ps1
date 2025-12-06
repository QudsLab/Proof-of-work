# Enhanced Proof-of-Work Build Script
# Builds client and server DLLs with all hash algorithm support

################################################################################
################################################################################
###                                                                          ###
###      oooooooooo.  ooooo     ooo ooooo ooooo        oooooooooo.           ###
###      `888'   `Y8b `888'     `8' `888' `888'        `888'   `Y8b          ###
###       888     888  888       8   888   888          888      888         ###
###       888oooo888'  888       8   888   888          888      888         ###
###       888    `88b  888       8   888   888          888      888         ###
###       888    .88P  `88.    .8'   888   888       o  888     d88'         ###
###      o888bood8P'     `YbodP'    o888o o888ooooood8 o888bood8P'           ###
###                                                                          ###
################################################################################
################################################################################


Write-Host "=" -NoNewline; Write-Host ("=" * 79)
Write-Host "Enhanced Proof-of-Work Build System"
Write-Host "=" -NoNewline; Write-Host ("=" * 79)

# Define paths
$libPath = ".\bin\win\64\lib"
$dllPath = ".\bin\win\64\dll"
$src_dir = ".\src"
$cryptoPath = "$src_dir\crypto"

# Create directory structure if missing
New-Item -ItemType Directory -Force -Path $libPath | Out-Null
New-Item -ItemType Directory -Force -Path $dllPath | Out-Null

Write-Host "`nStep 1: Cleaning previous builds..."

# Remove old DLLs and libs (if they exist)
Remove-Item -Path "$dllPath\client.dll" -ErrorAction SilentlyContinue
Remove-Item -Path "$libPath\client.lib" -ErrorAction SilentlyContinue
Remove-Item -Path "$dllPath\server.dll" -ErrorAction SilentlyContinue
Remove-Item -Path "$libPath\server.lib" -ErrorAction SilentlyContinue

Write-Host "  OK Cleaned old builds"

# Collect all hash algorithm source files
Write-Host "`nStep 2: Collecting hash algorithm sources..."

$hashSources = @(
    "$cryptoPath\md2\md2.c",
    "$cryptoPath\md4\md4.c",
    "$cryptoPath\md5\md5.c",
    "$cryptoPath\sha0\sha0.c",
    "$cryptoPath\sha1\sha1.c",
    "$cryptoPath\sha224\sha224.c",
    "$cryptoPath\sha256\sha256.c",
    "$cryptoPath\sha512\sha512.c",
    "$cryptoPath\sha3\sha3.c",
    "$cryptoPath\sha3_224\sha3_224.c",
    "$cryptoPath\sha3_384\sha3_384.c",
    "$cryptoPath\keccak\keccak.c",
    "$cryptoPath\shake\shake.c",
    "$cryptoPath\ripemd\ripemd160.c",
    "$cryptoPath\ripemd128\ripemd128.c",
    "$cryptoPath\ripemd256\ripemd256.c",
    "$cryptoPath\ripemd320\ripemd320.c",
    "$cryptoPath\blake2b\blake2b.c",
    "$cryptoPath\blake2s\blake2s.c",
    "$cryptoPath\whirlpool\whirlpool.c",
    "$cryptoPath\has160\has160.c",
    "$cryptoPath\nt\nt.c"
)

# Verify sources exist
$missingFiles = @()
foreach ($src in $hashSources) {
    if (!(Test-Path $src)) {
        $missingFiles += $src
    }
}

if ($missingFiles.Count -gt 0) {
    Write-Host "`n  ERROR: Missing source files:" -ForegroundColor Red
    foreach ($file in $missingFiles) {
        Write-Host "    - $file" -ForegroundColor Red
    }
    exit 1
}

Write-Host "  OK Found all $($hashSources.Count) hash algorithm sources"

# Collect include paths
Write-Host "`nStep 3: Setting up include paths..."

$includePaths = @(
    ".",
    "$cryptoPath\md2",
    "$cryptoPath\md4",
    "$cryptoPath\md5",
    "$cryptoPath\sha0",
    "$cryptoPath\sha1",
    "$cryptoPath\sha224",
    "$cryptoPath\sha256",
    "$cryptoPath\sha512",
    "$cryptoPath\sha3",
    "$cryptoPath\sha3_224",
    "$cryptoPath\sha3_384",
    "$cryptoPath\keccak",
    "$cryptoPath\shake",
    "$cryptoPath\ripemd",
    "$cryptoPath\ripemd128",
    "$cryptoPath\ripemd256",
    "$cryptoPath\ripemd320",
    "$cryptoPath\blake2b",
    "$cryptoPath\blake2s",
    "$cryptoPath\whirlpool",
    "$cryptoPath\has160",
    "$cryptoPath\nt"
)

$includeFlags = ($includePaths | ForEach-Object { "-I$_" }) -join " "

Write-Host "  OK Configured $($includePaths.Count) include paths"

# Build client DLL
Write-Host "`nStep 4: Building client.dll..."

$clientSources = "$src_dir\client.c " + ($hashSources -join " ")
$clientCmd = "gcc -shared -static-libgcc -o `"$dllPath\client.dll`" $clientSources $includeFlags `"-Wl,--out-implib,$libPath\client.lib`""

Write-Host "  Compiling..."
$output = Invoke-Expression $clientCmd 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: Client build failed" -ForegroundColor Red
    Write-Host $output
    exit 1
}

if (Test-Path "$dllPath\client.dll") {
    $size = (Get-Item "$dllPath\client.dll").Length / 1KB
    Write-Host (("  OK client.dll built successfully ({0})" -f [math]::Round($size,2)) + " KB") -ForegroundColor Green
} else {
    Write-Host "  ERROR: client.dll not found after build" -ForegroundColor Red
    exit 1
}

# Build server DLL
Write-Host "`nStep 5: Building server.dll..."

$serverSources = "$src_dir\server.c " + ($hashSources -join " ")
$serverCmd = "gcc -shared -static-libgcc -o `"$dllPath\server.dll`" $serverSources $includeFlags `"-Wl,--out-implib,$libPath\server.lib`""

Write-Host "  Compiling..."
$output = Invoke-Expression $serverCmd 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: Server build failed" -ForegroundColor Red
    Write-Host $output
    exit 1
}

if (Test-Path "$dllPath\server.dll") {
    $size = (Get-Item "$dllPath\server.dll").Length / 1KB
    Write-Host (("  OK server.dll built successfully ({0})" -f [math]::Round($size,2)) + " KB") -ForegroundColor Green
} else {
    Write-Host "  ERROR: server.dll not found after build" -ForegroundColor Red
    exit 1
}


################################################################################
################################################################################
###                                                                          ###
###           ooooooooooooo oooooooooooo  .oooooo..o ooooooooooooo           ###
###           8'   888   `8 `888'     `8 d8P'    `Y8 8'   888   `8           ###
###                888       888         Y88bo.           888                ###
###                888       888oooo8     `"Y8888o.       888                ###
###                888       888    "         `"Y88b      888                ###
###                888       888       o oo     .d8P      888                ###
###               o888o     o888ooooood8 8""88888P'      o888o               ###
###                                                                          ###
################################################################################
################################################################################

$pythonPath = "python"
# Run tests
Write-Host "`nStep 6: Running test suite..."
Write-Host "=" -NoNewline; Write-Host ("=" * 79)

try {
    # pass as 1st arg win and 2nd arg 64 to indicate platform
    Write-Host "=" -NoNewline; Write-Host ("=" * 79)
    Write-Host "  Running Python tests with command:"
    Write-Host "    python `"$pythonPath/main.py`" win 64`n"
    Write-Host "=" -NoNewline; Write-Host ("=" * 79)
    python "$pythonPath/main.py" win 64
    Write-Host "=" -NoNewline; Write-Host ("=" * 79)
    if ($LASTEXITCODE -eq 0) {
        Write-Host "`n" + ("=" * 80)
        Write-Host "BUILD AND TEST SUCCESSFUL!" -ForegroundColor Green
        Write-Host ("=" * 80)
        Write-Host "`nBuilt libraries:"
        Write-Host "  - $dllPath\client.dll"
        Write-Host "  - $dllPath\server.dll"
        Write-Host "  - $libPath\client.lib"
        Write-Host "  - $libPath\server.lib"
        Write-Host "`nPython utilities:"
        Write-Host "  - pow_utils_client.py"
        Write-Host "  - pow_utils_server.py"
        Write-Host "`nSupported algorithms: 34"
        Write-Host "  MD2, MD4, MD5, NT, HAS-160,"
        Write-Host "  RIPEMD-128/160/256/320,"
        Write-Host "  BLAKE2b-128/160/256/384/512, BLAKE2s-128/160/256,"
        Write-Host "  SHA-0, SHA-1, SHA2-224/256/384/512,"
        Write-Host "  SHA3-224/256/384/512, Keccak-224/256/384/512,"
        Write-Host "  SHAKE-128/256, Whirlpool"
    } else {
        Write-Host "TESTS FAILED"
        exit 1
    }
} catch {
    exit 1
}
