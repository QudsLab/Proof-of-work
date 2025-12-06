# first clear all previous builds

# first define the paths
$includePathSha256 = ".\includes\hash\cpu\sha256"
$includePathBlake3 = ".\includes\hash\cpu\blake3"
$libPath = ".\bin\lib"
$dllPath = ".\bin\dll"

# Create directory structure if missing
New-Item -ItemType Directory -Force -Path $libPath | Out-Null
New-Item -ItemType Directory -Force -Path $dllPath | Out-Null

Remove-Item -Path $dllPath\client.dll, $libPath\client.lib, $dllPath\server.dll, $libPath\server.lib -ErrorAction SilentlyContinue

# Compile object files with static linking
gcc -shared -static-libgcc -o "$dllPath\client.dll" pow_client.c "$includePathSha256\sha256.c" "$includePathBlake3\blake3.c" "-I$includePathSha256" "-I$includePathBlake3" "-Wl,--out-implib,$libPath\client.lib"
gcc -shared -static-libgcc -o "$dllPath\server.dll" pow_server.c "$includePathSha256\sha256.c" "$includePathBlake3\blake3.c" "-I$includePathSha256" "-I$includePathBlake3" "-Wl,--out-implib,$libPath\server.lib"

python pow_test.py
