import ctypes

# Load DLLs
client = ctypes.CDLL('./bin/dll/client.dll')
server = ctypes.CDLL('./bin/dll/server.dll')

# Define result struct
class PoWResult(ctypes.Structure):
    _fields_ = [("nonce", ctypes.c_int),
                ("hash_sha256", ctypes.c_ubyte * 32),
                ("hash_blake3", ctypes.c_ubyte * 32)]

# Define function signatures for all three variants
for func_name in ['generate_pow_sha256', 'generate_pow_blake3', 'generate_pow_combined']:
    func = getattr(client, func_name)
    func.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int]
    func.restype = PoWResult

for func_name in ['verify_pow_sha256', 'verify_pow_blake3', 'verify_pow_combined']:
    func = getattr(server, func_name)
    func.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int]
    func.restype = ctypes.c_int

# Test parameters
text = b"hello world"
difficulty = 12
max_nonce = 1000000000

print("=" * 60)
print("Testing Individual PoW Functions")
print("=" * 60)

print("\nINPUT TEXT: ", text,        ' '*4,   "(The input text bytes will be used)")
print(f"DIFFICULTY: {difficulty/4}", ' '*16, f"({difficulty}/4 is the output zeros amount)")
print(f"MAX NONCE: {max_nonce}",     ' '*10,  "(The maximum nonce value to search for)")

# Test SHA256 only
print("\n1. SHA256 Only:")
result = client.generate_pow_sha256(text, difficulty, 0, max_nonce)
print(f"   Nonce: {result.nonce}")
print(f"   SHA256: {''.join(f'{b:02x}' for b in result.hash_sha256)}")
print(f"   BLAKE3: {''.join(f'{b:02x}' for b in result.hash_blake3)} (should be zeros)")
if result.nonce != -1:
    valid = server.verify_pow_sha256(text, result.nonce, difficulty)
    print(f"   Verification: {'Passed' if valid else 'Failed'}")

# Test BLAKE3 only
print("\n2. BLAKE3 Only:")
result = client.generate_pow_blake3(text, difficulty, 0, max_nonce)
print(f"   Nonce: {result.nonce}")
print(f"   SHA256: {''.join(f'{b:02x}' for b in result.hash_sha256)} (should be zeros)")
print(f"   BLAKE3: {''.join(f'{b:02x}' for b in result.hash_blake3)}")
if result.nonce != -1:
    valid = server.verify_pow_blake3(text, result.nonce, difficulty)
    print(f"   Verification: {'Passed' if valid else 'Failed'}")

# Test Combined (both must pass)
print("\n3. Combined (Both SHA256 AND BLAKE3):")
result = client.generate_pow_combined(text, difficulty, 0, max_nonce)
print(f"   Nonce: {result.nonce}")
print(f"   SHA256: {''.join(f'{b:02x}' for b in result.hash_sha256)}")
print(f"   BLAKE3: {''.join(f'{b:02x}' for b in result.hash_blake3)}")
if result.nonce != -1:
    valid = server.verify_pow_combined(text, result.nonce, difficulty)
    print(f"   Verification: {'Passed' if valid else 'Failed'}")

print("\n" + "=" * 60)
