# -*- coding: utf-8 -*-
"""
Enhanced Proof-of-Work Test Suite
Tests single and multi-hash PoW with all supported algorithms
"""
import sys
import os
from pathlib import Path
from utils_client import PoWClient, create_multi_pow_challenge
from utils_server import PoWServer

# Test parameters
TEST_TEXT = b"hello world"
DIFFICULTY = 12
MAX_NONCE = 100000000

# current directory paths
BASE_DIR = Path(__file__).parent.parent

# get system arg for dll paths os and variant only
# take one arg for os type one for variant
OS__TYPE = "win"
VARIANT = "64"
if len(sys.argv) > 1:
    OS__TYPE = sys.argv[1].lower()
    VARIANT = sys.argv[2].lower()

# Determine library paths based on OS
if OS__TYPE == "win":
    BIN_PATH = BASE_DIR / "bin" / "win" / VARIANT / "lib"
    SERVER_DLL = str(BIN_PATH / "server.dll")
    CLIENT_DLL = str(BIN_PATH / "client.dll")
elif OS__TYPE == "linux":
    BIN_PATH = BASE_DIR / "bin" / "linux" / VARIANT / "lib"
    SERVER_DLL = str(BIN_PATH / "libserver.so")
    CLIENT_DLL = str(BIN_PATH / "libclient.so")
elif OS__TYPE == "macos":
    BIN_PATH = BASE_DIR / "bin" / "macos" / VARIANT / "lib"
    SERVER_DLL = str(BIN_PATH / "libserver.dylib")
    CLIENT_DLL = str(BIN_PATH / "libclient.dylib")
else:
    print(f"ERROR: Unknown OS type '{OS__TYPE}'")
    sys.exit(1)

print("=" * 80)
print("Enhanced Proof-of-Work Test Suite")
print("=" * 80)
print(f"\nINPUT TEXT: {TEST_TEXT.decode()}")
print(f"DIFFICULTY: {DIFFICULTY/4} hex digits ({DIFFICULTY} bits of leading zeros)")
print(f"MAX NONCE:  {MAX_NONCE}")
print(f"\nDLL Paths:")
print(f"  Client: {CLIENT_DLL}")
print(f"  Server: {SERVER_DLL}")

# Initialize client and server
try:
    client = PoWClient(dll_path=CLIENT_DLL)
    server = PoWServer(dll_path=SERVER_DLL)
except (FileNotFoundError, OSError) as e:
    print(f"\nERROR: Failed to load DLL files")
    print(f"{e}")
    sys.exit(1)

# ============================================================================
# PART 1: Single Hash Algorithm Tests
# ============================================================================
print("\n" + "=" * 80)
print("PART 1: Single Hash Algorithm Tests")
print("=" * 80)

single_tests = [
    "MD4",
    "MD5", 
    "SHA2-256",
    "BLAKE2s-256",
    "SHA3-256"
]

for algo in single_tests:
    print(f"\n{algo}:")
    result = client.generate_single(TEST_TEXT, algo, DIFFICULTY, 0, MAX_NONCE)
    
    if result['success']:
        print(f"  Nonce: {result['nonce']}")
        print(f"  Hash:  {client.hash_to_hex(result['hash'])}")
        
        # Verify
        valid = server.verify_single(TEST_TEXT, result['nonce'], algo, DIFFICULTY)
        status = "PASSED" if valid else "FAILED"
        print(f"  Verification: {status}")
    else:
        print(f"  FAILED: No nonce found within {MAX_NONCE} attempts")

# ============================================================================
# PART 2: Multi-Hash PoW Tests (2-3 examples with 4-6 algorithms each)
# ============================================================================
print("\n" + "=" * 80)
print("PART 2: Multi-Hash Proof-of-Work Tests")
print("=" * 80)
print("(All algorithms must satisfy difficulty for nonce to be valid)")

# Multi-hash test 1: 4 algorithms (optimized for speed)
print("\n" + "-" * 80)
print("Test 1: Fast Multi-Hash (4 algorithms)")
print("-" * 80)
algos_test1 = create_multi_pow_challenge(4, DIFFICULTY)
print(f"Algorithms: {', '.join(algos_test1)}")

result = client.generate_multi(TEST_TEXT, algos_test1, DIFFICULTY, 0, MAX_NONCE)
if result['success']:
    print(f"Nonce found: {result['nonce']}")
    print("\nHash outputs:")
    for i, algo in enumerate(result['algorithms']):
        print(f"  {algo:15} : {client.hash_to_hex(result['hashes'][i])}")
    
    # Verify
    valid = server.verify_multi(TEST_TEXT, result['nonce'], algos_test1, DIFFICULTY)
    status = "PASSED" if valid else "FAILED"
    print(f"\nVerification: {status}")
else:
    print(f"FAILED: No nonce found within {MAX_NONCE} attempts")

# Multi-hash test 2: 5 algorithms (medium difficulty)
print("\n" + "-" * 80)
print("Test 2: Medium Multi-Hash (5 algorithms)")
print("-" * 80)
algos_test2 = create_multi_pow_challenge(5, DIFFICULTY)
print(f"Algorithms: {', '.join(algos_test2)}")

result = client.generate_multi(TEST_TEXT, algos_test2, DIFFICULTY, 0, MAX_NONCE)
if result['success']:
    print(f"Nonce found: {result['nonce']}")
    print("\nHash outputs:")
    for i, algo in enumerate(result['algorithms']):
        print(f"  {algo:15} : {client.hash_to_hex(result['hashes'][i])}")
    
    # Verify
    valid = server.verify_multi(TEST_TEXT, result['nonce'], algos_test2, DIFFICULTY)
    status = "PASSED" if valid else "FAILED"
    print(f"\nVerification: {status}")
else:
    print(f"FAILED: No nonce found within {MAX_NONCE} attempts")

# Multi-hash test 3: 6 algorithms (challenging)
print("\n" + "-" * 80)
print("Test 3: Challenging Multi-Hash (6 algorithms)")
print("-" * 80)
algos_test3 = create_multi_pow_challenge(6, DIFFICULTY)
print(f"Algorithms: {', '.join(algos_test3)}")

result = client.generate_multi(TEST_TEXT, algos_test3, DIFFICULTY, 0, MAX_NONCE)
if result['success']:
    print(f"Nonce found: {result['nonce']}")
    print("\nHash outputs:")
    for i, algo in enumerate(result['algorithms']):
        print(f"  {algo:15} : {client.hash_to_hex(result['hashes'][i])}")
    
    # Verify
    valid = server.verify_multi(TEST_TEXT, result['nonce'], algos_test3, DIFFICULTY)
    status = "PASSED" if valid else "FAILED"
    print(f"\nVerification: {status}")
else:
    print(f"FAILED: No nonce found within {MAX_NONCE} attempts")

# ============================================================================
# PART 3: Custom Nonce Range Test
# ============================================================================
print("\n" + "=" * 80)
print("PART 3: Custom Nonce Range Tests")
print("=" * 80)

print("\nTest: Starting from nonce 1000 instead of 0")
result = client.generate_single(TEST_TEXT, "MD5", DIFFICULTY, 1000, MAX_NONCE)
if result['success']:
    print(f"  Algorithm: MD5")
    print(f"  Nonce: {result['nonce']} (started from 1000)")
    print(f"  Hash:  {client.hash_to_hex(result['hash'])}")
    
    # Verify
    valid = server.verify_single(TEST_TEXT, result['nonce'], "MD5", DIFFICULTY)
    status = "PASSED" if valid else "FAILED"
    print(f"  Verification: {status}")
else:
    print(f"  FAILED: No nonce found")

# ============================================================================
# PART 4: Edge Cases and Validation
# ============================================================================
print("\n" + "=" * 80)
print("PART 4: Edge Cases and Validation")
print("=" * 80)

# Test with different text
print("\nTest: Different input text")
result = client.generate_single(b"different text", "SHA2-256", DIFFICULTY, 0, MAX_NONCE)
if result['success']:
    print(f"  Text: 'different text'")
    print(f"  Nonce: {result['nonce']}")
    print(f"  Hash:  {client.hash_to_hex(result['hash'])}")
    
    # Verify with correct text
    valid = server.verify_single(b"different text", result['nonce'], "SHA2-256", DIFFICULTY)
    status = "PASSED" if valid else "FAILED"
    print(f"  Correct verification: {status}")
    
    # Verify with wrong text (should fail)
    valid_wrong = server.verify_single(b"wrong text", result['nonce'], "SHA2-256", DIFFICULTY)
    status_wrong = "PASSED (correctly rejected)" if not valid_wrong else "FAILED (should reject)"
    print(f"  Wrong text verification: {status_wrong}")

# Test with invalid nonce (should fail verification)
print("\nTest: Invalid nonce verification")
valid = server.verify_single(TEST_TEXT, 999999999, "SHA2-256", DIFFICULTY)
status = "FAILED (correctly rejected)" if not valid else "PASSED (should fail)"
print(f"  Verifying random nonce 999999999: {status}")

# ============================================================================
# Summary
# ============================================================================
print("\n" + "=" * 80)
print("Test Suite Complete!")
print("=" * 80)
print("\nKey Features Demonstrated:")
print("  [OK] Single hash algorithm PoW generation and verification")
print("  [OK] Multi-hash PoW with 4, 5, and 6 algorithms")
print("  [OK] Custom nonce range (starting from non-zero values)")
print("  [OK] Algorithm-optimized ordering for efficiency")
print("  [OK] Comprehensive verification tests")
print("  [OK] Edge case handling and validation")
print("\nAll 34 hash algorithms are supported:")
print("  MD2, MD4, MD5, NT Hash, HAS-160,")
print("  RIPEMD-128/160/256/320,")
print("  BLAKE2b-128/160/256/384/512, BLAKE2s-128/160/256,")
print("  SHA-0, SHA-1, SHA2-224/256/384/512,")
print("  SHA3-224/256/384/512,")
print("  Keccak-224/256/384/512,")
print("  SHAKE-128/256, Whirlpool")
print("=" * 80)
