"""
Proof-of-Work Server Utilities
Provides helper functions for verifying PoW with multiple hash algorithms
"""

import ctypes
import os

# Hash algorithm enumeration (must match C code)
HASH_ALGORITHMS = {
    'MD4': 0, 'NT': 1, 'MD5': 2, 'HAS-160': 3,
    'RIPEMD-256': 4, 'RIPEMD-128': 5,
    'BLAKE2s-128': 6, 'BLAKE2s-160': 7, 'BLAKE2s-256': 8,
    'BLAKE2b-512': 9, 'RIPEMD-320': 10,
    'BLAKE2b-128': 11, 'BLAKE2b-384': 12, 'RIPEMD-160': 13,
    'BLAKE2b-160': 14, 'BLAKE2b-256': 15,
    'SHA2-256': 16, 'SHA-0': 17, 'SHA-1': 18, 'SHA2-224': 19,
    'SHA2-512': 20, 'SHA2-384': 21,
    'Whirlpool': 22,
    'SHA3-224': 23, 'SHAKE-256': 24, 'SHA3-384': 25,
    'SHAKE-128': 26, 'Keccak-384': 27, 'Keccak-256': 28,
    'SHA3-256': 29, 'SHA3-512': 30, 'Keccak-512': 31, 'Keccak-224': 32,
    'MD2': 33
}

class PoWServer:
    def __init__(self, dll_path):
        """Initialize the PoW server with the DLL"""
        if not os.path.exists(dll_path):
            raise FileNotFoundError(f"Server DLL not found at {dll_path}")
        
        try:
            self.server = ctypes.CDLL(dll_path)
        except OSError as e:
            raise OSError(
                f"Failed to load Server DLL from {dll_path}\n"
                f"Error: {e}\n"
                f"Possible causes:\n"
                f"  - DLL is corrupted or not compiled\n"
                f"  - Architecture mismatch (32-bit vs 64-bit)\n"
                f"  - Missing dependencies\n"
                f"  - File is not a valid Windows DLL"
            ) from e
        
        # Setup function signatures for single hash verification
        self.server.verify_pow_single.argtypes = [
            ctypes.c_char_p,  # input
            ctypes.c_int,     # nonce
            ctypes.c_int,     # algo
            ctypes.c_int      # difficulty
        ]
        self.server.verify_pow_single.restype = ctypes.c_int
        
        # Setup function signatures for multi hash verification
        self.server.verify_pow_multi.argtypes = [
            ctypes.c_char_p,           # input
            ctypes.c_int,              # nonce
            ctypes.POINTER(ctypes.c_int),  # algos array
            ctypes.c_int,              # num_algos
            ctypes.c_int               # difficulty
        ]
        self.server.verify_pow_multi.restype = ctypes.c_int
    
    def verify_single(self, text, nonce, algo_name, difficulty):
        """
        Verify PoW for a single hash algorithm
        
        Args:
            text: Input text (string or bytes)
            nonce: The nonce to verify
            algo_name: Hash algorithm name (e.g., 'SHA2-256', 'MD5')
            difficulty: Number of leading zero bits required
        
        Returns:
            bool: True if valid, False otherwise
        """
        if isinstance(text, str):
            text = text.encode('utf-8')
        
        if algo_name not in HASH_ALGORITHMS:
            raise ValueError(f"Unknown algorithm: {algo_name}")
        
        algo_id = HASH_ALGORITHMS[algo_name]
        result = self.server.verify_pow_single(text, nonce, algo_id, difficulty)
        
        return result == 1
    
    def verify_multi(self, text, nonce, algo_names, difficulty):
        """
        Verify PoW for multiple hash algorithms (all must satisfy difficulty)
        
        Args:
            text: Input text (string or bytes)
            nonce: The nonce to verify
            algo_names: List of hash algorithm names
            difficulty: Number of leading zero bits required for ALL hashes
        
        Returns:
            bool: True if all hashes are valid, False otherwise
        """
        if isinstance(text, str):
            text = text.encode('utf-8')
        
        if len(algo_names) > 10:
            raise ValueError("Maximum 10 algorithms supported")
        
        # Convert algorithm names to IDs
        algo_ids = []
        for name in algo_names:
            if name not in HASH_ALGORITHMS:
                raise ValueError(f"Unknown algorithm: {name}")
            algo_ids.append(HASH_ALGORITHMS[name])
        
        # Create C array
        algos_array = (ctypes.c_int * len(algo_ids))(*algo_ids)
        
        result = self.server.verify_pow_multi(
            text, nonce, algos_array, len(algo_ids), difficulty
        )
        
        return result == 1
    
    def verify_challenge(self, challenge_data):
        """
        Verify a PoW challenge from standardized format
        
        Args:
            challenge_data: Dictionary with keys:
                - text: Input text
                - nonce: Nonce value
                - algorithms: List of algorithm names or single algorithm
                - difficulty: Difficulty level
        
        Returns:
            bool: True if valid, False otherwise
        """
        text = challenge_data['text']
        nonce = challenge_data['nonce']
        algos = challenge_data['algorithms']
        difficulty = challenge_data['difficulty']
        
        if isinstance(algos, str):
            # Single algorithm
            return self.verify_single(text, nonce, algos, difficulty)
        elif isinstance(algos, list):
            # Multiple algorithms
            return self.verify_multi(text, nonce, algos, difficulty)
        else:
            raise ValueError("algorithms must be a string or list")


# Example usage
if __name__ == "__main__":
    # Get the DLL path (same logic as main.py)
    from pathlib import Path
    BASE_DIR = Path(__file__).parent.parent
    BIN_PATH = BASE_DIR / "bin" / "win" / "64" / "dll"
    SERVER_DLL = str(BIN_PATH / "server.dll")
    
    try:
        server = PoWServer(SERVER_DLL)
    except (FileNotFoundError, OSError) as e:
        print(f"ERROR: {e}")
        import sys
        sys.exit(1)
    
    # Example single hash verification
    print("=" * 60)
    print("Single Hash Verification Example")
    print("=" * 60)
    
    # Test data (replace with actual values from client)
    test_text = "hello world"
    test_nonce = 12345  # This would come from the client
    test_algo = "SHA2-256"
    test_difficulty = 12
    
    valid = server.verify_single(test_text, test_nonce, test_algo, test_difficulty)
    print(f"Text: {test_text}")
    print(f"Nonce: {test_nonce}")
    print(f"Algorithm: {test_algo}")
    print(f"Difficulty: {test_difficulty}")
    print(f"Valid: {valid}")
    
    # Example multi hash verification
    print("\n" + "=" * 60)
    print("Multi-Hash Verification Example")
    print("=" * 60)
    
    test_algos = ["MD4", "NT", "MD5", "HAS-160"]
    valid = server.verify_multi(test_text, test_nonce, test_algos, test_difficulty)
    print(f"Text: {test_text}")
    print(f"Nonce: {test_nonce}")
    print(f"Algorithms: {', '.join(test_algos)}")
    print(f"Difficulty: {test_difficulty}")
    print(f"Valid: {valid}")
    
    # Example using challenge format
    print("\n" + "=" * 60)
    print("Challenge Format Verification Example")
    print("=" * 60)
    
    challenge = {
        'text': test_text,
        'nonce': test_nonce,
        'algorithms': test_algos,
        'difficulty': test_difficulty
    }
    
    valid = server.verify_challenge(challenge)
    print(f"Challenge: {challenge}")
    print(f"Valid: {valid}")
