"""
Proof-of-Work Client Utilities
Provides helper functions for generating PoW with multiple hash algorithms
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

# Optimized order for multi-hash PoW (fastest to slowest)
OPTIMIZED_ORDER = [
    'MD4', 'NT', 'MD5', 'HAS-160',
    'RIPEMD-256', 'RIPEMD-128',
    'BLAKE2s-128', 'BLAKE2s-160', 'BLAKE2s-256',
    'BLAKE2b-512', 'RIPEMD-320',
    'BLAKE2b-128', 'BLAKE2b-384', 'RIPEMD-160',
    'BLAKE2b-160', 'BLAKE2b-256',
    'SHA2-256', 'SHA-0', 'SHA-1', 'SHA2-224',
    'SHA2-512', 'SHA2-384',
    'Whirlpool',
    'SHA3-224', 'SHAKE-256', 'SHA3-384',
    'SHAKE-128', 'Keccak-384', 'Keccak-256',
    'SHA3-256', 'SHA3-512', 'Keccak-512', 'Keccak-224',
    'MD2'
]

# Result structures
class PoWResult(ctypes.Structure):
    _fields_ = [
        ("nonce", ctypes.c_int),
        ("hash", ctypes.c_ubyte * 128),
        ("hash_size", ctypes.c_int)
    ]

class MultiPoWResult(ctypes.Structure):
    _fields_ = [
        ("nonce", ctypes.c_int),
        ("hashes", (ctypes.c_ubyte * 128) * 10),
        ("hash_sizes", ctypes.c_int * 10),
        ("num_hashes", ctypes.c_int)
    ]

class PoWClient:
    def __init__(self, dll_path):
        """Initialize the PoW client with the DLL"""
        if not os.path.exists(dll_path):
            raise FileNotFoundError(f"Client DLL not found at {dll_path}")
        
        self.client = ctypes.CDLL(dll_path)
        
        # Setup function signatures for single hash
        self.client.generate_pow_single.argtypes = [
            ctypes.c_char_p,  # input
            ctypes.c_int,     # algo
            ctypes.c_int,     # difficulty
            ctypes.c_int,     # min_nonce
            ctypes.c_int      # max_nonce
        ]
        self.client.generate_pow_single.restype = PoWResult
        
        # Setup function signatures for multi hash
        self.client.generate_pow_multi.argtypes = [
            ctypes.c_char_p,           # input
            ctypes.POINTER(ctypes.c_int),  # algos array
            ctypes.c_int,              # num_algos
            ctypes.c_int,              # difficulty
            ctypes.c_int,              # min_nonce
            ctypes.c_int               # max_nonce
        ]
        self.client.generate_pow_multi.restype = MultiPoWResult
    
    def generate_single(self, text, algo_name, difficulty, min_nonce=0, max_nonce=1000000000):
        """
        Generate PoW for a single hash algorithm
        
        Args:
            text: Input text (string or bytes)
            algo_name: Hash algorithm name (e.g., 'SHA2-256', 'MD5')
            difficulty: Number of leading zero bits required
            min_nonce: Starting nonce value
            max_nonce: Maximum nonce to try
        
        Returns:
            dict with 'nonce', 'hash', 'hash_size', 'success'
        """
        if isinstance(text, str):
            text = text.encode('utf-8')
        
        if algo_name not in HASH_ALGORITHMS:
            raise ValueError(f"Unknown algorithm: {algo_name}")
        
        algo_id = HASH_ALGORITHMS[algo_name]
        result = self.client.generate_pow_single(text, algo_id, difficulty, min_nonce, max_nonce)
        
        return {
            'nonce': result.nonce,
            'hash': bytes(result.hash[:result.hash_size]),
            'hash_size': result.hash_size,
            'success': result.nonce != -1,
            'algorithm': algo_name
        }
    
    def generate_multi(self, text, algo_names, difficulty, min_nonce=0, max_nonce=1000000000):
        """
        Generate PoW for multiple hash algorithms (all must satisfy difficulty)
        
        Args:
            text: Input text (string or bytes)
            algo_names: List of hash algorithm names
            difficulty: Number of leading zero bits required for ALL hashes
            min_nonce: Starting nonce value
            max_nonce: Maximum nonce to try
        
        Returns:
            dict with 'nonce', 'hashes', 'hash_sizes', 'success', 'algorithms'
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
        
        result = self.client.generate_pow_multi(
            text, algos_array, len(algo_ids), difficulty, min_nonce, max_nonce
        )
        
        hashes = []
        hash_sizes = []
        for i in range(result.num_hashes):
            size = result.hash_sizes[i]
            hashes.append(bytes(result.hashes[i][:size]))
            hash_sizes.append(size)
        
        return {
            'nonce': result.nonce,
            'hashes': hashes,
            'hash_sizes': hash_sizes,
            'success': result.nonce != -1,
            'algorithms': algo_names
        }
    
    @staticmethod
    def hash_to_hex(hash_bytes):
        """Convert hash bytes to hex string"""
        return ''.join(f'{b:02x}' for b in hash_bytes)
    
    @staticmethod
    def get_optimized_algos(count):
        """Get the first N algorithms from optimized order"""
        if count > len(OPTIMIZED_ORDER):
            count = len(OPTIMIZED_ORDER)
        return OPTIMIZED_ORDER[:count]


def create_multi_pow_challenge(algo_count, difficulty=12):
    """
    Helper to create a multi-hash PoW challenge with optimal algorithm selection
    
    Args:
        algo_count: Number of algorithms to use (2-6 recommended)
        difficulty: Difficulty level (bits of leading zeros)
    
    Returns:
        List of algorithm names in optimized order
    """
    if algo_count < 2:
        algo_count = 2
    if algo_count > 6:
        algo_count = 6
    
    return PoWClient.get_optimized_algos(algo_count)


# Example usage
if __name__ == "__main__":
    client = PoWClient()
    
    # Single hash example
    print("=" * 60)
    print("Single Hash PoW Example")
    print("=" * 60)
    result = client.generate_single("hello world", "SHA2-256", 12)
    if result['success']:
        print(f"Algorithm: {result['algorithm']}")
        print(f"Nonce: {result['nonce']}")
        print(f"Hash: {client.hash_to_hex(result['hash'])}")
    else:
        print("Failed to find nonce")
    
    # Multi hash example
    print("\n" + "=" * 60)
    print("Multi-Hash PoW Example (4 algorithms)")
    print("=" * 60)
    algos = create_multi_pow_challenge(4, difficulty=12)
    print(f"Algorithms: {', '.join(algos)}")
    result = client.generate_multi("hello world", algos, 12, max_nonce=100000000)
    if result['success']:
        print(f"Nonce: {result['nonce']}")
        for i, algo in enumerate(result['algorithms']):
            print(f"{algo:15} : {client.hash_to_hex(result['hashes'][i])}")
    else:
        print("Failed to find nonce")
