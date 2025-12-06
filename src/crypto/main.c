#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

// Include all hash headers
#include "crypto/md2/md2.h"
#include "crypto/md4/md4.h"
#include "crypto/md5/md5.h"
#include "crypto/sha0/sha0.h"
#include "crypto/sha1/sha1.h"
#include "crypto/sha224/sha224.h"
#include "crypto/sha256/sha256.h"
#include "crypto/sha512/sha512.h"
#include "crypto/sha3/sha3.h"
#include "crypto/sha3_224/sha3_224.h"
#include "crypto/sha3_384/sha3_384.h"
#include "crypto/keccak/keccak.h"
#include "crypto/shake/shake.h"
#include "crypto/ripemd/ripemd160.h"
#include "crypto/ripemd128/ripemd128.h"
#include "crypto/ripemd256/ripemd256.h"
#include "crypto/ripemd320/ripemd320.h"
#include "crypto/blake2b/blake2b.h"
#include "crypto/blake2s/blake2s.h"
#include "crypto/whirlpool/whirlpool.h"
#include "crypto/has160/has160.h"
#include "crypto/nt/nt.h"

#define NUM_THREADS 24
#define BENCHMARK_DURATION 10
#define TEST_DATA "Hello World"

typedef enum {
    HASH_MD2, HASH_MD4, HASH_MD5,
    HASH_SHA0, HASH_SHA1,
    HASH_SHA224, HASH_SHA256, HASH_SHA384, HASH_SHA512,
    HASH_SHA3_224, HASH_SHA3_256, HASH_SHA3_384, HASH_SHA3_512,
    HASH_KECCAK224, HASH_KECCAK256, HASH_KECCAK384, HASH_KECCAK512,
    HASH_SHAKE128, HASH_SHAKE256,
    HASH_RIPEMD128, HASH_RIPEMD160, HASH_RIPEMD256, HASH_RIPEMD320,
    HASH_BLAKE2B_128, HASH_BLAKE2B_160, HASH_BLAKE2B_256, HASH_BLAKE2B_384, HASH_BLAKE2B_512,
    HASH_BLAKE2S_128, HASH_BLAKE2S_160, HASH_BLAKE2S_256,
    HASH_WHIRLPOOL, HASH_HAS160, HASH_NT,
    HASH_COUNT
} HashAlgorithm;

const char* hash_names[] = {
    "MD2", "MD4", "MD5",
    "SHA-0", "SHA-1",
    "SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512",
    "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512",
    "Keccak-224", "Keccak-256", "Keccak-384", "Keccak-512",
    "SHAKE-128", "SHAKE-256",
    "RIPEMD-128", "RIPEMD-160", "RIPEMD-256", "RIPEMD-320",
    "BLAKE2b-128", "BLAKE2b-160", "BLAKE2b-256", "BLAKE2b-384", "BLAKE2b-512",
    "BLAKE2s-128", "BLAKE2s-160", "BLAKE2s-256",
    "Whirlpool", "HAS-160", "NT Hash"
};

typedef struct {
    HashAlgorithm algo;
    volatile int running;
    uint64_t counts[BENCHMARK_DURATION];
    int thread_id;
} ThreadData;

void compute_hash(HashAlgorithm algo, const uint8_t *data, size_t len) {
    uint8_t digest[128]; // Max digest size
    
    switch(algo) {
        case HASH_MD2: md2_hash(data, len, digest); break;
        case HASH_MD4: md4_hash(data, len, digest); break;
        case HASH_MD5: md5_hash(data, len, digest); break;
        case HASH_SHA0: sha0_hash(data, len, digest); break;
        case HASH_SHA1: sha1_hash(data, len, digest); break;
        case HASH_SHA224: sha224_hash(data, len, digest); break;
        case HASH_SHA256: sha256(data, len, digest); break;
        case HASH_SHA384: sha384_hash(data, len, digest); break;
        case HASH_SHA512: sha512_hash(data, len, digest); break;
        case HASH_SHA3_224: sha3_224_hash(data, len, digest); break;
        case HASH_SHA3_256: sha3_256_hash(data, len, digest); break;
        case HASH_SHA3_384: sha3_384_hash(data, len, digest); break;
        case HASH_SHA3_512: sha3_512_hash(data, len, digest); break;
        case HASH_KECCAK224: keccak_224_hash(data, len, digest); break;
        case HASH_KECCAK256: keccak_256_hash(data, len, digest); break;
        case HASH_KECCAK384: keccak_384_hash(data, len, digest); break;
        case HASH_KECCAK512: keccak_512_hash(data, len, digest); break;
        case HASH_SHAKE128: shake128_hash(data, len, digest, 32); break;
        case HASH_SHAKE256: shake256_hash(data, len, digest, 64); break;
        case HASH_RIPEMD128: ripemd128_hash(data, len, digest); break;
        case HASH_RIPEMD160: ripemd160_hash(data, len, digest); break;
        case HASH_RIPEMD256: ripemd256_hash(data, len, digest); break;
        case HASH_RIPEMD320: ripemd320_hash(data, len, digest); break;
        case HASH_BLAKE2B_128: blake2b_128_hash(data, len, digest); break;
        case HASH_BLAKE2B_160: blake2b_160_hash(data, len, digest); break;
        case HASH_BLAKE2B_256: blake2b_256_hash(data, len, digest); break;
        case HASH_BLAKE2B_384: blake2b_384_hash(data, len, digest); break;
        case HASH_BLAKE2B_512: blake2b_512_hash(data, len, digest); break;
        case HASH_BLAKE2S_128: blake2s_128_hash(data, len, digest); break;
        case HASH_BLAKE2S_160: blake2s_160_hash(data, len, digest); break;
        case HASH_BLAKE2S_256: blake2s_256_hash(data, len, digest); break;
        case HASH_WHIRLPOOL: whirlpool_hash(data, len, digest); break;
        case HASH_HAS160: has160_hash(data, len, digest); break;
        case HASH_NT: nt_hash((const char *)data, digest); break;
        default: break;
    }
}

void* benchmark_thread(void *arg) {
    ThreadData *td = (ThreadData *)arg;
    const uint8_t *data = (const uint8_t *)TEST_DATA;
    size_t len = strlen(TEST_DATA);
    
    time_t start = time(NULL);
    time_t current_second = 0;
    uint64_t local_count = 0;
    
    while (td->running) {
        compute_hash(td->algo, data, len);
        local_count++;
        
        time_t now = time(NULL);
        time_t elapsed = now - start;
        
        if (elapsed != current_second && elapsed < BENCHMARK_DURATION) {
            td->counts[current_second] = local_count;
            local_count = 0;
            current_second = elapsed;
        }
    }
    
    // Save last second's count
    if (current_second < BENCHMARK_DURATION) {
        td->counts[current_second] = local_count;
    }
    
    return NULL;
}

void benchmark_algorithm(HashAlgorithm algo) {
    pthread_t threads[NUM_THREADS];
    ThreadData thread_data[NUM_THREADS];
    
    // Initialize thread data
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_data[i].algo = algo;
        thread_data[i].running = 1;
        thread_data[i].thread_id = i;
        memset((void*)thread_data[i].counts, 0, sizeof(thread_data[i].counts));
    }
    
    // Start threads
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_create(&threads[i], NULL, benchmark_thread, &thread_data[i]);
    }
    
    // Run for BENCHMARK_DURATION seconds
    sleep(BENCHMARK_DURATION);
    
    // Stop threads
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_data[i].running = 0;
    }
    
    // Wait for threads to finish
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    
    // Calculate and print results
    printf("%-14s", hash_names[algo]);
    
    uint64_t total_per_second[BENCHMARK_DURATION] = {0};
    uint64_t sum = 0;
    uint64_t min = UINT64_MAX;
    uint64_t max = 0;
    
    // Aggregate counts from all threads
    for (int sec = 0; sec < BENCHMARK_DURATION; sec++) {
        for (int t = 0; t < NUM_THREADS; t++) {
            total_per_second[sec] += thread_data[t].counts[sec];
        }
        
        printf(" | %10lu", total_per_second[sec]);
        sum += total_per_second[sec];
        
        if (total_per_second[sec] < min) min = total_per_second[sec];
        if (total_per_second[sec] > max) max = total_per_second[sec];
    }
    
    uint64_t avg = sum / BENCHMARK_DURATION;
    printf(" | %10lu | %10lu | %10lu\n", avg, min, max);
}

void run_benchmark() {
    printf("\n");
    printf("=================================================================================\n");
    printf("Hash Algorithm Benchmark - %d threads, %d seconds per algorithm\n", NUM_THREADS, BENCHMARK_DURATION);
    printf("Test data: \"%s\"\n", TEST_DATA);
    printf("=================================================================================\n\n");
    
    printf("--------------");
    for (int i = 0; i < BENCHMARK_DURATION; i++) {
        printf("-+-----------");
    }
    printf("-+------------+------------+-----------\n");

    // Print header
    printf("%-14s", "Algorithm");
    for (int i = 0; i < BENCHMARK_DURATION; i++) {
        printf(" | Sec %-6d", i + 1);
    }
    printf(" | %-10s | %-10s | %-10s\n", "Average", "Min", "Max");
    
    printf("--------------");
    for (int i = 0; i < BENCHMARK_DURATION; i++) {
        printf("-+-----------");
    }
    printf("-+------------+------------+-----------\n");
    
    // Benchmark each algorithm
    for (int algo = 0; algo < HASH_COUNT; algo++) {
        benchmark_algorithm((HashAlgorithm)algo);
    }
    
    printf("=================================================================================\n");
    printf("Benchmark complete! (All values are hashes per second)\n");
}

int main() {
    printf("Starting hash algorithm benchmark...\n");
    run_benchmark();
    return 0;
}