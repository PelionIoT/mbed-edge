/*
 * SSL Platform CMAC Operations Test
 * 
 * Copyright (c) 2024
 * 
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ssl_platform.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Test vectors for AES-CMAC (RFC 4493)
struct cmac_test_vector {
    const char *name;
    const unsigned char *key;
    size_t key_len;
    const unsigned char *message;
    size_t message_len;
    const unsigned char *expected_cmac;
    size_t cmac_len;
};

// Test vectors from RFC 4493
static const unsigned char test_key_128[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

static const unsigned char test_message_0[] = { };

static const unsigned char test_message_16[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
};

static const unsigned char test_message_40[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11
};

static const unsigned char test_message_64[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};

// Expected CMAC results from RFC 4493
static const unsigned char expected_cmac_0[] = {
    0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28,
    0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46
};

static const unsigned char expected_cmac_16[] = {
    0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
    0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c
};

static const unsigned char expected_cmac_40[] = {
    0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
    0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27
};

static const unsigned char expected_cmac_64[] = {
    0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
    0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe
};

static const struct cmac_test_vector test_vectors[] = {
    {
        "Empty message",
        test_key_128, 16,
        test_message_0, 0,
        expected_cmac_0, 16
    },
    {
        "16-byte message",
        test_key_128, 16,
        test_message_16, 16,
        expected_cmac_16, 16
    },
    {
        "40-byte message",
        test_key_128, 16,
        test_message_40, 40,
        expected_cmac_40, 16
    },
    {
        "64-byte message",
        test_key_128, 16,
        test_message_64, 64,
        expected_cmac_64, 16
    }
};

static const size_t num_test_vectors = sizeof(test_vectors) / sizeof(test_vectors[0]);

static void print_hex(const char *label, const unsigned char *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static int compare_results(const unsigned char *expected, const unsigned char *actual, size_t len)
{
    return memcmp(expected, actual, len) == 0;
}

static int test_one_shot_cmac(void)
{
    printf("\n=== Testing One-Shot CMAC Functions ===\n");
    int passed = 0;
    int total = 0;
    
    for (size_t i = 0; i < num_test_vectors; i++) {
        const struct cmac_test_vector *tv = &test_vectors[i];
        unsigned char output[16];
        int ret;
        
        printf("\nTest %zu: %s\n", i + 1, tv->name);
        
        // Test ssl_platform_aes_cmac
        ret = ssl_platform_aes_cmac(tv->key, tv->key_len, 
                                    tv->message, tv->message_len, 
                                    output);
        total++;
        
        if (ret == SSL_PLATFORM_SUCCESS) {
            if (compare_results(tv->expected_cmac, output, tv->cmac_len)) {
                printf("  ssl_platform_aes_cmac: PASS\n");
                passed++;
            } else {
                printf("  ssl_platform_aes_cmac: FAIL\n");
                print_hex("  Expected", tv->expected_cmac, tv->cmac_len);
                print_hex("  Got     ", output, tv->cmac_len);
            }
        } else {
            printf("  ssl_platform_aes_cmac: ERROR (ret=%d)\n", ret);
        }
        
        // Test ssl_platform_cipher_cmac
        ret = ssl_platform_cipher_cmac(SSL_PLATFORM_CIPHER_AES_128_ECB,
                                       tv->key, tv->key_len * 8,
                                       tv->message, tv->message_len,
                                       output);
        total++;
        
        if (ret == SSL_PLATFORM_SUCCESS) {
            if (compare_results(tv->expected_cmac, output, tv->cmac_len)) {
                printf("  ssl_platform_cipher_cmac: PASS\n");
                passed++;
            } else {
                printf("  ssl_platform_cipher_cmac: FAIL\n");
                print_hex("  Expected", tv->expected_cmac, tv->cmac_len);
                print_hex("  Got     ", output, tv->cmac_len);
            }
        } else {
            printf("  ssl_platform_cipher_cmac: ERROR (ret=%d)\n", ret);
        }
    }
    
    printf("\nOne-shot CMAC tests: %d/%d passed\n", passed, total);
    return passed == total;
}

static int test_streaming_cmac(void)
{
    printf("\n=== Testing Streaming CMAC Functions ===\n");
    int passed = 0;
    int total = 0;
    
    for (size_t i = 0; i < num_test_vectors; i++) {
        const struct cmac_test_vector *tv = &test_vectors[i];
        ssl_platform_cipher_context_t ctx;
        unsigned char output[16];
        int ret;
        
        printf("\nTest %zu: %s\n", i + 1, tv->name);
        
        // Initialize cipher context
        ssl_platform_cipher_init(&ctx);
        
        ret = ssl_platform_cipher_setup(&ctx, SSL_PLATFORM_CIPHER_AES_128_ECB);
        if (ret != SSL_PLATFORM_SUCCESS) {
            printf("  Setup failed: ERROR (ret=%d)\n", ret);
            ssl_platform_cipher_free(&ctx);
            total++;
            continue;
        }
        
        // Start CMAC
        ret = ssl_platform_cipher_cmac_starts(&ctx, tv->key, tv->key_len * 8);
        if (ret != SSL_PLATFORM_SUCCESS) {
            printf("  CMAC start failed: ERROR (ret=%d)\n", ret);
            ssl_platform_cipher_free(&ctx);
            total++;
            continue;
        }
        
        // Update CMAC (test with different chunk sizes)
        if (tv->message_len > 0) {
            if (tv->message_len <= 16) {
                // Single update
                ret = ssl_platform_cipher_cmac_update(&ctx, tv->message, tv->message_len);
            } else {
                // Multiple updates
                size_t remaining = tv->message_len;
                const unsigned char *data = tv->message;
                
                while (remaining > 0 && ret == SSL_PLATFORM_SUCCESS) {
                    size_t chunk_size = (remaining > 16) ? 16 : remaining;
                    ret = ssl_platform_cipher_cmac_update(&ctx, data, chunk_size);
                    data += chunk_size;
                    remaining -= chunk_size;
                }
            }
            
            if (ret != SSL_PLATFORM_SUCCESS) {
                printf("  CMAC update failed: ERROR (ret=%d)\n", ret);
                ssl_platform_cipher_free(&ctx);
                total++;
                continue;
            }
        }
        
        // Finish CMAC
        ret = ssl_platform_cipher_cmac_finish(&ctx, output);
        total++;
        
        if (ret == SSL_PLATFORM_SUCCESS) {
            if (compare_results(tv->expected_cmac, output, tv->cmac_len)) {
                printf("  Streaming CMAC: PASS\n");
                passed++;
            } else {
                printf("  Streaming CMAC: FAIL\n");
                print_hex("  Expected", tv->expected_cmac, tv->cmac_len);
                print_hex("  Got     ", output, tv->cmac_len);
            }
        } else {
            printf("  Streaming CMAC: ERROR (ret=%d)\n", ret);
        }
        
        ssl_platform_cipher_free(&ctx);
    }
    
    printf("\nStreaming CMAC tests: %d/%d passed\n", passed, total);
    return passed == total;
}

static int test_cipher_info_function(void)
{
    printf("\n=== Testing Cipher Info Function ===\n");
    
    const void *info = ssl_platform_cipher_info_from_type(SSL_PLATFORM_CIPHER_AES_128_ECB);
    if (info != NULL) {
        printf("ssl_platform_cipher_info_from_type(AES_128_ECB): PASS\n");
        return 1;
    } else {
        printf("ssl_platform_cipher_info_from_type(AES_128_ECB): FAIL\n");
        return 0;
    }
}

static int test_error_handling(void)
{
    printf("\n=== Testing Error Handling ===\n");
    int passed = 0;
    int total = 6;
    unsigned char output[16];
    
    // Test NULL parameter handling
    int ret = ssl_platform_aes_cmac(NULL, 16, test_message_16, 16, output);
    if (ret != SSL_PLATFORM_SUCCESS) {
        printf("NULL key test: PASS\n");
        passed++;
    } else {
        printf("NULL key test: FAIL\n");
    }
    
    ret = ssl_platform_aes_cmac(test_key_128, 16, NULL, 16, output);
    if (ret != SSL_PLATFORM_SUCCESS) {
        printf("NULL message test: PASS\n");
        passed++;
    } else {
        printf("NULL message test: FAIL\n");
    }
    
    ret = ssl_platform_aes_cmac(test_key_128, 16, test_message_16, 16, NULL);
    if (ret != SSL_PLATFORM_SUCCESS) {
        printf("NULL output test: PASS\n");
        passed++;
    } else {
        printf("NULL output test: FAIL\n");
    }
    
    // Test invalid key length
    ret = ssl_platform_aes_cmac(test_key_128, 15, test_message_16, 16, output);
    if (ret != SSL_PLATFORM_SUCCESS) {
        printf("Invalid key length test: PASS\n");
        passed++;
    } else {
        printf("Invalid key length test: FAIL\n");
    }
    
    // Test context operations with NULL
    ssl_platform_cipher_init(NULL);
    printf("NULL context init: PASS\n");
    passed++;
    
    ssl_platform_cipher_free(NULL);
    printf("NULL context free: PASS\n");
    passed++;
    
    printf("Error handling tests: %d/%d passed\n", passed, total);
    return passed == total;
}

int main(void)
{
    printf("SSL Platform CMAC Operations Test\n");
    printf("==================================\n");
    
#if SSL_PLATFORM_BACKEND == SSL_PLATFORM_BACKEND_MBEDTLS
    printf("Testing with mbed-TLS backend\n");
#elif SSL_PLATFORM_BACKEND == SSL_PLATFORM_BACKEND_OPENSSL
    printf("Testing with OpenSSL backend\n");
#else
    printf("Unknown SSL backend\n");
    return 1;
#endif
    
    int all_passed = 1;
    
    all_passed &= test_one_shot_cmac();
    all_passed &= test_streaming_cmac();
    all_passed &= test_cipher_info_function();
    all_passed &= test_error_handling();
    
    printf("\n=== Final Results ===\n");
    if (all_passed) {
        printf("All CMAC tests PASSED!\n");
        return 0;
    } else {
        printf("Some CMAC tests FAILED!\n");
        return 1;
    }
} 