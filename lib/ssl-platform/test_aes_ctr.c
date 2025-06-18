#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "ssl_platform.h"

/* Test vectors for AES-128-CTR */
struct aes_ctr_test_vector {
    const char *description;
    unsigned char key[16];
    unsigned char nonce_counter[16];
    unsigned char plaintext[64];
    size_t plaintext_len;
    unsigned char expected_ciphertext[64];
};

/* NIST test vectors for AES-128-CTR */
static struct aes_ctr_test_vector test_vectors[] = {
    {
        "NIST AES-128-CTR Test Vector (verified)",
        {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
        {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff},
        {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a},
        16,
        {0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce}
    }
};

/* Helper function to print hex data */
static void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/* Test basic functionality */
static int test_basic_functionality(void) {
    printf("\n=== Testing Basic Functionality ===\n");
    
    ssl_platform_aes_context_t ctx;
    unsigned char key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
                            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    unsigned char nonce[16] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                               0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
    unsigned char stream[16] = {0};
    unsigned char plaintext[] = "Hello World!";
    unsigned char ciphertext[32] = {0};
    unsigned char decrypted[32] = {0};
    size_t nc_off = 0;
    
    // Initialize AES context
    ssl_platform_aes_init(&ctx);
    
    // Set encryption key
    int ret = ssl_platform_aes_setkey_enc(&ctx, key, 128);
    if (ret != SSL_PLATFORM_SUCCESS) {
        printf("FAIL: Failed to set encryption key: %d\n", ret);
        ssl_platform_aes_free(&ctx);
        return -1;
    }
    
    size_t len = strlen((char*)plaintext);
    
    // Test encryption
    unsigned char nonce_copy[16];
    memcpy(nonce_copy, nonce, 16);
    ret = ssl_platform_aes_crypt_ctr(&ctx, len, &nc_off, nonce_copy, stream, plaintext, ciphertext);
    if (ret != SSL_PLATFORM_SUCCESS) {
        printf("FAIL: Encryption failed: %d\n", ret);
        ssl_platform_aes_free(&ctx);
        return -1;
    }
    
    print_hex("Plaintext ", plaintext, len);
    print_hex("Ciphertext", ciphertext, len);
    
    // Test decryption (CTR mode is symmetric)
    memcpy(nonce_copy, nonce, 16);
    nc_off = 0;
    memset(stream, 0, 16);
    ret = ssl_platform_aes_crypt_ctr(&ctx, len, &nc_off, nonce_copy, stream, ciphertext, decrypted);
    if (ret != SSL_PLATFORM_SUCCESS) {
        printf("FAIL: Decryption failed: %d\n", ret);
        ssl_platform_aes_free(&ctx);
        return -1;
    }
    
    print_hex("Decrypted ", decrypted, len);
    
    // Verify decryption matches original plaintext
    if (memcmp(plaintext, decrypted, len) != 0) {
        printf("FAIL: Decrypted text doesn't match original plaintext\n");
        ssl_platform_aes_free(&ctx);
        return -1;
    }
    
    ssl_platform_aes_free(&ctx);
    printf("PASS: Basic functionality test passed\n");
    return 0;
}

/* Test with known test vectors */
static int test_known_vectors(void) {
    printf("\n=== Testing Known Vectors ===\n");
    
    int num_vectors = sizeof(test_vectors) / sizeof(test_vectors[0]);
    
    for (int i = 0; i < num_vectors; i++) {
        printf("\nTesting: %s\n", test_vectors[i].description);
        
        ssl_platform_aes_context_t ctx;
        ssl_platform_aes_init(&ctx);
        
        int ret = ssl_platform_aes_setkey_enc(&ctx, test_vectors[i].key, 128);
        if (ret != SSL_PLATFORM_SUCCESS) {
            printf("FAIL: Failed to set key for vector %d: %d\n", i, ret);
            ssl_platform_aes_free(&ctx);
            return -1;
        }
        
        unsigned char ciphertext[64] = {0};
        unsigned char nonce_copy[16];
        unsigned char stream[16] = {0};
        size_t nc_off = 0;
        
        memcpy(nonce_copy, test_vectors[i].nonce_counter, 16);
        
        ret = ssl_platform_aes_crypt_ctr(&ctx, test_vectors[i].plaintext_len, &nc_off, 
                                        nonce_copy, stream, test_vectors[i].plaintext, ciphertext);
        if (ret != SSL_PLATFORM_SUCCESS) {
            printf("FAIL: Encryption failed for vector %d: %d\n", i, ret);
            ssl_platform_aes_free(&ctx);
            return -1;
        }
        
        print_hex("Expected  ", test_vectors[i].expected_ciphertext, test_vectors[i].plaintext_len);
        print_hex("Actual    ", ciphertext, test_vectors[i].plaintext_len);
        
        if (memcmp(ciphertext, test_vectors[i].expected_ciphertext, test_vectors[i].plaintext_len) != 0) {
            printf("FAIL: Ciphertext doesn't match expected for vector %d\n", i);
            ssl_platform_aes_free(&ctx);
            return -1;
        }
        
        printf("PASS: Vector %d passed\n", i);
        ssl_platform_aes_free(&ctx);
    }
    
    return 0;
}

/* Test parameter validation */
static int test_parameter_validation(void) {
    printf("\n=== Testing Parameter Validation ===\n");
    
    ssl_platform_aes_context_t ctx;
    unsigned char key[16] = {0};
    unsigned char nonce[16] = {0};
    unsigned char stream[16] = {0};
    unsigned char input[16] = {0};
    unsigned char output[16] = {0};
    size_t nc_off = 0;
    
    ssl_platform_aes_init(&ctx);
    ssl_platform_aes_setkey_enc(&ctx, key, 128);
    
    // Test NULL context
    int ret = ssl_platform_aes_crypt_ctr(NULL, 16, &nc_off, nonce, stream, input, output);
    if (ret != SSL_PLATFORM_ERROR_INVALID_PARAMETER) {
        printf("FAIL: NULL context should return INVALID_PARAMETER, got %d\n", ret);
        ssl_platform_aes_free(&ctx);
        return -1;
    }
    
    // Test NULL nc_off
    ret = ssl_platform_aes_crypt_ctr(&ctx, 16, NULL, nonce, stream, input, output);
    if (ret != SSL_PLATFORM_ERROR_INVALID_PARAMETER) {
        printf("FAIL: NULL nc_off should return INVALID_PARAMETER, got %d\n", ret);
        ssl_platform_aes_free(&ctx);
        return -1;
    }
    
    // Test NULL nonce
    ret = ssl_platform_aes_crypt_ctr(&ctx, 16, &nc_off, NULL, stream, input, output);
    if (ret != SSL_PLATFORM_ERROR_INVALID_PARAMETER) {
        printf("FAIL: NULL nonce should return INVALID_PARAMETER, got %d\n", ret);
        ssl_platform_aes_free(&ctx);
        return -1;
    }
    
    // Test NULL stream
    ret = ssl_platform_aes_crypt_ctr(&ctx, 16, &nc_off, nonce, NULL, input, output);
    if (ret != SSL_PLATFORM_ERROR_INVALID_PARAMETER) {
        printf("FAIL: NULL stream should return INVALID_PARAMETER, got %d\n", ret);
        ssl_platform_aes_free(&ctx);
        return -1;
    }
    
    // Test NULL input
    ret = ssl_platform_aes_crypt_ctr(&ctx, 16, &nc_off, nonce, stream, NULL, output);
    if (ret != SSL_PLATFORM_ERROR_INVALID_PARAMETER) {
        printf("FAIL: NULL input should return INVALID_PARAMETER, got %d\n", ret);
        ssl_platform_aes_free(&ctx);
        return -1;
    }
    
    // Test NULL output
    ret = ssl_platform_aes_crypt_ctr(&ctx, 16, &nc_off, nonce, stream, input, NULL);
    if (ret != SSL_PLATFORM_ERROR_INVALID_PARAMETER) {
        printf("FAIL: NULL output should return INVALID_PARAMETER, got %d\n", ret);
        ssl_platform_aes_free(&ctx);
        return -1;
    }
    
    ssl_platform_aes_free(&ctx);
    printf("PASS: Parameter validation tests passed\n");
    return 0;
}

/* Test segmented encryption (multiple calls with partial blocks) */
static int test_segmented_encryption(void) {
    printf("\n=== Testing Segmented Encryption ===\n");
    
    ssl_platform_aes_context_t ctx;
    unsigned char key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
                            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    unsigned char nonce[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    unsigned char stream[16] = {0};
    unsigned char plaintext[] = "This is a longer message for testing segmented encryption!";
    size_t total_len = strlen((char*)plaintext);
    unsigned char ciphertext_full[128] = {0};
    unsigned char ciphertext_segmented[128] = {0};
    size_t nc_off = 0;
    
    ssl_platform_aes_init(&ctx);
    ssl_platform_aes_setkey_enc(&ctx, key, 128);
    
    // Full encryption in one call
    unsigned char nonce_copy[16];
    memcpy(nonce_copy, nonce, 16);
    int ret = ssl_platform_aes_crypt_ctr(&ctx, total_len, &nc_off, nonce_copy, stream, 
                                        (unsigned char*)plaintext, ciphertext_full);
    if (ret != SSL_PLATFORM_SUCCESS) {
        printf("FAIL: Full encryption failed: %d\n", ret);
        ssl_platform_aes_free(&ctx);
        return -1;
    }
    
    // Segmented encryption
    memcpy(nonce_copy, nonce, 16);
    memset(stream, 0, 16);
    nc_off = 0;
    
    size_t pos = 0;
    const size_t segment_size = 7; // Prime number to test partial block handling
    
    while (pos < total_len) {
        size_t chunk_len = (total_len - pos < segment_size) ? (total_len - pos) : segment_size;
        
        ret = ssl_platform_aes_crypt_ctr(&ctx, chunk_len, &nc_off, nonce_copy, stream,
                                        (unsigned char*)plaintext + pos, 
                                        ciphertext_segmented + pos);
        if (ret != SSL_PLATFORM_SUCCESS) {
            printf("FAIL: Segmented encryption failed at position %zu: %d\n", pos, ret);
            ssl_platform_aes_free(&ctx);
            return -1;
        }
        
        pos += chunk_len;
    }
    
    // Compare results
    if (memcmp(ciphertext_full, ciphertext_segmented, total_len) != 0) {
        printf("FAIL: Segmented encryption doesn't match full encryption\n");
        print_hex("Full      ", ciphertext_full, total_len);
        print_hex("Segmented ", ciphertext_segmented, total_len);
        ssl_platform_aes_free(&ctx);
        return -1;
    }
    
    ssl_platform_aes_free(&ctx);
    printf("PASS: Segmented encryption test passed\n");
    return 0;
}

int main(void) {
    printf("=== SSL Platform AES-CTR Test Suite ===\n");
    
    int tests_passed = 0;
    int tests_failed = 0;
    
    if (test_parameter_validation() == 0) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    if (test_basic_functionality() == 0) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    if (test_known_vectors() == 0) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    if (test_segmented_encryption() == 0) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    printf("\n=== Test Results ===\n");
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    
    if (tests_failed == 0) {
        printf("All tests PASSED!\n");
        return 0;
    } else {
        printf("Some tests FAILED!\n");
        return 1;
    }
} 