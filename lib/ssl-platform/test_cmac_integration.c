/*
 * SSL Platform CMAC Integration Test
 * 
 * Copyright (c) 2024
 * 
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ssl_platform.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Simple test that validates our CMAC implementation matches expected results
int test_cmac_integration() {
    printf("=== SSL Platform CMAC Integration Test ===\n");
    
    // Test data (RFC 4493 test vector)
    const unsigned char key[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    
    const unsigned char input[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    
    const unsigned char expected[] = {
        0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
        0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c
    };
    
    unsigned char output[16];
    int ret;
    
    printf("Testing one-shot CMAC...\n");
    
    // Test one-shot CMAC
    ret = ssl_platform_aes_cmac(key, 128, input, sizeof(input), output);
    if (ret != SSL_PLATFORM_SUCCESS) {
        printf("ERROR: One-shot CMAC failed with error %d\n", ret);
        return 1;
    }
    
    printf("One-shot CMAC result: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", output[i]);
    }
    printf("\n");
    
    printf("Expected result:      ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", expected[i]);
    }
    printf("\n");
    
    if (memcmp(output, expected, 16) == 0) {
        printf("✓ One-shot CMAC test PASSED\n");
    } else {
        printf("✗ One-shot CMAC test FAILED\n");
        return 1;
    }
    
    printf("\nTesting streaming CMAC...\n");
    
    // Test streaming CMAC
    ssl_platform_cipher_context_t ctx;
    ssl_platform_cipher_init(&ctx);
    
    ret = ssl_platform_cipher_setup(&ctx, SSL_PLATFORM_CIPHER_AES_128_ECB);
    if (ret != SSL_PLATFORM_SUCCESS) {
        printf("ERROR: Cipher setup failed with error %d\n", ret);
        ssl_platform_cipher_free(&ctx);
        return 1;
    }
    
    ret = ssl_platform_cipher_cmac_starts(&ctx, key, 128);
    if (ret != SSL_PLATFORM_SUCCESS) {
        printf("ERROR: CMAC starts failed with error %d\n", ret);
        ssl_platform_cipher_free(&ctx);
        return 1;
    }
    
    ret = ssl_platform_cipher_cmac_update(&ctx, input, sizeof(input));
    if (ret != SSL_PLATFORM_SUCCESS) {
        printf("ERROR: CMAC update failed with error %d\n", ret);
        ssl_platform_cipher_free(&ctx);
        return 1;
    }
    
    memset(output, 0, sizeof(output));
    ret = ssl_platform_cipher_cmac_finish(&ctx, output);
    if (ret != SSL_PLATFORM_SUCCESS) {
        printf("ERROR: CMAC finish failed with error %d\n", ret);
        ssl_platform_cipher_free(&ctx);
        return 1;
    }
    
    ssl_platform_cipher_free(&ctx);
    
    printf("Streaming CMAC result: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", output[i]);
    }
    printf("\n");
    
    if (memcmp(output, expected, 16) == 0) {
        printf("✓ Streaming CMAC test PASSED\n");
    } else {
        printf("✗ Streaming CMAC test FAILED\n");
        return 1;
    }
    
    printf("\n=== All CMAC Integration Tests PASSED ===\n");
    return 0;
}

int main() {
    return test_cmac_integration();
} 