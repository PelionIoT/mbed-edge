/*
 * SSL Platform Migration Example
 * 
 * This file demonstrates how to migrate from direct mbed-TLS usage
 * to the SSL platform abstraction layer.
 * 
 * Copyright (c) 2024
 * SPDX-License-Identifier: Apache-2.0
 */

/* =============================================================================
 * OPTION 1: DROP-IN REPLACEMENT (RECOMMENDED FOR EXISTING CODE)
 * =============================================================================
 * 
 * Simply replace the mbed-TLS include with the compatibility header.
 * No other code changes needed!
 */

// Before:
// #include "mbedtls/base64.h"

// After:
#include "ssl_platform_compat.h"

/* =============================================================================
 * EXAMPLE: PROTOCOL_API.C BASE64 ENCODING
 * =============================================================================
 * 
 * This is the exact code pattern from protocol_api.c line 1005
 */

void example_base64_encoding_from_protocol_api(void)
{
    // This is the exact code from protocol_api.c that will now work
    // with both mbed-TLS and OpenSSL backends
    
    unsigned char *request_value = (unsigned char *)"Hello, World!";
    size_t request_value_len = 13;
    size_t out_size = 0;
    
    // Original line 1005: int32_t ret_val = mbedtls_base64_encode(NULL, 0, &out_size, request_ctx->value, request_ctx->value_len);
    int32_t ret_val = mbedtls_base64_encode(NULL, 0, &out_size, request_value, request_value_len);
    
    if (0 != ret_val && MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL != ret_val) {
        // Error handling - same as original
        return;
    }
    
    unsigned char *json_value = NULL;
    if (out_size == 0) {
        // Allocate just an empty string. This signifies no data.
        json_value = (unsigned char *) calloc(1, 1);
    } else {
        json_value = (unsigned char *) calloc(1, out_size);
    }
    
    if (!json_value) {
        // Error handling
        return;
    }
    
    if (out_size != 0) {
        if (0 != mbedtls_base64_encode(json_value, out_size, &out_size, request_value, request_value_len)) {
            // Error handling - same as original
            free(json_value);
            return;
        }
    }
    
    // Use json_value as needed...
    printf("Encoded: %s\n", (char*)json_value);
    
    free(json_value);
}

/* =============================================================================
 * OPTION 2: NEW SSL PLATFORM API (RECOMMENDED FOR NEW CODE)
 * =============================================================================
 * 
 * For new code, you can use the SSL platform API directly
 */

#include "ssl_platform.h"

void example_new_ssl_platform_api(void)
{
    unsigned char input[] = "Hello, SSL Platform!";
    unsigned char output[64];
    size_t output_len;
    
    int ret = ssl_platform_base64_encode(output, sizeof(output), &output_len, 
                                        input, strlen((char*)input));
    if (ret == SSL_PLATFORM_SUCCESS) {
        printf("Encoded: %.*s\n", (int)output_len, output);
    }
}

/* =============================================================================
 * OPTION 3: MIXED USAGE
 * =============================================================================
 * 
 * You can also mix both approaches in the same file
 */

void example_mixed_usage(void)
{
    // Use compatibility macros for existing mbed-TLS code
    size_t out_size = 0;
    mbedtls_base64_encode(NULL, 0, &out_size, (unsigned char*)"test", 4);
    
    // Use new SSL platform API for new code
    ssl_platform_hash_context_t hash_ctx;
    unsigned char hash_output[32];
    
    ssl_platform_hash_init(&hash_ctx, SSL_PLATFORM_HASH_SHA256);
    ssl_platform_hash_starts(&hash_ctx);
    ssl_platform_hash_update(&hash_ctx, (unsigned char*)"test", 4);
    ssl_platform_hash_finish(&hash_ctx, hash_output);
    ssl_platform_hash_free(&hash_ctx);
}

/* =============================================================================
 * MIGRATION STRATEGY FOR PROTOCOL_API.C
 * =============================================================================
 * 
 * To migrate protocol_api.c:
 * 
 * 1. Replace: #include "mbedtls/base64.h"
 *    With:    #include "ssl_platform_compat.h"
 * 
 * 2. No other code changes needed!
 * 
 * 3. To switch backends, just change SSL_PLATFORM_BACKEND:
 *    cmake -DSSL_PLATFORM_BACKEND=1 ..  # mbed-TLS
 *    cmake -DSSL_PLATFORM_BACKEND=2 ..  # OpenSSL
 * 
 * 4. All existing function calls like mbedtls_base64_encode() will
 *    automatically use the selected backend.
 */ 