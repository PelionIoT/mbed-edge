# SSL Platform Abstraction Layer

The SSL Platform Abstraction Layer provides a unified API for cryptographic and SSL/TLS operations that can switch between different backends (mbed-TLS and OpenSSL) with minimal code changes.

## Purpose

This library was created to enable easy migration from mbed-TLS to OpenSSL in the mbed-edge project while maintaining compatibility and allowing gradual transition. It provides:

- Unified API for common cryptographic operations
- Seamless backend switching via compile-time configuration
- Consistent error codes and return values
- Zero-cost abstractions with minimal overhead

## Supported Backends

### 1. mbed-TLS Backend (Default)
- Based on mbed-TLS 2.28.x
- Suitable for embedded systems
- Smaller memory footprint
- Configured with `SSL_PLATFORM_BACKEND=1`

### 2. OpenSSL Backend
- Based on OpenSSL 1.1.0+ or 3.0+
- Full-featured cryptographic library
- Optimized for performance
- Configured with `SSL_PLATFORM_BACKEND=2`

## Supported Operations

### Base64 Encoding/Decoding
- `ssl_platform_base64_encode()`
- `ssl_platform_base64_decode()`

### Hash Operations
- SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, MD5
- `ssl_platform_hash_init()`
- `ssl_platform_hash_starts()`
- `ssl_platform_hash_update()`
- `ssl_platform_hash_finish()`
- `ssl_platform_hash_free()`

### AES Operations
- ECB mode encryption/decryption
- Key sizes: 128, 192, 256 bits
- `ssl_platform_aes_init()`
- `ssl_platform_aes_setkey_enc()`
- `ssl_platform_aes_setkey_dec()`
- `ssl_platform_aes_crypt_ecb()`
- `ssl_platform_aes_free()`

### Public Key Operations
- Key parsing (PEM/DER formats)
- `ssl_platform_pk_init()`
- `ssl_platform_pk_parse_key()`
- `ssl_platform_pk_parse_public_key()`
- `ssl_platform_pk_free()`

### X.509 Certificate Operations
- Certificate parsing and validation
- `ssl_platform_x509_crt_init()`
- `ssl_platform_x509_crt_parse()`
- `ssl_platform_x509_crt_free()`

### Random Number Generation
- Entropy collection and PRNG
- `ssl_platform_entropy_init()`
- `ssl_platform_ctr_drbg_init()`
- `ssl_platform_ctr_drbg_seed()`
- `ssl_platform_ctr_drbg_random()`

### SSL/TLS Operations
- SSL context and configuration management
- Server Name Indication (SNI) support
- `ssl_platform_ssl_init()`
- `ssl_platform_ssl_config_init()`
- `ssl_platform_ssl_set_hostname()` - Set hostname for SNI

## Usage

### Basic Example

```c
#include "ssl_platform.h"

int main() {
    // Base64 encoding example
    unsigned char input[] = "Hello, World!";
    unsigned char output[64];
    size_t output_len;
    
    int ret = ssl_platform_base64_encode(output, sizeof(output), &output_len, 
                                        input, strlen((char*)input));
    if (ret == SSL_PLATFORM_SUCCESS) {
        printf("Encoded: %.*s\n", (int)output_len, output);
    }
    
    // Hash example
    ssl_platform_hash_context_t hash_ctx;
    unsigned char hash_output[32];
    
    ssl_platform_hash_init(&hash_ctx, SSL_PLATFORM_HASH_SHA256);
    ssl_platform_hash_starts(&hash_ctx);
    ssl_platform_hash_update(&hash_ctx, input, strlen((char*)input));
    ssl_platform_hash_finish(&hash_ctx, hash_output);
    ssl_platform_hash_free(&hash_ctx);
    
    return 0;
}
```

### AES Encryption Example

```c
#include "ssl_platform.h"

void aes_example() {
    ssl_platform_aes_context_t aes_ctx;
    unsigned char key[16] = {0}; // 128-bit key
    unsigned char plaintext[16] = "Hello AES!      ";
    unsigned char ciphertext[16];
    unsigned char decrypted[16];
    
    // Initialize and set encryption key
    ssl_platform_aes_init(&aes_ctx);
    ssl_platform_aes_setkey_enc(&aes_ctx, key, 128);
    
    // Encrypt
    ssl_platform_aes_crypt_ecb(&aes_ctx, SSL_PLATFORM_AES_ENCRYPT, 
                              plaintext, ciphertext);
    
    // Set decryption key and decrypt
    ssl_platform_aes_setkey_dec(&aes_ctx, key, 128);
    ssl_platform_aes_crypt_ecb(&aes_ctx, SSL_PLATFORM_AES_DECRYPT, 
                              ciphertext, decrypted);
    
    ssl_platform_aes_free(&aes_ctx);
}
```

### SSL/TLS SNI Example

```c
#include "ssl_platform.h"

void ssl_sni_example() {
    ssl_platform_ssl_context_t ssl_ctx;
    ssl_platform_ssl_config_t ssl_conf;
    
    // Initialize SSL context and configuration
    ssl_platform_ssl_init(&ssl_ctx);
    ssl_platform_ssl_config_init(&ssl_conf);
    
    // Set configuration defaults for client
    ssl_platform_ssl_config_defaults(&ssl_conf, SSL_PLATFORM_SSL_IS_CLIENT, 
                                     SSL_PLATFORM_SSL_TRANSPORT_STREAM, 
                                     SSL_PLATFORM_SSL_PRESET_DEFAULT);
    
    // Apply configuration to context
    ssl_platform_ssl_setup(&ssl_ctx, &ssl_conf);
    
    // Set hostname for SNI - critical for many servers
    int ret = ssl_platform_ssl_set_hostname(&ssl_ctx, "bootstrap.us-east-1.mbedcloud.com");
    if (ret != SSL_PLATFORM_SUCCESS) {
        printf("Failed to set hostname for SNI: %d\n", ret);
    }
    
    // Alternatively, use compatibility macro
    // mbedtls_ssl_set_hostname(&ssl_ctx, "bootstrap.us-east-1.mbedcloud.com");
    
    // ... continue with SSL connection setup ...
    
    ssl_platform_ssl_free(&ssl_ctx);
    ssl_platform_ssl_config_free(&ssl_conf);
}
```

## Configuration

### Backend Selection

#### Using CMake
```bash
# Use mbed-TLS backend (default)
cmake -DSSL_PLATFORM_BACKEND=1 ..

# Use OpenSSL backend
cmake -DSSL_PLATFORM_BACKEND=2 ..
```

#### Using Preprocessor Defines
```c
// Before including ssl_platform.h
#define SSL_PLATFORM_BACKEND SSL_PLATFORM_BACKEND_OPENSSL
#include "ssl_platform.h"
```

### Build Integration

#### CMakeLists.txt Integration
```cmake
# Add SSL platform library
add_subdirectory(lib/ssl-platform)

# Link to your target
target_link_libraries(your_target ssl-platform)

# Include headers
target_include_directories(your_target PRIVATE lib/ssl-platform)
```

## Error Handling

All functions return standardized error codes:

- `SSL_PLATFORM_SUCCESS` (0) - Operation successful
- `SSL_PLATFORM_ERROR_GENERIC` (-1) - Generic error
- `SSL_PLATFORM_ERROR_INVALID_PARAMETER` (-2) - Invalid parameter
- `SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL` (-3) - Buffer too small
- `SSL_PLATFORM_ERROR_INVALID_DATA` (-4) - Invalid input data
- `SSL_PLATFORM_ERROR_MEMORY_ALLOCATION` (-5) - Memory allocation failed
- `SSL_PLATFORM_ERROR_NOT_SUPPORTED` (-6) - Operation not supported

## Migration Guide

### From mbed-TLS to SSL Platform

Replace direct mbed-TLS calls:

```c
// Old mbed-TLS code
#include "mbedtls/base64.h"
mbedtls_base64_encode(dst, dlen, &olen, src, slen);

// New SSL platform code
#include "ssl_platform.h"
ssl_platform_base64_encode(dst, dlen, &olen, src, slen);
```

For SSL/TLS operations with SNI support:

```c
// Old mbed-TLS code
#include "mbedtls/ssl.h"
mbedtls_ssl_set_hostname(&ssl, "example.com");

// New SSL platform code (with compatibility macro)
#include "ssl_platform.h"
#include "ssl_platform_compat.h"
mbedtls_ssl_set_hostname(&ssl, "example.com");  // Uses ssl_platform_ssl_set_hostname internally

// Or use SSL platform API directly
ssl_platform_ssl_set_hostname(&ssl, "example.com");
```

### From SSL Platform to OpenSSL

Simply change the backend configuration:

```bash
# Change from mbed-TLS to OpenSSL
cmake -DSSL_PLATFORM_BACKEND=2 ..
make
```

## Dependencies

### mbed-TLS Backend
- mbed-TLS 2.28.x or compatible version
- Standard C library

### OpenSSL Backend
- OpenSSL 1.1.0 or later (recommended: 3.0+)
- Standard C library

## Performance Considerations

- The abstraction layer adds minimal overhead (typically 1-2 function calls)
- Backend selection is compile-time, so no runtime overhead
- OpenSSL backend may be faster for large operations
- mbed-TLS backend may be more suitable for memory-constrained environments

## Thread Safety

- Thread safety depends on the underlying backend
- mbed-TLS: Generally not thread-safe, requires external synchronization
- OpenSSL: Thread-safe with proper initialization (OpenSSL 1.1.0+)

## Limitations

- Not all mbed-TLS/OpenSSL features are exposed through the abstraction
- Some advanced features may require backend-specific code
- API is designed for common use cases in mbed-edge project

## Contributing

When adding new functionality:

1. Add the function declaration to `ssl_platform.h`
2. Implement for both backends (`ssl_platform_mbedtls.c` and `ssl_platform_openssl.c`)
3. Add appropriate error mapping
4. Update this documentation
5. Add tests if applicable

## License

This code is licensed under the Apache License 2.0. See the LICENSE file for details. 