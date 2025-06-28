# SSL Platform AES-CTR Implementation

## Overview

This document describes the implementation and testing of the `ssl_platform_aes_crypt_ctr` function in the SSL Platform Abstraction Layer.

## Implementation Details

### Function Signature

```c
int ssl_platform_aes_crypt_ctr(ssl_platform_aes_context_t *ctx,
                               size_t length,
                               size_t *nc_off,
                               unsigned char nonce_counter[16],
                               unsigned char stream_block[16],
                               const unsigned char *input,
                               unsigned char *output);
```

### Parameters

- `ctx`: AES context (must be initialized with `ssl_platform_aes_init()` and key set with `ssl_platform_aes_setkey_enc()`)
- `length`: Length of the input data to encrypt/decrypt
- `nc_off`: Offset in the current stream block (for resuming partial block operations)
- `nonce_counter`: 128-bit nonce and counter (modified during operation)
- `stream_block`: Saved stream block for resuming operations
- `input`: Input data buffer
- `output`: Output data buffer

### Backend Implementations

#### OpenSSL Backend
- Located in `ssl_platform_openssl.c`
- Uses the legacy AES API (`AES_encrypt`) for compatibility
- Implements CTR mode counter increment in big-endian format
- Handles partial block processing through `nc_off` parameter

#### mbed-TLS Backend
- Located in `ssl_platform_mbedtls.c`
- Uses `mbedtls_aes_crypt_ctr()` directly
- Maintains compatibility with the OpenSSL implementation

## Testing

### Test Suite

The test suite (`test_aes_ctr.c`) includes:

1. **Parameter Validation**: Tests error handling for NULL parameters
2. **Basic Functionality**: Tests encryption/decryption round-trip
3. **Known Vectors**: Tests against NIST AES-CTR test vectors
4. **Segmented Encryption**: Tests partial block processing across multiple calls

### Test Execution

#### Direct Compilation

```bash
# For OpenSSL backend
gcc -DSSL_PLATFORM_BACKEND=2 -I. -o test_aes_ctr test_aes_ctr.c ssl_platform_openssl.c -lssl -lcrypto

# For mbed-TLS backend
gcc -DSSL_PLATFORM_BACKEND=1 -I. -o test_aes_ctr test_aes_ctr.c ssl_platform_mbedtls.c -lmbedtls -lmbedcrypto
```

#### CMake Build

```bash
mkdir build
cd build
cmake -DSSL_PLATFORM_BACKEND=2 ../
make
./test_aes_ctr

# Or using CTest
ctest --verbose
```

### Test Results

All tests should pass with the following output:

```
=== SSL Platform AES-CTR Test Suite ===
=== Testing Parameter Validation ===
PASS: Parameter validation tests passed
=== Testing Basic Functionality ===
PASS: Basic functionality test passed
=== Testing Known Vectors ===
PASS: Vector 0 passed
=== Testing Segmented Encryption ===
PASS: Segmented encryption test passed
=== Test Results ===
Tests passed: 4
Tests failed: 0
All tests PASSED!
```

## Usage Example

```c
#include "ssl_platform.h"

int main() {
    ssl_platform_aes_context_t ctx;
    unsigned char key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
                            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    unsigned char nonce[16] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                               0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
    unsigned char stream[16] = {0};
    unsigned char plaintext[] = "Hello World!";
    unsigned char ciphertext[16] = {0};
    size_t nc_off = 0;
    
    // Initialize and set key
    ssl_platform_aes_init(&ctx);
    ssl_platform_aes_setkey_enc(&ctx, key, 128);
    
    // Encrypt
    ssl_platform_aes_crypt_ctr(&ctx, strlen((char*)plaintext), &nc_off, 
                               nonce, stream, plaintext, ciphertext);
    
    // Clean up
    ssl_platform_aes_free(&ctx);
    
    return 0;
}
```

## Notes

### OpenSSL Deprecation Warnings

When using the OpenSSL backend, you may see deprecation warnings about `AES_encrypt` and related functions. These are expected and the code will continue to work with OpenSSL 3.x. The warnings can be addressed in future versions by migrating to the EVP API.

### Thread Safety

The implementation is not thread-safe. Each thread should use its own AES context.

### Performance

CTR mode is particularly efficient for:
- Parallel processing (not implemented in this basic version)
- Random access to encrypted data
- Streaming applications

## Compliance

The implementation follows:
- NIST SP 800-38A specifications for CTR mode
- RFC 3686 for AES Counter Mode
- Compatible with both OpenSSL and mbed-TLS backends 