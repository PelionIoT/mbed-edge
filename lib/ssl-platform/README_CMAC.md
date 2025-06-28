# SSL Platform CMAC Operations

This document describes the CMAC (Cipher-based Message Authentication Code) operations implemented in the SSL Platform abstraction layer.

## Overview

CMAC operations provide authenticated encryption capabilities using AES as the underlying block cipher. The implementation supports both one-shot and streaming CMAC calculations with abstraction over mbed-TLS and OpenSSL backends.

## Functions Implemented

### Context Management

```c
void ssl_platform_cipher_init(ssl_platform_cipher_context_t *ctx);
void ssl_platform_cipher_free(ssl_platform_cipher_context_t *ctx);
int ssl_platform_cipher_setup(ssl_platform_cipher_context_t *ctx,
                              ssl_platform_cipher_type_t cipher_type);
```

### One-Shot CMAC Operations

```c
int ssl_platform_aes_cmac(const unsigned char *key, size_t keylen,
                          const unsigned char *input, size_t ilen,
                          unsigned char *output);

int ssl_platform_cipher_cmac(ssl_platform_cipher_type_t cipher_type,
                             const unsigned char *key, size_t keybits,
                             const unsigned char *input, size_t ilen,
                             unsigned char *output);
```

### Streaming CMAC Operations

```c
int ssl_platform_cipher_cmac_starts(ssl_platform_cipher_context_t *ctx,
                                    const unsigned char *key,
                                    size_t keybits);

int ssl_platform_cipher_cmac_update(ssl_platform_cipher_context_t *ctx,
                                    const unsigned char *input,
                                    size_t ilen);

int ssl_platform_cipher_cmac_finish(ssl_platform_cipher_context_t *ctx,
                                    unsigned char *output);
```

### Utility Functions

```c
const void *ssl_platform_cipher_info_from_type(ssl_platform_cipher_type_t cipher_type);
```

## Supported Cipher Types

- `SSL_PLATFORM_CIPHER_AES_128_ECB` - AES-128 ECB mode
- `SSL_PLATFORM_CIPHER_AES_192_ECB` - AES-192 ECB mode  
- `SSL_PLATFORM_CIPHER_AES_256_ECB` - AES-256 ECB mode
- `SSL_PLATFORM_CIPHER_AES_128_CBC` - AES-128 CBC mode
- `SSL_PLATFORM_CIPHER_AES_192_CBC` - AES-192 CBC mode
- `SSL_PLATFORM_CIPHER_AES_256_CBC` - AES-256 CBC mode

## Usage Examples

### One-Shot CMAC

```c
#include "ssl_platform.h"

unsigned char key[16] = { /* 128-bit key */ };
unsigned char message[] = "Hello, CMAC!";
unsigned char cmac[16];

int ret = ssl_platform_aes_cmac(key, 16, message, strlen(message), cmac);
if (ret == SSL_PLATFORM_SUCCESS) {
    // CMAC calculated successfully
}
```

### Streaming CMAC

```c
#include "ssl_platform.h"

ssl_platform_cipher_context_t ctx;
unsigned char key[16] = { /* 128-bit key */ };
unsigned char message1[] = "Hello, ";
unsigned char message2[] = "CMAC!";
unsigned char cmac[16];

ssl_platform_cipher_init(&ctx);
ssl_platform_cipher_setup(&ctx, SSL_PLATFORM_CIPHER_AES_128_ECB);
ssl_platform_cipher_cmac_starts(&ctx, key, 128);
ssl_platform_cipher_cmac_update(&ctx, message1, strlen(message1));
ssl_platform_cipher_cmac_update(&ctx, message2, strlen(message2));
ssl_platform_cipher_cmac_finish(&ctx, cmac);
ssl_platform_cipher_free(&ctx);
```

## Backend Implementation Details

### mbed-TLS Backend

- Uses `mbedtls_cipher_cmac()` for one-shot operations
- Uses `mbedtls_cipher_cmac_starts/update/finish()` for streaming operations
- Supports all AES key sizes (128, 192, 256 bits)
- Fully compatible with RFC 4493 test vectors

### OpenSSL Backend

- Uses `CMAC_Init/Update/Final()` on OpenSSL 1.1.0+
- Provides fallback implementation for older OpenSSL versions
- Note: Streaming CMAC requires buffering (simplified implementation)
- One-shot operations fully supported

## Test Coverage

The implementation includes comprehensive tests:

- **RFC 4493 Test Vectors**: All official AES-CMAC test vectors
- **Edge Cases**: Empty messages, various message lengths
- **Error Handling**: NULL parameter validation, invalid key sizes
- **Backend Coverage**: Tests run on both mbed-TLS and OpenSSL

Run tests with:
```bash
./test_cmac.sh
```

## Error Codes

- `SSL_PLATFORM_SUCCESS` - Operation successful
- `SSL_PLATFORM_ERROR_INVALID_PARAMETER` - NULL or invalid parameters
- `SSL_PLATFORM_ERROR_NOT_SUPPORTED` - Unsupported cipher type or operation
- `SSL_PLATFORM_ERROR_MEMORY_ALLOCATION` - Memory allocation failure
- `SSL_PLATFORM_ERROR_GENERIC` - General backend error

## Migration Guide

### From mbed-TLS

Replace:
```c
mbedtls_cipher_cmac(cipher_info, key, keybits, input, ilen, output);
```

With:
```c
ssl_platform_cipher_cmac(SSL_PLATFORM_CIPHER_AES_128_ECB, key, keybits, input, ilen, output);
```

### From OpenSSL

Replace:
```c
CMAC_Init(ctx, key, keylen, cipher, NULL);
CMAC_Update(ctx, input, ilen);
CMAC_Final(ctx, output, &outlen);
```

With:
```c
ssl_platform_cipher_cmac_starts(ctx, key, keylen * 8);
ssl_platform_cipher_cmac_update(ctx, input, ilen);
ssl_platform_cipher_cmac_finish(ctx, output);
```

## Performance Notes

- One-shot operations are generally faster for small messages
- Streaming operations are better for large messages that don't fit in memory
- mbed-TLS backend has full streaming support
- OpenSSL backend has limitations on streaming (implementation-dependent)

## Security Considerations

- Always use cryptographically secure random keys
- Clear sensitive key material from memory after use
- Validate CMAC results before using authenticated data
- Consider timing attack protections in production use

## Dependencies

### mbed-TLS Backend
- `mbedtls/cipher.h`
- `mbedtls/cmac.h`

### OpenSSL Backend  
- `openssl/cmac.h` (OpenSSL 1.1.0+)
- `openssl/evp.h`

## References

- [RFC 4493: The AES-CMAC Algorithm](https://tools.ietf.org/html/rfc4493)
- [NIST SP 800-38B: Cipher Modes of Operation](https://csrc.nist.gov/publications/detail/sp/800-38b/final) 