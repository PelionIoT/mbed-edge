# SSL Platform X.509 and CTR-DRBG Functions Implementation

## Overview

This document describes the implementation and testing of the X.509 certificate manipulation functions and CTR-DRBG functions in the SSL Platform Abstraction Layer for the OpenSSL backend.

## Implemented Functions

### X.509 Certificate Functions

#### `ssl_platform_x509_get_tbs`
**Purpose**: Extract the TBS (To Be Signed) portion of an X.509 certificate in DER format.

**Signature**:
```c
int ssl_platform_x509_get_tbs(ssl_platform_x509_crt_t *crt, unsigned char **buf, size_t *len);
```

**Parameters**:
- `crt`: X.509 certificate context
- `buf`: Output pointer to allocated TBS data (caller must free with `OPENSSL_free()`)
- `len`: Output length of TBS data

**Returns**: `SSL_PLATFORM_SUCCESS` on success, error code on failure

**OpenSSL Implementation**: Uses `i2d_re_X509_tbs()` to extract the TBS portion

---

#### `ssl_platform_x509_get_subject_name`
**Purpose**: Get the subject name of an X.509 certificate as a human-readable string.

**Signature**:
```c
int ssl_platform_x509_get_subject_name(ssl_platform_x509_crt_t *crt, char *buf, size_t buf_size);
```

**Parameters**:
- `crt`: X.509 certificate context
- `buf`: Output buffer for subject name string
- `buf_size`: Size of output buffer

**Returns**: `SSL_PLATFORM_SUCCESS` on success, error code on failure

**OpenSSL Implementation**: Uses `X509_get_subject_name()` and `X509_NAME_print_ex()` with RFC2253 formatting

---

#### `ssl_platform_x509_get_issuer_raw`
**Purpose**: Get the issuer name of an X.509 certificate in DER format.

**Signature**:
```c
int ssl_platform_x509_get_issuer_raw(ssl_platform_x509_crt_t *crt, unsigned char **buf, size_t *len);
```

**Parameters**:
- `crt`: X.509 certificate context
- `buf`: Output pointer to allocated issuer DER data (caller must free with `OPENSSL_free()`)
- `len`: Output length of issuer data

**Returns**: `SSL_PLATFORM_SUCCESS` on success, error code on failure

**OpenSSL Implementation**: Uses `X509_get_issuer_name()` and `i2d_X509_NAME()`

---

#### `ssl_platform_x509_get_subject_raw`
**Purpose**: Get the subject name of an X.509 certificate in DER format.

**Signature**:
```c
int ssl_platform_x509_get_subject_raw(ssl_platform_x509_crt_t *crt, unsigned char **buf, size_t *len);
```

**Parameters**:
- `crt`: X.509 certificate context
- `buf`: Output pointer to allocated subject DER data (caller must free with `OPENSSL_free()`)
- `len`: Output length of subject data

**Returns**: `SSL_PLATFORM_SUCCESS` on success, error code on failure

**OpenSSL Implementation**: Uses `X509_get_subject_name()` and `i2d_X509_NAME()`

---

#### `ssl_platform_x509_get_validity`
**Purpose**: Get the validity period (not before/not after dates) of an X.509 certificate.

**Signature**:
```c
int ssl_platform_x509_get_validity(ssl_platform_x509_crt_t *crt, struct tm *not_before, struct tm *not_after);
```

**Parameters**:
- `crt`: X.509 certificate context
- `not_before`: Output structure for "not before" date
- `not_after`: Output structure for "not after" date

**Returns**: `SSL_PLATFORM_SUCCESS` on success, error code on failure

**OpenSSL Implementation**: Uses `X509_get0_notBefore()`, `X509_get0_notAfter()`, and `ASN1_TIME_to_tm()`

---

#### `ssl_platform_x509_get_signature`
**Purpose**: Get the signature data from an X.509 certificate.

**Signature**:
```c
int ssl_platform_x509_get_signature(ssl_platform_x509_crt_t *crt, unsigned char **buf, size_t *len);
```

**Parameters**:
- `crt`: X.509 certificate context
- `buf`: Output pointer to allocated signature data (caller must free with `free()`)
- `len`: Output length of signature data

**Returns**: `SSL_PLATFORM_SUCCESS` on success, error code on failure

**OpenSSL Implementation**: Uses `X509_get0_signature()` to access signature data

---

#### `ssl_platform_x509_crt_check_extended_key_usage`
**Purpose**: Check if an X.509 certificate has a specific Extended Key Usage (EKU).

**Signature**:
```c
int ssl_platform_x509_crt_check_extended_key_usage(ssl_platform_x509_crt_t *crt, 
                                                   const unsigned char *usage, 
                                                   size_t oid_len);
```

**Parameters**:
- `crt`: X.509 certificate context
- `usage`: OID string of the Extended Key Usage to check (e.g., "1.3.6.1.5.5.7.3.1" for Server Authentication)
- `oid_len`: Length of the OID string

**Returns**: `SSL_PLATFORM_SUCCESS` if EKU is present, `SSL_PLATFORM_ERROR_GENERIC` if not found or no EKU extension

**OpenSSL Implementation**: Uses `X509_get_ext_d2i()` with `NID_ext_key_usage` and `OBJ_txt2obj()`

---

#### `ssl_platform_x509_get_pubkey`
**Purpose**: Extract the public key from an X.509 certificate.

**Signature**:
```c
int ssl_platform_x509_get_pubkey(ssl_platform_x509_crt_t *crt, ssl_platform_pk_context_t *pk);
```

**Parameters**:
- `crt`: X.509 certificate context
- `pk`: Public key context to populate (must be initialized)

**Returns**: `SSL_PLATFORM_SUCCESS` on success, error code on failure

**OpenSSL Implementation**: Uses `X509_get_pubkey()` to extract the public key

---

### CTR-DRBG Functions

#### `ssl_platform_ctr_drbg_reseed`
**Purpose**: Reseed the CTR-DRBG with additional entropy.

**Signature**:
```c
int ssl_platform_ctr_drbg_reseed(ssl_platform_ctr_drbg_context_t *ctx, 
                                 const unsigned char *additional, 
                                 size_t len);
```

**Parameters**:
- `ctx`: CTR-DRBG context
- `additional`: Additional entropy data (can be NULL)
- `len`: Length of additional entropy data

**Returns**: `SSL_PLATFORM_SUCCESS` on success, error code on failure

**OpenSSL Implementation**: Uses `RAND_add()` to add entropy to the OpenSSL entropy pool

---

## Testing

### Test Suite

The test suite (`test_x509_functions.c`) includes comprehensive testing for all implemented functions:

1. **Parameter Validation**: Tests error handling for NULL and invalid parameters
2. **Certificate Parsing**: Tests loading of X.509 certificates from PEM format
3. **Subject Name Extraction**: Tests retrieval of certificate subject as human-readable string
4. **Issuer/Subject Raw Data**: Tests extraction of DER-encoded issuer and subject names
5. **Validity Period**: Tests extraction of certificate validity dates
6. **Signature Extraction**: Tests retrieval of certificate signature data
7. **TBS Extraction**: Tests extraction of To-Be-Signed certificate portion
8. **Public Key Extraction**: Tests extraction of public key from certificate
9. **Extended Key Usage**: Tests checking for specific EKU OIDs
10. **CTR-DRBG Reseeding**: Tests reseeding functionality with and without additional entropy

### Test Certificate

The test suite uses a self-signed X.509 certificate with the following properties:
- Subject: `CN=test.example.com,O=TestOrg,L=TestCity,ST=TestState,C=US`
- Key Type: RSA 2048-bit
- Validity: 1 year
- Self-signed (issuer = subject)

### Test Execution

#### Direct Compilation
```bash
gcc -DSSL_PLATFORM_BACKEND=2 -I. -o test_x509_functions test_x509_functions.c ssl_platform_openssl.c -lssl -lcrypto
./test_x509_functions
```

#### CMake Build
```bash
mkdir build
cd build
cmake -DSSL_PLATFORM_BACKEND=2 ../
make
./test_x509_functions

# Or using CTest
ctest --verbose
```

### Expected Test Results

All tests should pass with output similar to:
```
=== SSL Platform X.509 and CTR-DRBG Test Suite ===
=== Testing Parameter Validation ===
PASS: All parameter validation tests passed
=== Testing Certificate Parsing ===
PASS: Certificate parsed successfully
[... additional test output ...]
=== Test Results ===
Tests passed: 11
Tests failed: 0
All tests PASSED!
```

## Memory Management

**Important**: Several functions allocate memory that must be freed by the caller:

- `ssl_platform_x509_get_tbs()`: Free with `OPENSSL_free()`
- `ssl_platform_x509_get_issuer_raw()`: Free with `OPENSSL_free()`
- `ssl_platform_x509_get_subject_raw()`: Free with `OPENSSL_free()`
- `ssl_platform_x509_get_signature()`: Free with `free()`

## Error Handling

All functions return:
- `SSL_PLATFORM_SUCCESS` (0) on success
- `SSL_PLATFORM_ERROR_INVALID_PARAMETER` for NULL or invalid parameters
- `SSL_PLATFORM_ERROR_GENERIC` for other errors (e.g., OpenSSL API failures)
- `SSL_PLATFORM_ERROR_MEMORY_ALLOCATION` for memory allocation failures
- `SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL` for insufficient buffer size

## Backend Compatibility

These implementations are specific to the OpenSSL backend (`SSL_PLATFORM_BACKEND=2`). The mbed-TLS backend has equivalent implementations that maintain API compatibility while using mbed-TLS-specific functions.

## Usage Examples

### Extract Certificate Subject Name
```c
ssl_platform_x509_crt_t cert;
ssl_platform_x509_crt_init(&cert);
ssl_platform_x509_crt_parse(&cert, cert_pem, strlen(cert_pem));

char subject[256];
int ret = ssl_platform_x509_get_subject_name(&cert, subject, sizeof(subject));
if (ret == SSL_PLATFORM_SUCCESS) {
    printf("Subject: %s\n", subject);
}

ssl_platform_x509_crt_free(&cert);
```

### Check Extended Key Usage
```c
const char *server_auth_oid = "1.3.6.1.5.5.7.3.1";
int ret = ssl_platform_x509_crt_check_extended_key_usage(&cert, 
                                                         (const unsigned char*)server_auth_oid, 
                                                         strlen(server_auth_oid));
if (ret == SSL_PLATFORM_SUCCESS) {
    printf("Certificate has Server Authentication EKU\n");
}
```

### Extract Public Key
```c
ssl_platform_pk_context_t pk;
ssl_platform_pk_init(&pk);

int ret = ssl_platform_x509_get_pubkey(&cert, &pk);
if (ret == SSL_PLATFORM_SUCCESS) {
    printf("Public key extracted, type: %d\n", pk.key_type);
}

ssl_platform_pk_free(&pk);
```

## Compliance

The implementation follows:
- OpenSSL 3.x API patterns and best practices
- X.509 certificate format standards (RFC 5280)
- Extended Key Usage extension specifications (RFC 5280)
- CTR-DRBG specifications (NIST SP 800-90A) 