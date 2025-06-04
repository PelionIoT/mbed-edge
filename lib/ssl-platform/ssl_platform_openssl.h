/*
 * SSL Platform Abstraction Layer - OpenSSL Backend
 * 
 * Copyright (c) 2024
 * 
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SSL_PLATFORM_OPENSSL_H
#define SSL_PLATFORM_OPENSSL_H

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include "ssl_platform_compat.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =============================================================================
 * CONTEXT STRUCTURE DEFINITIONS
 * =============================================================================
 */

/**
 * \brief AES context structure for OpenSSL backend
 */
struct ssl_platform_aes_context {
    AES_KEY encrypt_key;
    AES_KEY decrypt_key;
    int key_bits;
    int mode;  /* encryption or decryption */
};

/**
 * \brief Hash context structure for OpenSSL backend
 */
struct ssl_platform_hash_context {
    ssl_platform_hash_type_t type;
    EVP_MD_CTX *md_ctx;
    union {
        SHA_CTX sha1;
        SHA256_CTX sha256;
        SHA512_CTX sha512;
        MD5_CTX md5;
    } ctx;
};

/**
 * \brief Public key context structure for OpenSSL backend
 */
struct ssl_platform_pk_context {
    EVP_PKEY *pkey;
    int key_type;  /* RSA, EC, etc. */
};

/**
 * \brief X.509 certificate structure for OpenSSL backend
 */
struct ssl_platform_x509_crt {
    X509 *cert;
    struct ssl_platform_x509_crt *next;  /* For certificate chains */
};

/**
 * \brief Entropy context structure for OpenSSL backend
 */
struct ssl_platform_entropy_context {
    int initialized;  /* OpenSSL handles entropy internally */
};

/**
 * \brief CTR-DRBG context structure for OpenSSL backend
 */
struct ssl_platform_ctr_drbg_context {
    int initialized;  /* OpenSSL handles PRNG internally */
};

/**
 * \brief SSL context structure for OpenSSL backend
 */
struct ssl_platform_ssl_context {
    SSL *ssl;
};

/**
 * \brief SSL configuration structure for OpenSSL backend
 */
struct ssl_platform_ssl_config {
    SSL_CTX *ssl_ctx;
    int endpoint;     /* client or server */
    int authmode;     /* verification mode */
    int min_version;  /* minimum TLS version */
    int max_version;  /* maximum TLS version */
};

/* =============================================================================
 * ERROR CODE MAPPINGS
 * =============================================================================
 */

/**
 * \brief Convert OpenSSL error codes to SSL platform error codes
 */
static inline int ssl_platform_openssl_error_map(int openssl_ret)
{
    if (openssl_ret == 1 || openssl_ret > 0) {
        return SSL_PLATFORM_SUCCESS;
    }
    
    unsigned long err = ERR_get_error();
    switch (ERR_GET_REASON(err)) {
        case EVP_R_BUFFER_TOO_SMALL:
            return SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL;
        case EVP_R_INVALID_KEY_LENGTH:
        case EVP_R_BAD_DECRYPT:
            return SSL_PLATFORM_ERROR_INVALID_DATA;
        default:
            return SSL_PLATFORM_ERROR_GENERIC;
    }
}

/* =============================================================================
 * HASH TYPE MAPPINGS
 * =============================================================================
 */

/**
 * \brief Map SSL platform hash type to OpenSSL message digest
 */
static inline const EVP_MD* ssl_platform_hash_type_to_openssl(ssl_platform_hash_type_t type)
{
    switch (type) {
        case SSL_PLATFORM_HASH_SHA1:
            return EVP_sha1();
        case SSL_PLATFORM_HASH_SHA224:
            return EVP_sha224();
        case SSL_PLATFORM_HASH_SHA256:
            return EVP_sha256();
        case SSL_PLATFORM_HASH_SHA384:
            return EVP_sha384();
        case SSL_PLATFORM_HASH_SHA512:
            return EVP_sha512();
        case SSL_PLATFORM_HASH_MD5:
            return EVP_md5();
        default:
            return NULL;
    }
}

/**
 * \brief Get hash output size for SSL platform hash type
 */
static inline size_t ssl_platform_openssl_hash_get_size(ssl_platform_hash_type_t type)
{
    switch (type) {
        case SSL_PLATFORM_HASH_SHA1:
            return SHA_DIGEST_LENGTH;
        case SSL_PLATFORM_HASH_SHA224:
            return SHA224_DIGEST_LENGTH;
        case SSL_PLATFORM_HASH_SHA256:
            return SHA256_DIGEST_LENGTH;
        case SSL_PLATFORM_HASH_SHA384:
            return SHA384_DIGEST_LENGTH;
        case SSL_PLATFORM_HASH_SHA512:
            return SHA512_DIGEST_LENGTH;
        case SSL_PLATFORM_HASH_MD5:
            return MD5_DIGEST_LENGTH;
        default:
            return 0;
    }
}

/* =============================================================================
 * CIPHER TYPE MAPPINGS
 * =============================================================================
 */

/**
 * \brief Map SSL platform cipher type to OpenSSL cipher
 */
static inline const EVP_CIPHER* ssl_platform_cipher_type_to_openssl(ssl_platform_cipher_type_t type)
{
    switch (type) {
        case SSL_PLATFORM_CIPHER_AES_128_ECB:
            return EVP_aes_128_ecb();
        case SSL_PLATFORM_CIPHER_AES_192_ECB:
            return EVP_aes_192_ecb();
        case SSL_PLATFORM_CIPHER_AES_256_ECB:
            return EVP_aes_256_ecb();
        case SSL_PLATFORM_CIPHER_AES_128_CBC:
            return EVP_aes_128_cbc();
        case SSL_PLATFORM_CIPHER_AES_192_CBC:
            return EVP_aes_192_cbc();
        case SSL_PLATFORM_CIPHER_AES_256_CBC:
            return EVP_aes_256_cbc();
        case SSL_PLATFORM_CIPHER_AES_128_GCM:
            return EVP_aes_128_gcm();
        case SSL_PLATFORM_CIPHER_AES_192_GCM:
            return EVP_aes_192_gcm();
        case SSL_PLATFORM_CIPHER_AES_256_GCM:
            return EVP_aes_256_gcm();
        default:
            return NULL;
    }
}

/* =============================================================================
 * ECC CURVE MAPPINGS
 * =============================================================================
 */

/**
 * \brief Map SSL platform ECC group ID to OpenSSL NID
 */
static inline int ssl_platform_ecp_group_to_openssl(ssl_platform_ecp_group_id_t grp_id)
{
    switch (grp_id) {
        case SSL_PLATFORM_ECP_DP_SECP256R1:
            return NID_X9_62_prime256v1;
        case SSL_PLATFORM_ECP_DP_SECP384R1:
            return NID_secp384r1;
        case SSL_PLATFORM_ECP_DP_SECP521R1:
            return NID_secp521r1;
        default:
            return NID_undef;
    }
}

/* =============================================================================
 * UTILITY MACROS
 * =============================================================================
 */

/**
 * \brief Check if OpenSSL version supports a specific feature
 */
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
#define SSL_PLATFORM_OPENSSL_1_1_0_OR_LATER
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#define SSL_PLATFORM_OPENSSL_3_0_OR_LATER
#endif

#ifdef __cplusplus
}
#endif

#endif /* SSL_PLATFORM_OPENSSL_H */ 