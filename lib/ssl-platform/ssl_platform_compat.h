/*
 * SSL Platform Abstraction Layer - Compatibility Macros
 * 
 * Copyright (c) 2024
 * 
 * SPDX-License-Identifier: Apache-2.0
 * 
 * This header provides compile-time compatibility macros that redirect
 * mbed-TLS function calls to the SSL platform abstraction layer.
 * This allows existing code to use mbed-TLS APIs while transparently
 * using the configured backend (mbed-TLS or OpenSSL).
 */

#ifndef SSL_PLATFORM_COMPAT_H
#define SSL_PLATFORM_COMPAT_H

#include "ssl_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =============================================================================
 * COMPATIBILITY MACROS FOR MBED-TLS FUNCTIONS
 * =============================================================================
 */

/* Base64 operations */
#define mbedtls_base64_encode        ssl_platform_base64_encode
#define mbedtls_base64_decode        ssl_platform_base64_decode

/* AES operations */
#define mbedtls_aes_context          ssl_platform_aes_context_t
#define mbedtls_aes_init             ssl_platform_aes_init
#define mbedtls_aes_free             ssl_platform_aes_free
#define mbedtls_aes_setkey_enc       ssl_platform_aes_setkey_enc
#define mbedtls_aes_setkey_dec       ssl_platform_aes_setkey_dec
#define mbedtls_aes_crypt_ecb        ssl_platform_aes_crypt_ecb

/* AES mode constants */
#define MBEDTLS_AES_ENCRYPT          SSL_PLATFORM_AES_ENCRYPT
#define MBEDTLS_AES_DECRYPT          SSL_PLATFORM_AES_DECRYPT

/* Error codes */
#define MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL  SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL
#define MBEDTLS_ERR_BASE64_INVALID_CHARACTER SSL_PLATFORM_ERROR_INVALID_DATA

/* Hash operations - these require wrapper functions since the APIs differ slightly */
#define mbedtls_sha1_context         ssl_platform_hash_context_t
#define mbedtls_sha256_context       ssl_platform_hash_context_t
#define mbedtls_sha512_context       ssl_platform_hash_context_t
#define mbedtls_md5_context          ssl_platform_hash_context_t

/* Public key operations */
#define mbedtls_pk_context           ssl_platform_pk_context_t
#define mbedtls_pk_init              ssl_platform_pk_init
#define mbedtls_pk_free              ssl_platform_pk_free
#define mbedtls_pk_parse_key         ssl_platform_pk_parse_key
#define mbedtls_pk_parse_public_key  ssl_platform_pk_parse_public_key

/* X.509 certificate operations */
#define mbedtls_x509_crt             ssl_platform_x509_crt_t
#define mbedtls_x509_crt_init        ssl_platform_x509_crt_init
#define mbedtls_x509_crt_free        ssl_platform_x509_crt_free
#define mbedtls_x509_crt_parse       ssl_platform_x509_crt_parse

/* Random number generation */
#define mbedtls_entropy_context      ssl_platform_entropy_context_t
#define mbedtls_ctr_drbg_context     ssl_platform_ctr_drbg_context_t
#define mbedtls_entropy_init         ssl_platform_entropy_init
#define mbedtls_entropy_free         ssl_platform_entropy_free
#define mbedtls_ctr_drbg_init        ssl_platform_ctr_drbg_init
#define mbedtls_ctr_drbg_free        ssl_platform_ctr_drbg_free
#define mbedtls_ctr_drbg_seed        ssl_platform_ctr_drbg_seed
#define mbedtls_ctr_drbg_random      ssl_platform_ctr_drbg_random

/* SSL/TLS operations */
#define mbedtls_ssl_context          ssl_platform_ssl_context_t
#define mbedtls_ssl_config           ssl_platform_ssl_config_t
#define mbedtls_ssl_init             ssl_platform_ssl_init
#define mbedtls_ssl_free             ssl_platform_ssl_free
#define mbedtls_ssl_config_init      ssl_platform_ssl_config_init
#define mbedtls_ssl_config_free      ssl_platform_ssl_config_free

/* =============================================================================
 * WRAPPER FUNCTIONS FOR COMPLEX API DIFFERENCES
 * =============================================================================
 */

/**
 * \brief Wrapper for SHA1 initialization to match mbed-TLS API
 */
static inline void ssl_platform_compat_sha1_init(ssl_platform_hash_context_t *ctx)
{
    ssl_platform_hash_init(ctx, SSL_PLATFORM_HASH_SHA1);
}

/**
 * \brief Wrapper for SHA1 starts to match mbed-TLS API
 */
static inline int ssl_platform_compat_sha1_starts_ret(ssl_platform_hash_context_t *ctx)
{
    return ssl_platform_hash_starts(ctx);
}

/**
 * \brief Wrapper for SHA1 update to match mbed-TLS API
 */
static inline int ssl_platform_compat_sha1_update_ret(ssl_platform_hash_context_t *ctx,
                                                      const unsigned char *input,
                                                      size_t ilen)
{
    return ssl_platform_hash_update(ctx, input, ilen);
}

/**
 * \brief Wrapper for SHA1 finish to match mbed-TLS API
 */
static inline int ssl_platform_compat_sha1_finish_ret(ssl_platform_hash_context_t *ctx,
                                                      unsigned char output[20])
{
    return ssl_platform_hash_finish(ctx, output);
}

/**
 * \brief Wrapper for SHA256 initialization to match mbed-TLS API
 */
static inline void ssl_platform_compat_sha256_init(ssl_platform_hash_context_t *ctx)
{
    ssl_platform_hash_init(ctx, SSL_PLATFORM_HASH_SHA256);
}

/**
 * \brief Wrapper for SHA256 starts to match mbed-TLS API
 */
static inline int ssl_platform_compat_sha256_starts_ret(ssl_platform_hash_context_t *ctx, int is224)
{
    ssl_platform_hash_type_t type = is224 ? SSL_PLATFORM_HASH_SHA224 : SSL_PLATFORM_HASH_SHA256;
    ssl_platform_hash_init(ctx, type);
    return ssl_platform_hash_starts(ctx);
}

/**
 * \brief Wrapper for SHA256 update to match mbed-TLS API
 */
static inline int ssl_platform_compat_sha256_update_ret(ssl_platform_hash_context_t *ctx,
                                                        const unsigned char *input,
                                                        size_t ilen)
{
    return ssl_platform_hash_update(ctx, input, ilen);
}

/**
 * \brief Wrapper for SHA256 finish to match mbed-TLS API
 */
static inline int ssl_platform_compat_sha256_finish_ret(ssl_platform_hash_context_t *ctx,
                                                        unsigned char output[32])
{
    return ssl_platform_hash_finish(ctx, output);
}

/* Hash function compatibility macros */
#define mbedtls_sha1_init            ssl_platform_compat_sha1_init
#define mbedtls_sha1_starts_ret      ssl_platform_compat_sha1_starts_ret
#define mbedtls_sha1_update_ret      ssl_platform_compat_sha1_update_ret
#define mbedtls_sha1_finish_ret      ssl_platform_compat_sha1_finish_ret
#define mbedtls_sha1_free            ssl_platform_hash_free

#define mbedtls_sha256_init          ssl_platform_compat_sha256_init
#define mbedtls_sha256_starts_ret    ssl_platform_compat_sha256_starts_ret
#define mbedtls_sha256_update_ret    ssl_platform_compat_sha256_update_ret
#define mbedtls_sha256_finish_ret    ssl_platform_compat_sha256_finish_ret
#define mbedtls_sha256_free          ssl_platform_hash_free

/* MD5 compatibility (similar pattern) */
#define mbedtls_md5_init(ctx)        ssl_platform_hash_init(ctx, SSL_PLATFORM_HASH_MD5)
#define mbedtls_md5_starts_ret       ssl_platform_hash_starts
#define mbedtls_md5_update_ret       ssl_platform_hash_update
#define mbedtls_md5_finish_ret       ssl_platform_hash_finish
#define mbedtls_md5_free             ssl_platform_hash_free

/* =============================================================================
 * ENTROPY FUNCTION COMPATIBILITY
 * =============================================================================
 */

/**
 * \brief Entropy function wrapper to match mbed-TLS callback signature
 */
static inline int ssl_platform_compat_entropy_func(void *data, unsigned char *output, size_t len)
{
    ssl_platform_entropy_context_t *ctx = (ssl_platform_entropy_context_t *)data;
    (void)ctx; // OpenSSL handles entropy internally
    return ssl_platform_ctr_drbg_random(NULL, output, len);
}

#define mbedtls_entropy_func         ssl_platform_compat_entropy_func

#ifdef __cplusplus
}
#endif

#endif /* SSL_PLATFORM_COMPAT_H */ 