/*
 * SSL Platform Abstraction Layer - Mbed-TLS Backend
 * 
 * Copyright (c) 2024
 * 
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef SSL_PLATFORM_MBEDTLS_H
#define SSL_PLATFORM_MBEDTLS_H

#include "mbedtls/aes.h"
#include "mbedtls/base64.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/md5.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ssl.h"
#include "mbedtls/config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* =============================================================================
 * CONTEXT STRUCTURE DEFINITIONS
 * =============================================================================
 */

/**
 * \brief AES context structure for mbed-TLS backend
 */
struct ssl_platform_aes_context {
    mbedtls_aes_context mbedtls_ctx;
};

/**
 * \brief Hash context structure for mbed-TLS backend
 */
struct ssl_platform_hash_context {
    ssl_platform_hash_type_t type;
    union {
        mbedtls_sha1_context sha1;
        mbedtls_sha256_context sha256;
        mbedtls_sha512_context sha512;
        mbedtls_md5_context md5;
        mbedtls_md_context_t md;
    } ctx;
};

/**
 * \brief Public key context structure for mbed-TLS backend
 */
struct ssl_platform_pk_context {
    mbedtls_pk_context mbedtls_ctx;
};

/**
 * \brief X.509 certificate structure for mbed-TLS backend
 */
struct ssl_platform_x509_crt {
    mbedtls_x509_crt mbedtls_crt;
};

/**
 * \brief Entropy context structure for mbed-TLS backend
 */
struct ssl_platform_entropy_context {
    mbedtls_entropy_context mbedtls_ctx;
};

/**
 * \brief CTR-DRBG context structure for mbed-TLS backend
 */
struct ssl_platform_ctr_drbg_context {
    mbedtls_ctr_drbg_context mbedtls_ctx;
};

/**
 * \brief SSL context structure for mbed-TLS backend
 */
struct ssl_platform_ssl_context {
    mbedtls_ssl_context mbedtls_ssl;
};

/**
 * \brief SSL configuration structure for mbed-TLS backend
 */
struct ssl_platform_ssl_config {
    mbedtls_ssl_config mbedtls_conf;
};

/* =============================================================================
 * ERROR CODE MAPPINGS
 * =============================================================================
 */

/**
 * \brief Convert mbed-TLS error codes to SSL platform error codes
 */
static inline int ssl_platform_mbedtls_error_map(int mbedtls_ret)
{
    switch (mbedtls_ret) {
        case 0:
            return SSL_PLATFORM_SUCCESS;
        case MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL:
            return SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL;
        case MBEDTLS_ERR_BASE64_INVALID_CHARACTER:
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
 * \brief Map SSL platform hash type to mbed-TLS message digest type
 */
static inline mbedtls_md_type_t ssl_platform_hash_type_to_mbedtls(ssl_platform_hash_type_t type)
{
    switch (type) {
        case SSL_PLATFORM_HASH_SHA1:
            return MBEDTLS_MD_SHA1;
        case SSL_PLATFORM_HASH_SHA224:
            return MBEDTLS_MD_SHA224;
        case SSL_PLATFORM_HASH_SHA256:
            return MBEDTLS_MD_SHA256;
        case SSL_PLATFORM_HASH_SHA384:
            return MBEDTLS_MD_SHA384;
        case SSL_PLATFORM_HASH_SHA512:
            return MBEDTLS_MD_SHA512;
        case SSL_PLATFORM_HASH_MD5:
            return MBEDTLS_MD_MD5;
        default:
            return MBEDTLS_MD_NONE;
    }
}

/**
 * \brief Get hash output size for SSL platform hash type
 */
static inline size_t ssl_platform_mbedtls_hash_get_size(ssl_platform_hash_type_t type)
{
    switch (type) {
        case SSL_PLATFORM_HASH_SHA1:
            return 20;
        case SSL_PLATFORM_HASH_SHA224:
            return 28;
        case SSL_PLATFORM_HASH_SHA256:
            return 32;
        case SSL_PLATFORM_HASH_SHA384:
            return 48;
        case SSL_PLATFORM_HASH_SHA512:
            return 64;
        case SSL_PLATFORM_HASH_MD5:
            return 16;
        default:
            return 0;
    }
}

/* =============================================================================
 * ECC CURVE MAPPINGS
 * =============================================================================
 */

/**
 * \brief Map SSL platform ECC group ID to mbed-TLS ECC group ID
 */
static inline mbedtls_ecp_group_id ssl_platform_ecp_group_to_mbedtls(ssl_platform_ecp_group_id_t grp_id)
{
    switch (grp_id) {
        case SSL_PLATFORM_ECP_DP_SECP256R1:
            return MBEDTLS_ECP_DP_SECP256R1;
        case SSL_PLATFORM_ECP_DP_SECP384R1:
            return MBEDTLS_ECP_DP_SECP384R1;
        case SSL_PLATFORM_ECP_DP_SECP521R1:
            return MBEDTLS_ECP_DP_SECP521R1;
        default:
            return MBEDTLS_ECP_DP_NONE;
    }
}

#ifdef __cplusplus
}
#endif

#endif /* SSL_PLATFORM_MBEDTLS_H */ 