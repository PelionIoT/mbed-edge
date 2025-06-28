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
#include "mbedtls/cipher.h"
#include "mbedtls/cmac.h"
#include "mbedtls/ccm.h"
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/oid.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"

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
    mbedtls_pk_context pk_ctx;  /* Use pk_ctx name for compatibility with existing code */
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

/**
 * \brief Cipher context structure for mbed-TLS backend
 */
struct ssl_platform_cipher_context {
    mbedtls_cipher_context_t mbedtls_ctx;
    ssl_platform_cipher_type_t cipher_type;
};

/**
 * \brief CCM context structure for mbed-TLS backend
 */
struct ssl_platform_ccm_context {
    mbedtls_ccm_context mbedtls_ctx;
};

/**
 * \brief ECP group structure for mbed-TLS backend
 */
struct ssl_platform_ecp_group {
    mbedtls_ecp_group mbedtls_grp;
};

/**
 * \brief ECP point structure for mbed-TLS backend
 */
struct ssl_platform_ecp_point {
    mbedtls_ecp_point mbedtls_pt;
};

/**
 * \brief ECP keypair structure for mbed-TLS backend
 */
struct ssl_platform_ecp_keypair {
    mbedtls_ecp_keypair mbedtls_keypair;
};

/**
 * \brief MPI (Multi-Precision Integer) structure for mbed-TLS backend
 */
struct ssl_platform_mpi {
    mbedtls_mpi mbedtls_mpi;
};

/* =============================================================================
 * ERROR CODE MAPPINGS
 * =============================================================================
 */

/**
 * \brief Convert mbed-TLS error codes to SSL platform error codes
 * \note This function is implemented in ssl_platform_mbedtls.c 
 *       to access all SSL platform error constants
 */
int ssl_platform_mbedtls_error_map(int mbedtls_ret);

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

/* =============================================================================
 * CIPHER TYPE MAPPINGS
 * =============================================================================
 */

/**
 * \brief Map SSL platform cipher type to mbed-TLS cipher type
 */
static inline mbedtls_cipher_type_t ssl_platform_cipher_type_to_mbedtls(ssl_platform_cipher_type_t type)
{
    switch (type) {
        case SSL_PLATFORM_CIPHER_AES_128_ECB:
            return MBEDTLS_CIPHER_AES_128_ECB;
        case SSL_PLATFORM_CIPHER_AES_192_ECB:
            return MBEDTLS_CIPHER_AES_192_ECB;
        case SSL_PLATFORM_CIPHER_AES_256_ECB:
            return MBEDTLS_CIPHER_AES_256_ECB;
        case SSL_PLATFORM_CIPHER_AES_128_CBC:
            return MBEDTLS_CIPHER_AES_128_CBC;
        case SSL_PLATFORM_CIPHER_AES_192_CBC:
            return MBEDTLS_CIPHER_AES_192_CBC;
        case SSL_PLATFORM_CIPHER_AES_256_CBC:
            return MBEDTLS_CIPHER_AES_256_CBC;
        case SSL_PLATFORM_CIPHER_AES_128_GCM:
            return MBEDTLS_CIPHER_AES_128_GCM;
        case SSL_PLATFORM_CIPHER_AES_192_GCM:
            return MBEDTLS_CIPHER_AES_192_GCM;
        case SSL_PLATFORM_CIPHER_AES_256_GCM:
            return MBEDTLS_CIPHER_AES_256_GCM;
        case SSL_PLATFORM_CIPHER_AES_128_CCM:
            return MBEDTLS_CIPHER_AES_128_CCM;
        case SSL_PLATFORM_CIPHER_AES_192_CCM:
            return MBEDTLS_CIPHER_AES_192_CCM;
        case SSL_PLATFORM_CIPHER_AES_256_CCM:
            return MBEDTLS_CIPHER_AES_256_CCM;
        default:
            return MBEDTLS_CIPHER_NONE;
    }
}

#ifdef __cplusplus
}
#endif

#endif /* SSL_PLATFORM_MBEDTLS_H */ 