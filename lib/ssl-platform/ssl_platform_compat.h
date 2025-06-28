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
#define mbedtls_pk_verify            ssl_platform_pk_verify
#define mbedtls_pk_sign              ssl_platform_pk_sign
#define mbedtls_pk_setup             ssl_platform_pk_setup
#define mbedtls_pk_write_key_der     ssl_platform_pk_write_key_der
#define mbedtls_pk_write_pubkey_der  ssl_platform_pk_write_pubkey_der

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
#define mbedtls_ssl_set_hostname     ssl_platform_ssl_set_hostname

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

/* =============================================================================
 * MPI (MULTI-PRECISION INTEGER) COMPATIBILITY
 * =============================================================================
 */

/* MPI types and functions */
#define mbedtls_mpi                  ssl_platform_mpi_t
#define mbedtls_mpi_init             ssl_platform_mpi_init
#define mbedtls_mpi_free             ssl_platform_mpi_free
#define mbedtls_mpi_copy             ssl_platform_mpi_copy
#define mbedtls_mpi_size             ssl_platform_mpi_size
#define mbedtls_mpi_write_binary     ssl_platform_mpi_write_binary
#define mbedtls_mpi_read_binary      ssl_platform_mpi_read_binary
#define mbedtls_mpi_write_string     ssl_platform_mpi_write_string
#define mbedtls_mpi_read_string      ssl_platform_mpi_read_string
#define mbedtls_mpi_cmp_mpi          ssl_platform_mpi_cmp_mpi
#define mbedtls_mpi_cmp_int          ssl_platform_mpi_cmp_int
#define mbedtls_mpi_set_bit          ssl_platform_mpi_set_bit
#define mbedtls_mpi_get_bit          ssl_platform_mpi_get_bit

/* =============================================================================
 * ECP (ELLIPTIC CURVE POINT) COMPATIBILITY  
 * =============================================================================
 */

/* ECP types and functions */
#define mbedtls_ecp_group            ssl_platform_ecp_group_t
#define mbedtls_ecp_point            ssl_platform_ecp_point_t  
#define mbedtls_ecp_keypair          ssl_platform_ecp_keypair_t
#define mbedtls_ecp_group_id         ssl_platform_ecp_group_id_t
#define mbedtls_ecp_group_init       ssl_platform_ecp_group_init
#define mbedtls_ecp_group_free       ssl_platform_ecp_group_free
#define mbedtls_ecp_group_load       ssl_platform_ecp_group_load
#define mbedtls_ecp_point_init       ssl_platform_ecp_point_init
#define mbedtls_ecp_point_free       ssl_platform_ecp_point_free
#define mbedtls_ecp_point_write_binary ssl_platform_ecp_point_write_binary
#define mbedtls_ecp_point_read_binary ssl_platform_ecp_point_read_binary
#define mbedtls_ecp_keypair_init     ssl_platform_ecp_keypair_init
#define mbedtls_ecp_keypair_free     ssl_platform_ecp_keypair_free
#define mbedtls_ecp_gen_key          ssl_platform_ecp_gen_key
#define mbedtls_ecp_check_privkey    ssl_platform_ecp_check_privkey
#define mbedtls_ecp_check_pubkey     ssl_platform_ecp_check_pubkey
#define mbedtls_ecdh_compute_shared  ssl_platform_ecdh_compute_shared

/* ECP curve ID constants */
#define MBEDTLS_ECP_DP_NONE          SSL_PLATFORM_ECP_DP_NONE
#define MBEDTLS_ECP_DP_SECP256R1     SSL_PLATFORM_ECP_DP_SECP256R1
#define MBEDTLS_ECP_DP_SECP384R1     SSL_PLATFORM_ECP_DP_SECP384R1
#define MBEDTLS_ECP_DP_SECP521R1     SSL_PLATFORM_ECP_DP_SECP521R1

/* =============================================================================
 * ASN.1 COMPATIBILITY
 * =============================================================================
 */

/* ASN.1 types */
#define mbedtls_asn1_buf             ssl_platform_asn1_buf
#define mbedtls_asn1_sequence        ssl_platform_asn1_sequence
#define mbedtls_asn1_named_data      ssl_platform_asn1_named_data

/* ASN.1 functions */
#define mbedtls_asn1_get_tag         ssl_platform_asn1_get_tag
#define mbedtls_asn1_write_len       ssl_platform_asn1_write_len
#define mbedtls_asn1_write_tag       ssl_platform_asn1_write_tag
#define mbedtls_asn1_write_int       ssl_platform_asn1_write_int
#define mbedtls_asn1_write_mpi       ssl_platform_asn1_write_mpi
#define mbedtls_asn1_write_null      ssl_platform_asn1_write_null
#define mbedtls_asn1_write_oid       ssl_platform_asn1_write_oid
#define mbedtls_asn1_write_bool      ssl_platform_asn1_write_bool
#define mbedtls_asn1_write_ia5_string ssl_platform_asn1_write_ia5_string
#define mbedtls_asn1_write_utf8_string ssl_platform_asn1_write_utf8_string
#define mbedtls_asn1_write_printable_string ssl_platform_asn1_write_printable_string
#define mbedtls_asn1_write_bitstring ssl_platform_asn1_write_bitstring
#define mbedtls_asn1_write_octet_string ssl_platform_asn1_write_octet_string
#define mbedtls_asn1_write_sequence_tag ssl_platform_asn1_write_sequence_tag
#define mbedtls_asn1_write_set_tag   ssl_platform_asn1_write_set_tag

/* =============================================================================
 * STRUCT MEMBER COMPATIBILITY  
 * =============================================================================
 */

/**
 * \brief Compatibility macro to access the underlying mbedTLS PK context
 * The factory-configurator-client code expects ->pk_ctx but our structure uses ->pk_ctx
 * Note: Function definition is provided below in the ECP compatibility section
 */

/* Compatibility macro for the old pk_ctx member access pattern */
#if SSL_PLATFORM_BACKEND == SSL_PLATFORM_BACKEND_MBEDTLS
#define SSL_PLATFORM_PK_CTX_ACCESS(ctx) (mbedtls_pk_get_ctx(ssl_platform_pk_get_mbedtls_context(ctx)))
#else
#define SSL_PLATFORM_PK_CTX_ACCESS(ctx) (NULL)
#endif

/* =============================================================================
 * ECP KEYPAIR COMPATIBILITY MACROS 
 * =============================================================================
 */

#if SSL_PLATFORM_BACKEND == SSL_PLATFORM_BACKEND_MBEDTLS

/* Direct member access compatibility for ECP keypairs */
#define ssl_platform_ecp_keypair_d(keypair)     (&((keypair)->mbedtls_keypair.d))
#define ssl_platform_ecp_keypair_Q(keypair)     (&((keypair)->mbedtls_keypair.Q))
#define ssl_platform_ecp_keypair_grp(keypair)   (&((keypair)->mbedtls_keypair.grp))
#define ssl_platform_ecp_keypair_grp_id(keypair) ((keypair)->mbedtls_keypair.grp.id)

/* Additional compatibility helper functions */
static inline void *ssl_platform_pk_get_mbedtls_context(const ssl_platform_pk_context_t *ctx)
{
    if (ctx != NULL) {
        return (void*)&ctx->pk_ctx;
    }
    return NULL;
}

static inline mbedtls_ecp_keypair *ssl_platform_pk_get_ecp_keypair_direct(const ssl_platform_pk_context_t *ctx)
{
    if (ctx != NULL) {
        return (mbedtls_ecp_keypair*)mbedtls_pk_ec(ctx->pk_ctx);
    }
    return NULL;
}

static inline mbedtls_ecp_group *ssl_platform_ecp_group_get_mbedtls(const ssl_platform_ecp_group_t *grp)
{
    if (grp != NULL) {
        return (mbedtls_ecp_group*)&grp->mbedtls_grp;
    }
    return NULL;
}

static inline mbedtls_mpi *ssl_platform_mpi_get_mbedtls(const ssl_platform_mpi_t *mpi)
{
    if (mpi != NULL) {
        return (mbedtls_mpi*)&mpi->mbedtls_mpi;
    }
    return NULL;
}

#else

/* For non-mbedTLS backends (OpenSSL), provide compatibility stubs */
#define ssl_platform_ecp_keypair_d(keypair)     (NULL)
#define ssl_platform_ecp_keypair_Q(keypair)     (NULL) 
#define ssl_platform_ecp_keypair_grp(keypair)   (NULL)
#define ssl_platform_ecp_keypair_grp_id(keypair) (0)

static inline void *ssl_platform_pk_get_mbedtls_context(const ssl_platform_pk_context_t *ctx) { (void)ctx; return NULL; }
static inline void *ssl_platform_pk_get_ecp_keypair_direct(const ssl_platform_pk_context_t *ctx) { (void)ctx; return NULL; }
static inline void *ssl_platform_ecp_group_get_mbedtls(const ssl_platform_ecp_group_t *grp) { (void)grp; return NULL; }
static inline void *ssl_platform_mpi_get_mbedtls(const ssl_platform_mpi_t *mpi) { (void)mpi; return NULL; }

#endif

/* =============================================================================
 * FACTORY-CONFIGURATOR-CLIENT COMPATIBILITY LAYER
 * =============================================================================
 */

/* 
 * The factory-configurator-client code makes direct member accesses and function calls
 * that were designed for mbedTLS. We need to intercept these and provide compatibility.
 */

#if SSL_PLATFORM_BACKEND == SSL_PLATFORM_BACKEND_MBEDTLS

/*
 * For mbedTLS backend, we can provide relatively direct access since the underlying
 * implementation is mbedTLS anyway.
 */

/* PK context member access compatibility */
static inline void **ssl_platform_pk_get_ctx_ptr(ssl_platform_pk_context_t *ctx)
{
    if (ctx != NULL) {
        ctx->pk_ctx = mbedtls_pk_ec(ctx->pk_ctx);  /* Store the EC key pointer */
        return &ctx->pk_ctx;
    }
    return NULL;
}

/* Macro to simulate ->pk_ctx access */
#define SSL_PLATFORM_PK_CTX_ACCESS(ctx) (ssl_platform_pk_get_ecp_keypair_direct(ctx))

/* ECP keypair member access through SSL platform types */
#define SSL_PLATFORM_ECP_D(keypair) (&((ssl_platform_ecp_keypair_t*)(keypair))->mbedtls_keypair.d)
#define SSL_PLATFORM_ECP_Q(keypair) (&((ssl_platform_ecp_keypair_t*)(keypair))->mbedtls_keypair.Q)
#define SSL_PLATFORM_ECP_GRP_ID(keypair) (((ssl_platform_ecp_keypair_t*)(keypair))->mbedtls_keypair.grp.id)

#else  /* OpenSSL backend */

/*
 * For OpenSSL backend, we need to provide stub implementations since the factory-configurator-client
 * code is trying to do mbedTLS-specific operations that don't have direct OpenSSL equivalents.
 */

/* 
 * For OpenSSL backend, we can't access structure members directly from the compatibility header
 * because the structure may not be fully defined at this point. Instead, we provide stubs 
 * that return NULL/0 to gracefully handle the factory-configurator-client calls.
 */

/* Forward declaration for the function that will be implemented in the OpenSSL source */
void **ssl_platform_pk_get_ctx_ptr_openssl(ssl_platform_pk_context_t *ctx);

/* PK context member access compatibility - forward to implementation */
static inline void **ssl_platform_pk_get_ctx_ptr(ssl_platform_pk_context_t *ctx)
{
    /* Forward to implementation in the OpenSSL source file */
    return ssl_platform_pk_get_ctx_ptr_openssl(ctx);
}

/* Macro to simulate ->pk_ctx access */
#define SSL_PLATFORM_PK_CTX_ACCESS(ctx) (NULL)

/* ECP keypair member access stubs for OpenSSL */
#define SSL_PLATFORM_ECP_D(keypair) (NULL)
#define SSL_PLATFORM_ECP_Q(keypair) (NULL)
#define SSL_PLATFORM_ECP_GRP_ID(keypair) (0)

#endif

/* 
 * Factory-configurator-client compatibility macros
 * These redirect the direct member access patterns to our compatibility layer
 */

/* When code does: (mbedtls_ecp_keypair*)ctx->pk_ctx */
#define MBEDTLS_ECP_FROM_PK_CTX(ctx) ((mbedtls_ecp_keypair*)SSL_PLATFORM_PK_CTX_ACCESS(ctx))

/* When code does: keypair->d */
#define MBEDTLS_ECP_KEYPAIR_D(keypair) SSL_PLATFORM_ECP_D(keypair)

/* When code does: keypair->Q */  
#define MBEDTLS_ECP_KEYPAIR_Q(keypair) SSL_PLATFORM_ECP_Q(keypair)

/* When code does: keypair->grp.id */
#define MBEDTLS_ECP_KEYPAIR_GRP_ID(keypair) SSL_PLATFORM_ECP_GRP_ID(keypair)

/*
 * Enhanced compatibility layer for factory-configurator-client code
 * Since we're using mbedTLS backend, SSL platform structures are just wrappers around mbedTLS structures.
 * We can provide simple unwrapping macros to give direct access to the underlying mbedTLS structures.
 */

#if SSL_PLATFORM_BACKEND == SSL_PLATFORM_BACKEND_MBEDTLS

/*
 * Type unwrapping macros: Convert SSL platform types to underlying mbedTLS types
 * This allows factory-configurator-client code to access mbedTLS structures directly
 */

/* Unwrap SSL platform structures to mbedTLS structures */
#define SSL_TO_MBEDTLS_ECP_KEYPAIR(ssl_keypair) (&((ssl_keypair)->mbedtls_keypair))
#define SSL_TO_MBEDTLS_MPI(ssl_mpi) (&((ssl_mpi)->mbedtls_mpi))
#define SSL_TO_MBEDTLS_ECP_GROUP(ssl_grp) (&((ssl_grp)->mbedtls_grp))
#define SSL_TO_MBEDTLS_ECP_POINT(ssl_pt) (&((ssl_pt)->mbedtls_pt))
#define SSL_TO_MBEDTLS_PK_CONTEXT(ssl_pk) (&((ssl_pk)->pk_ctx))

/* 
 * Redirect factory-configurator-client function calls to use unwrapped types
 * These macros intercept calls and convert SSL platform types to mbedTLS types
 */

/* Override mbedTLS function calls to handle SSL platform types */
#undef mbedtls_ecdh_get_params
#define mbedtls_ecdh_get_params(ctx, key, side) \
    mbedtls_ecdh_get_params(ctx, \
        (const mbedtls_ecp_keypair*)SSL_TO_MBEDTLS_ECP_KEYPAIR((ssl_platform_ecp_keypair_t*)(key)), \
        side)

#undef mbedtls_ecdsa_from_keypair  
#define mbedtls_ecdsa_from_keypair(ctx, key) \
    mbedtls_ecdsa_from_keypair(ctx, \
        (const mbedtls_ecp_keypair*)SSL_TO_MBEDTLS_ECP_KEYPAIR((ssl_platform_ecp_keypair_t*)(key)))

#undef mbedtls_ecp_group_copy
#define mbedtls_ecp_group_copy(dst, src) \
    mbedtls_ecp_group_copy(dst, \
        (const mbedtls_ecp_group*)SSL_TO_MBEDTLS_ECP_GROUP((ssl_platform_ecp_group_t*)(src)))

#undef mbedtls_asn1_get_mpi
#define mbedtls_asn1_get_mpi(p, end, X) \
    mbedtls_asn1_get_mpi(p, end, \
        (mbedtls_mpi*)SSL_TO_MBEDTLS_MPI((ssl_platform_mpi_t*)(X)))

/* The mbedtls_x509write_csr_set_key function should work directly since 
 * ssl_platform_pk_get_backend_context() returns the correct mbedtls_pk_context*
 * No macro redirection needed - the error suggests a type detection issue. */

#undef ssl_platform_mpi_copy
#define ssl_platform_mpi_copy(X, Y) \
    mbedtls_mpi_copy( \
        (mbedtls_mpi*)SSL_TO_MBEDTLS_MPI((ssl_platform_mpi_t*)(X)), \
        (const mbedtls_mpi*)SSL_TO_MBEDTLS_MPI((ssl_platform_mpi_t*)(Y)))

#undef ssl_platform_asn1_write_mpi
#define ssl_platform_asn1_write_mpi(p, start, X) \
    mbedtls_asn1_write_mpi(p, start, \
        (const mbedtls_mpi*)SSL_TO_MBEDTLS_MPI((ssl_platform_mpi_t*)(X)))

/*
 * When factory-configurator-client casts (mbedtls_ecp_keypair*)ctx->pk_ctx,
 * we return the underlying mbedTLS keypair
 */
#undef SSL_PLATFORM_PK_CTX_ACCESS  
#define SSL_PLATFORM_PK_CTX_ACCESS(ctx) ((void*)mbedtls_pk_ec(SSL_TO_MBEDTLS_PK_CONTEXT(ctx)))

/*
 * Factory-configurator-client expects to be able to cast ssl_platform types
 * to mbedTLS types and access their members directly. 
 * 
 * Since we can't override C-style casting, we need to ensure that 
 * ssl_platform_pk_get_backend_context() returns an mbedTLS PK context
 * that can be directly used by the factory-configurator-client code.
 * 
 * The key insight is that the factory-configurator-client code does:
 * 1. Gets backend context: mbedtls_pk_context *ctx = ssl_platform_pk_get_backend_context(ssl_key)
 * 2. Accesses pk_ctx: ctx->pk_ctx  
 * 3. Casts to ECP keypair: (mbedtls_ecp_keypair*)ctx->pk_ctx
 * 4. Accesses members: ->d, ->Q, ->grp.id
 *
 * For this to work, ssl_platform_pk_get_backend_context() must return 
 * a pointer to the actual mbedTLS PK context from our SSL platform wrapper.
 */

#else  /* OpenSSL backend */

/* For OpenSSL, we can't provide the same direct access, so return safe defaults */
#undef SSL_PLATFORM_PK_CTX_ACCESS
#define SSL_PLATFORM_PK_CTX_ACCESS(ctx) (NULL)

#endif

/* =============================================================================
 * FUNCTION COMPATIBILITY WRAPPERS
 * =============================================================================
 */

#if SSL_PLATFORM_BACKEND == SSL_PLATFORM_BACKEND_MBEDTLS

/* Direct mbedTLS access functions for compatibility */
#define mbedtls_pk_ec(ctx)  mbedtls_pk_ec(ctx)

/*
 * Enhanced function compatibility wrappers for factory-configurator-client
 * These handle both SSL platform types and provide graceful fallbacks for OpenSSL backend
 */

/* Enhanced compatibility wrapper functions */
#if SSL_PLATFORM_BACKEND == SSL_PLATFORM_BACKEND_MBEDTLS

/* Include the actual mbedTLS headers to call original functions */
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/asn1.h"
#include "mbedtls/x509_csr.h"

/* Use macro to get access to original mbedTLS functions */
#define MBEDTLS_ECDH_GET_PARAMS_ORIG  mbedtls_ecdh_get_params
#define MBEDTLS_ECDSA_FROM_KEYPAIR_ORIG  mbedtls_ecdsa_from_keypair  
#define MBEDTLS_ECP_GROUP_COPY_ORIG  mbedtls_ecp_group_copy
#define MBEDTLS_ASN1_GET_MPI_ORIG  mbedtls_asn1_get_mpi
#define MBEDTLS_X509WRITE_CSR_SET_KEY_ORIG  mbedtls_x509write_csr_set_key

static inline int ssl_platform_ecdh_get_params_enhanced(mbedtls_ecdh_context *ctx, 
                                                        void *key, 
                                                        mbedtls_ecdh_side side)
{
    /* For mbedTLS backend, try to get the underlying mbedTLS keypair */
    ssl_platform_ecp_keypair_t *ssl_key = (ssl_platform_ecp_keypair_t *)key;
    if (ssl_key) {
        /* Call original mbedTLS function directly */
        extern int MBEDTLS_ECDH_GET_PARAMS_ORIG(mbedtls_ecdh_context *ctx, const mbedtls_ecp_keypair *key, mbedtls_ecdh_side side);
        return MBEDTLS_ECDH_GET_PARAMS_ORIG(ctx, &ssl_key->mbedtls_keypair, side);
    }
    return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
}

static inline int ssl_platform_ecdsa_from_keypair_enhanced(mbedtls_ecdsa_context *ctx,
                                                          void *key)
{
    ssl_platform_ecp_keypair_t *ssl_key = (ssl_platform_ecp_keypair_t *)key;
    if (ssl_key) {
        extern int MBEDTLS_ECDSA_FROM_KEYPAIR_ORIG(mbedtls_ecdsa_context *ctx, const mbedtls_ecp_keypair *key);
        return MBEDTLS_ECDSA_FROM_KEYPAIR_ORIG(ctx, &ssl_key->mbedtls_keypair);
    }
    return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
}

static inline int ssl_platform_ecp_group_copy_enhanced(mbedtls_ecp_group *dst,
                                                       void *src)
{
    ssl_platform_ecp_group_t *ssl_grp = (ssl_platform_ecp_group_t *)src;
    if (ssl_grp) {
        extern int MBEDTLS_ECP_GROUP_COPY_ORIG(mbedtls_ecp_group *dst, const mbedtls_ecp_group *src);
        return MBEDTLS_ECP_GROUP_COPY_ORIG(dst, &ssl_grp->mbedtls_grp);
    }
    return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
}

static inline int ssl_platform_asn1_get_mpi_enhanced(unsigned char **p, 
                                                     const unsigned char *end,
                                                     void *X)
{
    ssl_platform_mpi_t *ssl_mpi = (ssl_platform_mpi_t *)X;
    if (ssl_mpi) {
        extern int MBEDTLS_ASN1_GET_MPI_ORIG(unsigned char **p, const unsigned char *end, mbedtls_mpi *X);
        return MBEDTLS_ASN1_GET_MPI_ORIG(p, end, &ssl_mpi->mbedtls_mpi);
    }
    return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
}

static inline void ssl_platform_x509write_csr_set_key_enhanced(mbedtls_x509write_csr *ctx, 
                                                               void *key)
{
    ssl_platform_pk_context_t *ssl_key = (ssl_platform_pk_context_t *)key;
    if (ssl_key) {
        extern void MBEDTLS_X509WRITE_CSR_SET_KEY_ORIG(mbedtls_x509write_csr *ctx, mbedtls_pk_context *key);
        MBEDTLS_X509WRITE_CSR_SET_KEY_ORIG(ctx, &ssl_key->pk_ctx);
    }
}

#else  /* OpenSSL backend */

static inline int ssl_platform_ecdh_get_params_enhanced(void *ctx, void *key, int side)
{
    /* For OpenSSL backend, return not supported */
    (void)ctx; (void)key; (void)side;
    return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
}

static inline int ssl_platform_ecdsa_from_keypair_enhanced(void *ctx, void *key)
{
    (void)ctx; (void)key;
    return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
}

static inline int ssl_platform_ecp_group_copy_enhanced(void *dst, void *src)
{
    (void)dst; (void)src;
    return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
}

static inline int ssl_platform_asn1_get_mpi_enhanced(unsigned char **p, 
                                                     const unsigned char *end,
                                                     void *X)
{
    (void)p; (void)end; (void)X;
    return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
}

static inline void ssl_platform_x509write_csr_set_key_enhanced(void *ctx, void *key)
{
    (void)ctx; (void)key;
}

#endif

/* 
 * Function redirection macros for factory-configurator-client compatibility
 * These intercept the function calls and redirect them to our enhanced wrappers
 */
#undef mbedtls_ecdh_get_params
#define mbedtls_ecdh_get_params(ctx, key, side) ssl_platform_ecdh_get_params_enhanced(ctx, (void*)(key), side)

#undef mbedtls_ecdsa_from_keypair  
#define mbedtls_ecdsa_from_keypair(ctx, key) ssl_platform_ecdsa_from_keypair_enhanced(ctx, (void*)(key))

#undef mbedtls_ecp_group_copy
#define mbedtls_ecp_group_copy(dst, src) ssl_platform_ecp_group_copy_enhanced(dst, (void*)(src))

#undef mbedtls_asn1_get_mpi
#define mbedtls_asn1_get_mpi(p, end, X) ssl_platform_asn1_get_mpi_enhanced(p, end, (void*)(X))

#undef mbedtls_x509write_csr_set_key
#define mbedtls_x509write_csr_set_key(ctx, key) ssl_platform_x509write_csr_set_key_enhanced(ctx, (void*)(key))

#endif /* SSL_PLATFORM_BACKEND == SSL_PLATFORM_BACKEND_MBEDTLS */

#ifdef __cplusplus
}
#endif

#endif /* SSL_PLATFORM_COMPAT_H */ 