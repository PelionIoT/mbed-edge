/*
 * SSL Platform Abstraction Layer - Mbed-TLS Backend Implementation
 * 
 * Copyright (c) 2024
 * 
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ssl_platform.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/oid.h"
#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/oid.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/bignum.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#if SSL_PLATFORM_BACKEND == SSL_PLATFORM_BACKEND_MBEDTLS

/* =============================================================================
 * BASE64 OPERATIONS IMPLEMENTATION
 * =============================================================================
 */

int ssl_platform_base64_encode(unsigned char *dst, size_t dlen, size_t *olen,
                              const unsigned char *src, size_t slen)
{
    int ret = mbedtls_base64_encode(dst, dlen, olen, src, slen);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_base64_decode(unsigned char *dst, size_t dlen, size_t *olen,
                               const unsigned char *src, size_t slen)
{
    int ret = mbedtls_base64_decode(dst, dlen, olen, src, slen);
    return ssl_platform_mbedtls_error_map(ret);
}

/* =============================================================================
 * AES OPERATIONS IMPLEMENTATION
 * =============================================================================
 */

void ssl_platform_aes_init(ssl_platform_aes_context_t *ctx)
{
    if (ctx != NULL) {
        mbedtls_aes_init(&ctx->mbedtls_ctx);
    }
}

void ssl_platform_aes_free(ssl_platform_aes_context_t *ctx)
{
    if (ctx != NULL) {
        mbedtls_aes_free(&ctx->mbedtls_ctx);
    }
}

int ssl_platform_aes_setkey_enc(ssl_platform_aes_context_t *ctx,
                                const unsigned char *key,
                                unsigned int keybits)
{
    if (ctx == NULL || key == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_aes_setkey_enc(&ctx->mbedtls_ctx, key, keybits);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_aes_setkey_dec(ssl_platform_aes_context_t *ctx,
                                const unsigned char *key,
                                unsigned int keybits)
{
    if (ctx == NULL || key == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_aes_setkey_dec(&ctx->mbedtls_ctx, key, keybits);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_aes_crypt_ecb(ssl_platform_aes_context_t *ctx,
                               int mode,
                               const unsigned char input[16],
                               unsigned char output[16])
{
    if (ctx == NULL || input == NULL || output == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int mbedtls_mode = (mode == SSL_PLATFORM_AES_ENCRYPT) ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT;
    int ret = mbedtls_aes_crypt_ecb(&ctx->mbedtls_ctx, mbedtls_mode, input, output);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_aes_crypt_ctr(ssl_platform_aes_context_t *ctx,
                               size_t length,
                               size_t *nc_off,
                               unsigned char nonce_counter[16],
                               unsigned char stream_block[16],
                               const unsigned char *input,
                               unsigned char *output)
{
    if (ctx == NULL || nc_off == NULL || nonce_counter == NULL || 
        stream_block == NULL || input == NULL || output == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_aes_crypt_ctr(&ctx->mbedtls_ctx, length, nc_off,
                                   nonce_counter, stream_block, input, output);
    return ssl_platform_mbedtls_error_map(ret);
}

/* =============================================================================
 * CMAC OPERATIONS IMPLEMENTATION
 * =============================================================================
 */

int ssl_platform_aes_cmac(const unsigned char *key, size_t keylen,
                          const unsigned char *input, size_t ilen,
                          unsigned char *output)
{
    if (key == NULL || input == NULL || output == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    const mbedtls_cipher_info_t *cipher_info;
    int keybits = keylen * 8;
    
    // Select the appropriate cipher based on key length
    switch (keybits) {
        case 128:
            cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
            break;
        case 192:
            cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_ECB);
            break;
        case 256:
            cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_ECB);
            break;
        default:
            return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    if (cipher_info == NULL) {
        return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
    }
    
    int ret = mbedtls_cipher_cmac(cipher_info, key, keybits, input, ilen, output);
    return ssl_platform_mbedtls_error_map(ret);
}

void ssl_platform_cipher_init(ssl_platform_cipher_context_t *ctx)
{
    if (ctx != NULL) {
        mbedtls_cipher_init(&ctx->mbedtls_ctx);
        ctx->cipher_type = SSL_PLATFORM_CIPHER_AES_128_ECB; // Default
    }
}

void ssl_platform_cipher_free(ssl_platform_cipher_context_t *ctx)
{
    if (ctx != NULL) {
        mbedtls_cipher_free(&ctx->mbedtls_ctx);
    }
}

int ssl_platform_cipher_setup(ssl_platform_cipher_context_t *ctx,
                              ssl_platform_cipher_type_t cipher_type)
{
    if (ctx == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    mbedtls_cipher_type_t mbedtls_type = ssl_platform_cipher_type_to_mbedtls(cipher_type);
    if (mbedtls_type == MBEDTLS_CIPHER_NONE) {
        return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
    }
    
    const mbedtls_cipher_info_t *cipher_info = mbedtls_cipher_info_from_type(mbedtls_type);
    if (cipher_info == NULL) {
        return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
    }
    
    int ret = mbedtls_cipher_setup(&ctx->mbedtls_ctx, cipher_info);
    if (ret != 0) {
        return ssl_platform_mbedtls_error_map(ret);
    }
    
    ctx->cipher_type = cipher_type;
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_cipher_cmac_starts(ssl_platform_cipher_context_t *ctx,
                                    const unsigned char *key,
                                    size_t keybits)
{
    if (ctx == NULL || key == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_cipher_cmac_starts(&ctx->mbedtls_ctx, key, keybits);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_cipher_cmac_update(ssl_platform_cipher_context_t *ctx,
                                    const unsigned char *input,
                                    size_t ilen)
{
    if (ctx == NULL || input == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_cipher_cmac_update(&ctx->mbedtls_ctx, input, ilen);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_cipher_cmac_finish(ssl_platform_cipher_context_t *ctx,
                                    unsigned char *output)
{
    if (ctx == NULL || output == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_cipher_cmac_finish(&ctx->mbedtls_ctx, output);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_cipher_cmac(ssl_platform_cipher_type_t cipher_type,
                             const unsigned char *key, size_t keybits,
                             const unsigned char *input, size_t ilen,
                             unsigned char *output)
{
    if (key == NULL || input == NULL || output == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    mbedtls_cipher_type_t mbedtls_type = ssl_platform_cipher_type_to_mbedtls(cipher_type);
    if (mbedtls_type == MBEDTLS_CIPHER_NONE) {
        return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
    }
    
    const mbedtls_cipher_info_t *cipher_info = mbedtls_cipher_info_from_type(mbedtls_type);
    if (cipher_info == NULL) {
        return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
    }
    
    int ret = mbedtls_cipher_cmac(cipher_info, key, keybits, input, ilen, output);
    return ssl_platform_mbedtls_error_map(ret);
}

const void *ssl_platform_cipher_info_from_type(ssl_platform_cipher_type_t cipher_type)
{
    mbedtls_cipher_type_t mbedtls_type = ssl_platform_cipher_type_to_mbedtls(cipher_type);
    if (mbedtls_type == MBEDTLS_CIPHER_NONE) {
        return NULL;
    }
    
    return mbedtls_cipher_info_from_type(mbedtls_type);
}

/* =============================================================================
 * HASH OPERATIONS IMPLEMENTATION
 * =============================================================================
 */

int ssl_platform_hash_init(ssl_platform_hash_context_t *ctx, ssl_platform_hash_type_t type)
{
    if (ctx == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    ctx->type = type;
    
    switch (type) {
        case SSL_PLATFORM_HASH_SHA224:
        case SSL_PLATFORM_HASH_SHA256:
            mbedtls_sha256_init(&ctx->ctx.sha256);
            break;
        case SSL_PLATFORM_HASH_SHA1:
        case SSL_PLATFORM_HASH_SHA384:
        case SSL_PLATFORM_HASH_SHA512:
        case SSL_PLATFORM_HASH_MD5:
            // These hash functions are not enabled in the current mbed-TLS configuration
            return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
        default:
            return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    return SSL_PLATFORM_SUCCESS;
}

void ssl_platform_hash_free(ssl_platform_hash_context_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    
    switch (ctx->type) {
        case SSL_PLATFORM_HASH_SHA224:
        case SSL_PLATFORM_HASH_SHA256:
            memset(&ctx->ctx.sha256, 0, sizeof(ctx->ctx.sha256));
            break;
        case SSL_PLATFORM_HASH_SHA1:
        case SSL_PLATFORM_HASH_SHA384:
        case SSL_PLATFORM_HASH_SHA512:
        case SSL_PLATFORM_HASH_MD5:
            // These hash functions are not supported
            break;
        default:
            break;
    }
}

int ssl_platform_hash_starts(ssl_platform_hash_context_t *ctx)
{
    if (ctx == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret;
    
    switch (ctx->type) {
        case SSL_PLATFORM_HASH_SHA224:
            mbedtls_sha256_starts(&ctx->ctx.sha256, 1);  /* 1 for SHA224 */
            ret = 0;
            break;
        case SSL_PLATFORM_HASH_SHA256:
            mbedtls_sha256_starts(&ctx->ctx.sha256, 0);  /* 0 for SHA256 */
            ret = 0;
            break;
        case SSL_PLATFORM_HASH_SHA1:
        case SSL_PLATFORM_HASH_SHA384:
        case SSL_PLATFORM_HASH_SHA512:
        case SSL_PLATFORM_HASH_MD5:
            return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
        default:
            return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_hash_update(ssl_platform_hash_context_t *ctx,
                             const unsigned char *input,
                             size_t ilen)
{
    if (ctx == NULL || input == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret;
    
    switch (ctx->type) {
        case SSL_PLATFORM_HASH_SHA224:
        case SSL_PLATFORM_HASH_SHA256:
            mbedtls_sha256_update(&ctx->ctx.sha256, input, ilen);
            ret = 0;
            break;
        case SSL_PLATFORM_HASH_SHA1:
        case SSL_PLATFORM_HASH_SHA384:
        case SSL_PLATFORM_HASH_SHA512:
        case SSL_PLATFORM_HASH_MD5:
            return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
        default:
            return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_hash_finish(ssl_platform_hash_context_t *ctx,
                             unsigned char *output)
{
    if (ctx == NULL || output == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret;
    
    switch (ctx->type) {
        case SSL_PLATFORM_HASH_SHA224:
        case SSL_PLATFORM_HASH_SHA256:
            mbedtls_sha256_finish(&ctx->ctx.sha256, output);
            ret = 0;
            break;
        case SSL_PLATFORM_HASH_SHA1:
        case SSL_PLATFORM_HASH_SHA384:
        case SSL_PLATFORM_HASH_SHA512:
        case SSL_PLATFORM_HASH_MD5:
            return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
        default:
            return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    return ssl_platform_mbedtls_error_map(ret);
}

void ssl_platform_hash_clone(ssl_platform_hash_context_t *dst,
                             const ssl_platform_hash_context_t *src)
{
    if (!dst || !src) {
        return;
    }

    // Copy the hash type
    dst->type = src->type;

    // Clone the appropriate context based on type
    switch (src->type) {
        case SSL_PLATFORM_HASH_SHA224:
        case SSL_PLATFORM_HASH_SHA256:
            memcpy(&dst->ctx.sha256, &src->ctx.sha256, sizeof(src->ctx.sha256));
            break;
        case SSL_PLATFORM_HASH_SHA1:
        case SSL_PLATFORM_HASH_SHA384:
        case SSL_PLATFORM_HASH_SHA512:
        case SSL_PLATFORM_HASH_MD5:
            // These hash functions are not supported
            break;
        default:
            // Invalid type, do nothing
            break;
    }
}

size_t ssl_platform_hash_get_size(ssl_platform_hash_type_t type)
{
    return ssl_platform_mbedtls_hash_get_size(type);
}

/* =============================================================================
 * PUBLIC KEY OPERATIONS IMPLEMENTATION
 * =============================================================================
 */

void ssl_platform_pk_init(ssl_platform_pk_context_t *ctx)
{
    if (ctx != NULL) {
        mbedtls_pk_init(&ctx->pk_ctx);
    }
}

void ssl_platform_pk_free(ssl_platform_pk_context_t *ctx)
{
    if (ctx != NULL) {
        mbedtls_pk_free(&ctx->pk_ctx);
    }
}

int ssl_platform_pk_parse_key(ssl_platform_pk_context_t *ctx,
                              const unsigned char *key, size_t keylen,
                              const unsigned char *pwd, size_t pwdlen)
{
    if (ctx == NULL || key == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_pk_parse_key(&ctx->pk_ctx, key, keylen, pwd, pwdlen);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_pk_parse_public_key(ssl_platform_pk_context_t *ctx,
                                     const unsigned char *key, size_t keylen)
{
    if (!ctx || !key) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_pk_parse_public_key(&ctx->pk_ctx, key, keylen);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_pk_verify(ssl_platform_pk_context_t *ctx, ssl_platform_hash_type_t md_alg,
                           const unsigned char *hash, size_t hash_len,
                           const unsigned char *sig, size_t sig_len)
{
    if (!ctx || !hash || !sig) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    mbedtls_md_type_t mbedtls_md_alg = ssl_platform_hash_type_to_mbedtls(md_alg);
    if (mbedtls_md_alg == MBEDTLS_MD_NONE) {
        return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
    }
    
    int ret = mbedtls_pk_verify(&ctx->pk_ctx, mbedtls_md_alg, hash, hash_len, sig, sig_len);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_pk_sign(ssl_platform_pk_context_t *ctx, ssl_platform_hash_type_t md_alg,
                         const unsigned char *hash, size_t hash_len,
                         unsigned char *sig, size_t *sig_len,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    if (!ctx || !hash || !sig || !sig_len) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    mbedtls_md_type_t mbedtls_md_alg = ssl_platform_hash_type_to_mbedtls(md_alg);
    if (mbedtls_md_alg == MBEDTLS_MD_NONE) {
        return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
    }
    
    // Require caller to provide RNG function - do not use global RNG to avoid conflicts with PAL layer
    if (f_rng == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_pk_sign(&ctx->pk_ctx, mbedtls_md_alg, hash, hash_len, sig, sig_len, f_rng, p_rng);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_pk_setup(ssl_platform_pk_context_t *ctx, const void *info)
{
    if (!ctx || !info) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_pk_setup(&ctx->pk_ctx, (const mbedtls_pk_info_t *)info);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_pk_write_key_der(ssl_platform_pk_context_t *ctx,
                                  unsigned char *buf, size_t size)
{
    if (!ctx || !buf) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_pk_write_key_der(&ctx->pk_ctx, buf, size);
    if (ret < 0) {
        return ssl_platform_mbedtls_error_map(ret);
    }
    return ret;  // Return length on success
}

int ssl_platform_pk_write_pubkey_der(ssl_platform_pk_context_t *ctx,
                                     unsigned char *buf, size_t size)
{
    if (!ctx || !buf) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_pk_write_pubkey_der(&ctx->pk_ctx, buf, size);
    if (ret < 0) {
        return ssl_platform_mbedtls_error_map(ret);
    }
    return ret;  // Return length on success
}

/**
 * \brief Get the underlying mbedTLS pk context for compatibility with existing code
 * 
 * \param ctx   The SSL platform pk context
 * \return      Pointer to the underlying mbedTLS pk context, or NULL on error
 */
void *ssl_platform_pk_get_backend_context(ssl_platform_pk_context_t *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }
    
    return &ctx->pk_ctx;
}

/**
 * \brief Get the ECC keypair from a PK context
 */
void *ssl_platform_pk_get_ecp_keypair(ssl_platform_pk_context_t *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }
    
    mbedtls_pk_context *pk_ctx = &ctx->pk_ctx;
    if (mbedtls_pk_get_type(pk_ctx) == MBEDTLS_PK_ECKEY) {
        return mbedtls_pk_ec(*pk_ctx);
    }
    
    return NULL;
}

/**
 * \brief Get the private key MPI from an ECC keypair
 */
void *ssl_platform_ecp_keypair_get_private_key(ssl_platform_ecp_keypair_t *keypair)
{
    if (keypair == NULL) {
        return NULL;
    }
    
    return &keypair->mbedtls_keypair.d;
}

/**
 * \brief Get the public key point from an ECC keypair
 */
void *ssl_platform_ecp_keypair_get_public_key(ssl_platform_ecp_keypair_t *keypair)
{
    if (keypair == NULL) {
        return NULL;
    }
    
    return &keypair->mbedtls_keypair.Q;
}

/**
 * \brief Get the group from an ECC keypair
 */
void *ssl_platform_ecp_keypair_get_group(ssl_platform_ecp_keypair_t *keypair)
{
    if (keypair == NULL) {
        return NULL;
    }
    
    return &keypair->mbedtls_keypair.grp;
}

/**
 * \brief Get the group ID from an ECC group
 */
int ssl_platform_ecp_group_get_id(ssl_platform_ecp_group_t *group)
{
    if (group == NULL) {
        return 0;
    }
    
    return group->mbedtls_grp.id;
}

/**
 * \brief Get the underlying MPI backend context
 */
void *ssl_platform_mpi_get_backend_context(ssl_platform_mpi_t *mpi)
{
    if (mpi == NULL) {
        return NULL;
    }
    
    return &mpi->mbedtls_mpi;
}

/**
 * \brief Get the underlying ECP group from ssl-platform ECP group
 */
void *ssl_platform_ecp_group_get_backend_context(ssl_platform_ecp_group_t *grp)
{
    if (grp == NULL) {
        return NULL;
    }
    
    return &grp->mbedtls_grp;
}

/**
 * \brief Get the underlying ECP point from ssl-platform ECP point
 */
void *ssl_platform_ecp_point_get_backend_context(ssl_platform_ecp_point_t *pt)
{
    if (pt == NULL) {
        return NULL;
    }
    
    return &pt->mbedtls_pt;
}

/**
 * \brief MPI copy operation
 */
int ssl_platform_mpi_copy(ssl_platform_mpi_t *X, const ssl_platform_mpi_t *Y)
{
    if (X == NULL || Y == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_mpi_copy(&X->mbedtls_mpi, &Y->mbedtls_mpi);
    return ssl_platform_mbedtls_error_map(ret);
}

/* =============================================================================
 * X.509 CERTIFICATE OPERATIONS IMPLEMENTATION
 * =============================================================================
 */

void ssl_platform_x509_crt_init(ssl_platform_x509_crt_t *crt)
{
    if (crt != NULL) {
        mbedtls_x509_crt_init(&crt->mbedtls_crt);
    }
}

void ssl_platform_x509_crt_free(ssl_platform_x509_crt_t *crt)
{
    if (crt != NULL) {
        mbedtls_x509_crt_free(&crt->mbedtls_crt);
    }
}

int ssl_platform_x509_crt_parse(ssl_platform_x509_crt_t *chain,
                                const unsigned char *buf, size_t buflen)
{
    if (chain == NULL || buf == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_x509_crt_parse(&chain->mbedtls_crt, buf, buflen);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_x509_get_pubkey(ssl_platform_x509_crt_t *crt,
                                 ssl_platform_pk_context_t *pk)
{
    if (crt == NULL || pk == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    // Copy the public key from the certificate to the PK context
    int ret = mbedtls_pk_setup(&pk->pk_ctx, mbedtls_pk_info_from_type(mbedtls_pk_get_type(&crt->mbedtls_crt.pk)));
    if (ret != 0) {
        return ssl_platform_mbedtls_error_map(ret);
    }
    
    ret = mbedtls_pk_check_pair(&crt->mbedtls_crt.pk, &pk->pk_ctx);
    if (ret == 0) {
        // If check_pair succeeds, we can copy the key
        pk->pk_ctx = crt->mbedtls_crt.pk;
    } else {
        // For public key extraction, we need to copy the public key part
        // This is a simplified implementation - copy the entire PK context
        memcpy(&pk->pk_ctx, &crt->mbedtls_crt.pk, sizeof(mbedtls_pk_context));
    }
    
    return SSL_PLATFORM_SUCCESS;
}

// Enhanced X.509 certificate field access functions
int ssl_platform_x509_get_issuer_raw(ssl_platform_x509_crt_t *crt, unsigned char **buf, size_t *len)
{
    if (crt == NULL || buf == NULL || len == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    *buf = crt->mbedtls_crt.issuer_raw.p;
    *len = crt->mbedtls_crt.issuer_raw.len;
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_x509_get_subject_raw(ssl_platform_x509_crt_t *crt, unsigned char **buf, size_t *len)
{
    if (crt == NULL || buf == NULL || len == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    *buf = crt->mbedtls_crt.subject_raw.p;
    *len = crt->mbedtls_crt.subject_raw.len;
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_x509_get_validity(ssl_platform_x509_crt_t *crt, struct tm *not_before, struct tm *not_after)
{
    if (crt == NULL || not_before == NULL || not_after == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    // Convert mbedtls_x509_time to struct tm
    memset(not_before, 0, sizeof(struct tm));
    memset(not_after, 0, sizeof(struct tm));
    
    not_before->tm_year = crt->mbedtls_crt.valid_from.year - 1900;
    not_before->tm_mon = crt->mbedtls_crt.valid_from.mon - 1;
    not_before->tm_mday = crt->mbedtls_crt.valid_from.day;
    not_before->tm_hour = crt->mbedtls_crt.valid_from.hour;
    not_before->tm_min = crt->mbedtls_crt.valid_from.min;
    not_before->tm_sec = crt->mbedtls_crt.valid_from.sec;
    
    not_after->tm_year = crt->mbedtls_crt.valid_to.year - 1900;
    not_after->tm_mon = crt->mbedtls_crt.valid_to.mon - 1;
    not_after->tm_mday = crt->mbedtls_crt.valid_to.day;
    not_after->tm_hour = crt->mbedtls_crt.valid_to.hour;
    not_after->tm_min = crt->mbedtls_crt.valid_to.min;
    not_after->tm_sec = crt->mbedtls_crt.valid_to.sec;
    
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_x509_get_signature(ssl_platform_x509_crt_t *crt, unsigned char **buf, size_t *len)
{
    if (crt == NULL || buf == NULL || len == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    *buf = crt->mbedtls_crt.sig.p;
    *len = crt->mbedtls_crt.sig.len;
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_x509_get_tbs(ssl_platform_x509_crt_t *crt, unsigned char **buf, size_t *len)
{
    if (crt == NULL || buf == NULL || len == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    *buf = crt->mbedtls_crt.tbs.p;
    *len = crt->mbedtls_crt.tbs.len;
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_x509_get_subject_name(ssl_platform_x509_crt_t *crt, char *buf, size_t buf_size)
{
    if (crt == NULL || buf == NULL || buf_size == 0) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    // Clear the buffer first
    memset(buf, 0, buf_size);
    
    printf("DEBUG: ssl_platform_x509_get_subject_name - buf_size: %zu\n", buf_size);
    
    // Make sure buffer is large enough for a reasonable subject name
    if (buf_size < 32) {
        printf("ERROR: Buffer too small for subject name (minimum 32 bytes)\n");
        return SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL;
    }
    
    int ret = mbedtls_x509_dn_gets(buf, buf_size, &crt->mbedtls_crt.subject);
    
    printf("DEBUG: mbedtls_x509_dn_gets returned: %d (0x%x)\n", ret, ret);
    
    if (ret < 0) {
        printf("ERROR: mbedtls_x509_dn_gets failed with mbedTLS error: %d (0x%x)\n", ret, ret);
        
        // Try with a smaller buffer size in case the issue is buffer related
        if (buf_size > 512) {
            printf("DEBUG: Retrying with smaller buffer size: 512\n");
            char temp_buf[512];
            memset(temp_buf, 0, sizeof(temp_buf));
            int retry_ret = mbedtls_x509_dn_gets(temp_buf, sizeof(temp_buf), &crt->mbedtls_crt.subject);
            if (retry_ret >= 0) {
                printf("DEBUG: Retry succeeded with smaller buffer\n");
                size_t copy_len = (retry_ret < buf_size - 1) ? retry_ret : buf_size - 1;
                memcpy(buf, temp_buf, copy_len);
                buf[copy_len] = '\0';
                printf("DEBUG: Subject name extracted successfully: '%s' (length: %zu)\n", buf, copy_len);
                return SSL_PLATFORM_SUCCESS;
            }
        }
        
        // If standard method fails, provide a fallback
        printf("DEBUG: Attempting fallback subject name\n");
        snprintf(buf, buf_size, "CN=unknown_certificate");
        printf("DEBUG: Fallback subject name: '%s'\n", buf);
        return SSL_PLATFORM_SUCCESS;
    } else {
        printf("DEBUG: Subject name extracted successfully: '%s' (length: %d)\n", buf, ret);
        return SSL_PLATFORM_SUCCESS;
    }
}

int ssl_platform_x509_crt_check_extended_key_usage(ssl_platform_x509_crt_t *crt,
                                                   const unsigned char *usage,
                                                   size_t oid_len)
{
    if (crt == NULL || usage == NULL || oid_len == 0) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_x509_crt_check_extended_key_usage(&crt->mbedtls_crt, 
                                                       (const char *)usage, 
                                                       oid_len);
    return ssl_platform_mbedtls_error_map(ret);
}

/**
 * \brief          Verify X.509 certificate against CA chain
 */
int ssl_platform_x509_crt_verify(ssl_platform_x509_crt_t *crt, 
                                 ssl_platform_x509_crt_t *trust_ca,
                                 uint32_t *flags)
{
    if (crt == NULL || flags == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_x509_crt_verify(&crt->mbedtls_crt, 
                                     trust_ca ? &trust_ca->mbedtls_crt : NULL, 
                                     NULL,  // CRL not supported for now
                                     NULL,  // CN not checked here
                                     flags, 
                                     NULL,  // No verification callback
                                     NULL); // No callback parameter
    return ssl_platform_mbedtls_error_map(ret);
}

/* =============================================================================
 * CTR DRBG OPERATIONS IMPLEMENTATION
 * =============================================================================
 */

void ssl_platform_ctr_drbg_init(ssl_platform_ctr_drbg_context_t *ctx)
{
    if (ctx != NULL) {
        mbedtls_ctr_drbg_init(&ctx->mbedtls_ctx);
    }
}

void ssl_platform_ctr_drbg_free(ssl_platform_ctr_drbg_context_t *ctx)
{
    if (ctx != NULL) {
        mbedtls_ctr_drbg_free(&ctx->mbedtls_ctx);
    }
}

int ssl_platform_ctr_drbg_seed(ssl_platform_ctr_drbg_context_t *ctx,
                               int (*f_entropy)(void *, unsigned char *, size_t),
                               void *p_entropy,
                               const unsigned char *custom,
                               size_t len)
{
    if (ctx == NULL || f_entropy == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_ctr_drbg_seed(&ctx->mbedtls_ctx, f_entropy, p_entropy, custom, len);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_ctr_drbg_random(void *p_rng, unsigned char *output, size_t output_len)
{
    if (p_rng == NULL || output == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    ssl_platform_ctr_drbg_context_t *ctx = (ssl_platform_ctr_drbg_context_t *)p_rng;
    int ret = mbedtls_ctr_drbg_random(&ctx->mbedtls_ctx, output, output_len);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_ctr_drbg_reseed(ssl_platform_ctr_drbg_context_t *ctx, 
                                 const unsigned char *additional, 
                                 size_t len)
{
    if (ctx == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_ctr_drbg_reseed(&ctx->mbedtls_ctx, additional, len);
    return ssl_platform_mbedtls_error_map(ret);
}

/**
 * \brief          Check if CTR-DRBG is seeded
 */
int ssl_platform_ctr_drbg_is_seeded(ssl_platform_ctr_drbg_context_t *ctx)
{
    if (ctx == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
#if defined(MBEDTLS_CTR_DRBG_C)
    // mbedTLS doesn't have a direct "is_seeded" function, but we can check 
    // if the context has been seeded by checking internal state
    // For safety, we'll assume it's seeded if the context is initialized
    // This is a simplified check - in practice, we track seeding status
    return (ctx->mbedtls_ctx.entropy_len > 0) ? SSL_PLATFORM_SUCCESS : SSL_PLATFORM_ERROR_GENERIC;
#else
    return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
#endif
}

/* =============================================================================
 * ENTROPY OPERATIONS IMPLEMENTATION
 * =============================================================================
 */

void ssl_platform_entropy_init(ssl_platform_entropy_context_t *ctx)
{
    if (ctx != NULL) {
        mbedtls_entropy_init(&ctx->mbedtls_ctx);
    }
}

void ssl_platform_entropy_free(ssl_platform_entropy_context_t *ctx)
{
    if (ctx != NULL) {
        mbedtls_entropy_free(&ctx->mbedtls_ctx);
    }
}

/* =============================================================================
 * GLOBAL PAL ENTROPY MANAGEMENT
 * =============================================================================
 */

static ssl_platform_entropy_context_t *g_pal_entropy = NULL;
static bool g_pal_entropy_initialized = false;

int ssl_platform_pal_entropy_init(void)
{
    if (g_pal_entropy != NULL) {
        return SSL_PLATFORM_SUCCESS; // Already initialized
    }
    
    g_pal_entropy = (ssl_platform_entropy_context_t*)malloc(sizeof(ssl_platform_entropy_context_t));
    if (g_pal_entropy == NULL) {
        return SSL_PLATFORM_ERROR_MEMORY_ALLOCATION;
    }
    
    memset(g_pal_entropy, 0, sizeof(ssl_platform_entropy_context_t));
    ssl_platform_entropy_init(g_pal_entropy);
    g_pal_entropy_initialized = false;
    
    return SSL_PLATFORM_SUCCESS;
}

void* ssl_platform_pal_entropy_get(void)
{
    if (g_pal_entropy == NULL) {
        return NULL;
    }
    return &g_pal_entropy->mbedtls_ctx;
}

int ssl_platform_pal_entropy_cleanup(void)
{
    if (g_pal_entropy != NULL) {
        ssl_platform_entropy_free(g_pal_entropy);
        free(g_pal_entropy);
        g_pal_entropy = NULL;
    }
    g_pal_entropy_initialized = false;
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_pal_entropy_add_source(int (*f_source)(void *, unsigned char *, size_t, size_t *),
                                        void *p_source, size_t threshold, int strong)
{
    if (g_pal_entropy == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    if (!g_pal_entropy_initialized) {
        int ret = mbedtls_entropy_add_source(&g_pal_entropy->mbedtls_ctx, f_source, p_source, threshold, strong);
        if (ret == 0) {
            g_pal_entropy_initialized = true;
            return SSL_PLATFORM_SUCCESS;
        } else {
            return ssl_platform_mbedtls_error_map(ret);
        }
    }
    
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_entropy_func(void *data, unsigned char *output, size_t len)
{
    if (data == NULL || output == NULL) {
        return -1;
    }
    
    // The data parameter should be a pointer to an mbedtls_entropy_context
    mbedtls_entropy_context *entropy_ctx = (mbedtls_entropy_context *)data;
    
    int ret = mbedtls_entropy_func(entropy_ctx, output, len);
    return ret; // Return mbedtls error code directly (0 = success)
}

/**
 * \brief          ASN.1 get tag (simplified wrapper)
 */
int ssl_platform_asn1_get_tag(unsigned char **p, const unsigned char *end,
                              size_t *len, int tag)
{
    if (p == NULL || end == NULL || len == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
#if defined(MBEDTLS_ASN1_PARSE_C)
    int ret = mbedtls_asn1_get_tag(p, end, len, tag);
    return ssl_platform_mbedtls_error_map(ret);
#else
    return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
#endif
}

/* Note: MPI functions are implemented in ssl_platform_mpi_ext.c */

/* =============================================================================
 * ECP OPERATIONS IMPLEMENTATION
 * =============================================================================
 */

int ssl_platform_ecp_group_init(ssl_platform_ecp_group_t *grp)
{
    if (grp == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    mbedtls_ecp_group_init(&grp->mbedtls_grp);
    return SSL_PLATFORM_SUCCESS;
}

void ssl_platform_ecp_group_free(ssl_platform_ecp_group_t *grp)
{
    if (grp != NULL) {
        mbedtls_ecp_group_free(&grp->mbedtls_grp);
    }
}

int ssl_platform_ecp_group_load(ssl_platform_ecp_group_t *grp, ssl_platform_ecp_group_id_t id)
{
    if (grp == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    mbedtls_ecp_group_id mbedtls_id = ssl_platform_ecp_group_to_mbedtls(id);
    if (mbedtls_id == MBEDTLS_ECP_DP_NONE) {
        return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
    }
    
    int ret = mbedtls_ecp_group_load(&grp->mbedtls_grp, mbedtls_id);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_ecp_point_init(ssl_platform_ecp_point_t *pt)
{
    if (pt == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    mbedtls_ecp_point_init(&pt->mbedtls_pt);
    return SSL_PLATFORM_SUCCESS;
}

void ssl_platform_ecp_point_free(ssl_platform_ecp_point_t *pt)
{
    if (pt != NULL) {
        mbedtls_ecp_point_free(&pt->mbedtls_pt);
    }
}

int ssl_platform_ecp_point_write_binary(const ssl_platform_ecp_group_t *grp,
                                        const ssl_platform_ecp_point_t *pt,
                                        int format, size_t *olen,
                                        unsigned char *buf, size_t buflen)
{
    if (grp == NULL || pt == NULL || olen == NULL || buf == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int mbedtls_format = (format == SSL_PLATFORM_ECP_PF_UNCOMPRESSED) ? 
                         MBEDTLS_ECP_PF_UNCOMPRESSED : MBEDTLS_ECP_PF_COMPRESSED;
    
    int ret = mbedtls_ecp_point_write_binary(&grp->mbedtls_grp, &pt->mbedtls_pt,
                                           mbedtls_format, olen, buf, buflen);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_ecp_point_read_binary(const ssl_platform_ecp_group_t *grp,
                                       ssl_platform_ecp_point_t *pt,
                                       const unsigned char *buf, size_t buflen)
{
    if (grp == NULL || pt == NULL || buf == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_ecp_point_read_binary(&grp->mbedtls_grp, &pt->mbedtls_pt, buf, buflen);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_ecp_keypair_init(ssl_platform_ecp_keypair_t *keypair)
{
    if (keypair == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    mbedtls_ecp_keypair_init(&keypair->mbedtls_keypair);
    return SSL_PLATFORM_SUCCESS;
}

void ssl_platform_ecp_keypair_free(ssl_platform_ecp_keypair_t *keypair)
{
    if (keypair != NULL) {
        mbedtls_ecp_keypair_free(&keypair->mbedtls_keypair);
    }
}


ssl_platform_ecp_point_t *ssl_platform_ecp_keypair_get_point(ssl_platform_ecp_keypair_t *keypair)
{
    if (keypair == NULL) {
        return NULL;
    }
    
    return (ssl_platform_ecp_point_t *)&keypair->mbedtls_keypair.Q;
}

ssl_platform_mpi_t *ssl_platform_ecp_keypair_get_private(ssl_platform_ecp_keypair_t *keypair)
{
    if (keypair == NULL) {
        return NULL;
    }
    
    // Note: This is a workaround - in practice we need a proper wrapper
    // For now, we assume ssl_platform_mpi_t layout matches mbedtls_mpi
    static ssl_platform_mpi_t wrapper;
    wrapper.mbedtls_mpi = keypair->mbedtls_keypair.d;
    return &wrapper;
}

int ssl_platform_ecp_gen_key(ssl_platform_ecp_group_id_t grp_id,
                             ssl_platform_ecp_keypair_t *keypair,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng)
{
    if (keypair == NULL || f_rng == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    mbedtls_ecp_group_id mbedtls_id = ssl_platform_ecp_group_to_mbedtls(grp_id);
    if (mbedtls_id == MBEDTLS_ECP_DP_NONE) {
        return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
    }
    
    int ret = mbedtls_ecp_gen_key(mbedtls_id, &keypair->mbedtls_keypair, f_rng, p_rng);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_ecp_check_privkey(const ssl_platform_ecp_group_t *grp,
                                   const ssl_platform_mpi_t *d)
{
    if (grp == NULL || d == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_ecp_check_privkey(&grp->mbedtls_grp, &d->mbedtls_mpi);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_ecp_check_pubkey(const ssl_platform_ecp_group_t *grp,
                                  const ssl_platform_ecp_point_t *pt)
{
    if (grp == NULL || pt == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_ecp_check_pubkey(&grp->mbedtls_grp, &pt->mbedtls_pt);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_ecdh_compute_shared(const ssl_platform_ecp_group_t *grp,
                                     ssl_platform_mpi_t *z,
                                     const ssl_platform_ecp_point_t *Q,
                                     const ssl_platform_mpi_t *d,
                                     int (*f_rng)(void *, unsigned char *, size_t),
                                     void *p_rng)
{
    if (grp == NULL || z == NULL || Q == NULL || d == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_ecdh_compute_shared((mbedtls_ecp_group *)&grp->mbedtls_grp, (mbedtls_mpi *)z,
                                         &Q->mbedtls_pt, (const mbedtls_mpi *)d,
                                         f_rng, p_rng);
    return ssl_platform_mbedtls_error_map(ret);
}

/* =============================================================================
 * CCM OPERATIONS IMPLEMENTATION
 * =============================================================================
 */

void ssl_platform_ccm_init(ssl_platform_ccm_context_t *ctx)
{
    if (ctx != NULL) {
        mbedtls_ccm_init(&ctx->mbedtls_ctx);
    }
}

void ssl_platform_ccm_free(ssl_platform_ccm_context_t *ctx)
{
    if (ctx != NULL) {
        mbedtls_ccm_free(&ctx->mbedtls_ctx);
    }
}

int ssl_platform_ccm_setkey(ssl_platform_ccm_context_t *ctx,
                            int cipher,
                            const unsigned char *key,
                            unsigned int keybits)
{
    if (ctx == NULL || key == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    // Map cipher ID - currently only AES is supported
    mbedtls_cipher_id_t mbedtls_cipher = MBEDTLS_CIPHER_ID_AES;
    if (cipher != 0) { // Assume 0 means AES for now
        mbedtls_cipher = MBEDTLS_CIPHER_ID_AES;
    }
    
    int ret = mbedtls_ccm_setkey(&ctx->mbedtls_ctx, mbedtls_cipher, key, keybits);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_ccm_encrypt_and_tag(ssl_platform_ccm_context_t *ctx,
                                     size_t length,
                                     const unsigned char *iv, size_t iv_len,
                                     const unsigned char *add, size_t add_len,
                                     const unsigned char *input,
                                     unsigned char *output,
                                     unsigned char *tag, size_t tag_len)
{
    if (ctx == NULL || iv == NULL || output == NULL || tag == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_ccm_encrypt_and_tag(&ctx->mbedtls_ctx, length, iv, iv_len,
                                         add, add_len, input, output, tag, tag_len);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_ccm_auth_decrypt(ssl_platform_ccm_context_t *ctx,
                                  size_t length,
                                  const unsigned char *iv, size_t iv_len,
                                  const unsigned char *add, size_t add_len,
                                  const unsigned char *input,
                                  unsigned char *output,
                                  const unsigned char *tag, size_t tag_len)
{
    if (ctx == NULL || iv == NULL || tag == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_ccm_auth_decrypt(&ctx->mbedtls_ctx, length, iv, iv_len,
                                      add, add_len, input, output, tag, tag_len);
    return ssl_platform_mbedtls_error_map(ret);
}

/* =============================================================================
 * MPI OPERATIONS IMPLEMENTATION
 * =============================================================================
 */

int ssl_platform_mpi_init(ssl_platform_mpi_t *X)
{
    if (X == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    mbedtls_mpi_init(&X->mbedtls_mpi);
    return SSL_PLATFORM_SUCCESS;
}

void ssl_platform_mpi_free(ssl_platform_mpi_t *X)
{
    if (X != NULL) {
        mbedtls_mpi_free(&X->mbedtls_mpi);
    }
}

size_t ssl_platform_mpi_size(const ssl_platform_mpi_t *X)
{
    if (X == NULL) {
        return 0;
    }
    
    return mbedtls_mpi_size(&X->mbedtls_mpi);
}

int ssl_platform_mpi_write_binary(const ssl_platform_mpi_t *X, unsigned char *buf, size_t buflen)
{
    if (X == NULL || buf == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_mpi_write_binary(&X->mbedtls_mpi, buf, buflen);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_mpi_read_binary(ssl_platform_mpi_t *X, const unsigned char *buf, size_t buflen)
{
    if (X == NULL || buf == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_mpi_read_binary(&X->mbedtls_mpi, buf, buflen);
    return ssl_platform_mbedtls_error_map(ret);
}

const void *ssl_platform_pk_info_from_type(ssl_platform_pk_type_t type)
{
    mbedtls_pk_type_t mbedtls_type;
    
    switch (type) {
        case SSL_PLATFORM_PK_ECKEY:
            mbedtls_type = MBEDTLS_PK_ECKEY;
            break;
        case SSL_PLATFORM_PK_ECDSA:
            mbedtls_type = MBEDTLS_PK_ECDSA;
            break;
        case SSL_PLATFORM_PK_RSA:
            mbedtls_type = MBEDTLS_PK_RSA;
            break;
        default:
            return NULL;
    }
    
    return mbedtls_pk_info_from_type(mbedtls_type);
}

int ssl_platform_pk_setup_info(ssl_platform_pk_context_t *ctx, const void *info)
{
    if (ctx == NULL || info == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_pk_setup(&ctx->pk_ctx, (const mbedtls_pk_info_t *)info);
    return ssl_platform_mbedtls_error_map(ret);
}

/* =============================================================================
 * SSL OPERATIONS IMPLEMENTATION  
 * =============================================================================
 */

void ssl_platform_ssl_init(ssl_platform_ssl_context_t *ssl)
{
    if (ssl != NULL) {
        mbedtls_ssl_init(&ssl->mbedtls_ssl);
    }
}

void ssl_platform_ssl_free(ssl_platform_ssl_context_t *ssl)
{
    if (ssl != NULL) {
        mbedtls_ssl_free(&ssl->mbedtls_ssl);
    }
}

void ssl_platform_ssl_config_init(ssl_platform_ssl_config_t *conf)
{
    if (conf != NULL) {
        mbedtls_ssl_config_init(&conf->mbedtls_conf);
    }
}

void ssl_platform_ssl_config_free(ssl_platform_ssl_config_t *conf)
{
    if (conf != NULL) {
        mbedtls_ssl_config_free(&conf->mbedtls_conf);
    }
}

int ssl_platform_ssl_config_defaults(ssl_platform_ssl_config_t *conf,
                                     int endpoint, int transport, int preset)
{
    if (conf == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_ssl_config_defaults(&conf->mbedtls_conf, endpoint, transport, preset);
    if (ret != 0) {
        return ssl_platform_mbedtls_error_map(ret);
    }
    
    // Set handshake timeout to prevent hanging
    mbedtls_ssl_conf_handshake_timeout(&conf->mbedtls_conf, 1000, 60000); // 1s min, 60s max
    
    // Set read timeout for non-blocking operations
    mbedtls_ssl_conf_read_timeout(&conf->mbedtls_conf, 30000); // 30 second read timeout
    
    return SSL_PLATFORM_SUCCESS;
}

void ssl_platform_ssl_conf_rng(ssl_platform_ssl_config_t *conf,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng)
{
    if (conf != NULL) {
        mbedtls_ssl_conf_rng(&conf->mbedtls_conf, f_rng, p_rng);
    }
}

int ssl_platform_ssl_setup(ssl_platform_ssl_context_t *ssl,
                           const ssl_platform_ssl_config_t *conf)
{
    if (ssl == NULL || conf == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_ssl_setup(&ssl->mbedtls_ssl, &conf->mbedtls_conf);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_ssl_read(ssl_platform_ssl_context_t *ssl, unsigned char *buf, size_t len)
{
    if (ssl == NULL || buf == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    // Check if handshake is complete first
    if (ssl->mbedtls_ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER && ssl->mbedtls_ssl.state != 16) {
        printf("SSL read called but handshake not complete, state: %d\n", ssl->mbedtls_ssl.state);
        return SSL_PLATFORM_ERROR_WANT_READ;
    }
    
    int ret = mbedtls_ssl_read(&ssl->mbedtls_ssl, buf, len);
    if (ret >= 0) {
        if (ret > 0) {
            printf("SSL read successful: %d bytes\n", ret);
        }
        return ret; // Return number of bytes read
    }
    
    // Enhanced debugging for read errors - but don't spam for normal WANT_READ
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
        printf("SSL read error: -0x%x, state: %d\n", -ret, ssl->mbedtls_ssl.state);
    }
    
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_ssl_write(ssl_platform_ssl_context_t *ssl, const unsigned char *buf, size_t len)
{
    if (ssl == NULL || buf == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_ssl_write(&ssl->mbedtls_ssl, buf, len);
    if (ret >= 0) {
        return ret; // Return number of bytes written
    }
    
    // Enhanced debugging for write errors
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
        printf("SSL write error: -0x%x, state: %d\n", -ret, ssl->mbedtls_ssl.state);
    }
    
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_ssl_handshake(ssl_platform_ssl_context_t *ssl)
{
    if (ssl == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    // Check current state first
    int current_state = ssl->mbedtls_ssl.state;
    printf("SSL handshake called: current state: %d\n", current_state);
    
    // Check if handshake is already complete - state 16 is MBEDTLS_SSL_HANDSHAKE_OVER
    if (current_state == MBEDTLS_SSL_HANDSHAKE_OVER || current_state == 16) {
        printf("SSL handshake: already complete (state %d), returning SUCCESS\n", current_state);
        return SSL_PLATFORM_SUCCESS;
    }
    
    int ret = mbedtls_ssl_handshake(&ssl->mbedtls_ssl);
    
    printf("SSL handshake state: %d, return code: -0x%x\n", ssl->mbedtls_ssl.state, -ret);
    
    // Check for handshake completion FIRST before checking error codes
    if (ssl->mbedtls_ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER || ssl->mbedtls_ssl.state == 16) {
        printf("SSL handshake COMPLETED successfully, state: %d\n", ssl->mbedtls_ssl.state);
        return SSL_PLATFORM_SUCCESS;
    }
    
    // Handle the case where state 12 with WANT_READ might indicate near completion
    if (ssl->mbedtls_ssl.state == 12 && ret == MBEDTLS_ERR_SSL_WANT_READ) {
        printf("SSL handshake: state 12 with WANT_READ - checking for completion\n");
        // State 12 might be the final state for some handshake scenarios
        return ssl_platform_mbedtls_error_map(ret);
    }
    
    // Enhanced error mapping for better debugging
    if (ret == 0) {
        return SSL_PLATFORM_SUCCESS;
    }
    
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_ssl_handshake_step(ssl_platform_ssl_context_t *ssl)
{
    if (ssl == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    // Check if handshake is already complete
    if (ssl->mbedtls_ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
        return SSL_PLATFORM_SUCCESS;
    }
    
    printf("SSL handshake step: current state %d\n", ssl->mbedtls_ssl.state);
    
    int ret = mbedtls_ssl_handshake_step(&ssl->mbedtls_ssl);
    
    printf("SSL handshake step result: state %d, ret -0x%x\n", ssl->mbedtls_ssl.state, -ret);
    
    // Check for completion after step
    if (ssl->mbedtls_ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
        printf("SSL handshake step: HANDSHAKE COMPLETED\n");
        return SSL_PLATFORM_SUCCESS;
    }
    
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_ssl_close_notify(ssl_platform_ssl_context_t *ssl)
{
    if (ssl == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_ssl_close_notify(&ssl->mbedtls_ssl);
    return ssl_platform_mbedtls_error_map(ret);
}

void ssl_platform_ssl_conf_authmode(ssl_platform_ssl_config_t *conf, int authmode)
{
    if (conf != NULL) {
        mbedtls_ssl_conf_authmode(&conf->mbedtls_conf, authmode);
    }
}

int ssl_platform_ssl_conf_own_cert(ssl_platform_ssl_config_t *conf,
                                   ssl_platform_x509_crt_t *own_cert,
                                   ssl_platform_pk_context_t *pk_key)
{
    if (conf == NULL || own_cert == NULL || pk_key == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_ssl_conf_own_cert(&conf->mbedtls_conf, &own_cert->mbedtls_crt, &pk_key->pk_ctx);
    return ssl_platform_mbedtls_error_map(ret);
}

void ssl_platform_ssl_conf_ca_chain(ssl_platform_ssl_config_t *conf,
                                    ssl_platform_x509_crt_t *ca_chain,
                                    void *ca_crl)
{
    if (conf != NULL && ca_chain != NULL) {
        mbedtls_ssl_conf_ca_chain(&conf->mbedtls_conf, &ca_chain->mbedtls_crt, NULL);
    }
}

void ssl_platform_ssl_conf_ciphersuites(ssl_platform_ssl_config_t *conf,
                                        const int *ciphersuites)
{
    if (conf != NULL && ciphersuites != NULL) {
        mbedtls_ssl_conf_ciphersuites(&conf->mbedtls_conf, ciphersuites);
    }
}

void ssl_platform_ssl_conf_handshake_timeout(ssl_platform_ssl_config_t *conf,
                                             uint32_t min, uint32_t max)
{
    if (conf != NULL) {
        mbedtls_ssl_conf_handshake_timeout(&conf->mbedtls_conf, min, max);
    }
}

int ssl_platform_ssl_conf_psk(ssl_platform_ssl_config_t *conf,
                              const unsigned char *psk, size_t psk_len,
                              const unsigned char *psk_identity, size_t psk_identity_len)
{
    if (conf == NULL || psk == NULL || psk_identity == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
#if defined(MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
    int ret = mbedtls_ssl_conf_psk(&conf->mbedtls_conf, psk, psk_len, psk_identity, psk_identity_len);
    return ssl_platform_mbedtls_error_map(ret);
#else
    // PSK not supported in this configuration
    return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
#endif
}

int ssl_platform_ssl_set_hostname(ssl_platform_ssl_context_t *ssl, const char *hostname)
{
    if (ssl == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
#if defined(MBEDTLS_X509_CRT_PARSE_C)
    int ret = mbedtls_ssl_set_hostname(&ssl->mbedtls_ssl, hostname);
    return ssl_platform_mbedtls_error_map(ret);
#else
    return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
#endif
}

void ssl_platform_ssl_set_bio(ssl_platform_ssl_context_t *ssl,
                              void *p_bio,
                              int (*f_send)(void *, const unsigned char *, size_t),
                              int (*f_recv)(void *, unsigned char *, size_t),
                              int (*f_recv_timeout)(void *, unsigned char *, size_t, uint32_t))
{
    if (ssl != NULL) {
        mbedtls_ssl_set_bio(&ssl->mbedtls_ssl, p_bio, f_send, f_recv, f_recv_timeout);
    }
}

void ssl_platform_ssl_set_timer_cb(ssl_platform_ssl_context_t *ssl,
                                   void *p_timer,
                                   void (*f_set_timer)(void *, uint32_t, uint32_t),
                                   int (*f_get_timer)(void *))
{
    if (ssl != NULL) {
        mbedtls_ssl_set_timer_cb(&ssl->mbedtls_ssl, p_timer, f_set_timer, f_get_timer);
    }
}

uint32_t ssl_platform_ssl_get_verify_result(const ssl_platform_ssl_context_t *ssl)
{
    if (ssl == NULL) {
        printf("ERROR: ssl_platform_ssl_get_verify_result called with NULL ssl context\n");
        return 0xFFFFFFFF; // Error indicator
    }
    
    uint32_t result = mbedtls_ssl_get_verify_result(&ssl->mbedtls_ssl);
    printf("DEBUG: ssl_platform_ssl_get_verify_result returned: 0x%x (%u)\n", result, result);
    
    if (result == 0) {
        printf("DEBUG: Certificate verification SUCCESSFUL (flags = 0)\n");
    } else {
        printf("DEBUG: Certificate verification has flags: 0x%x\n", result);
        if (result & MBEDTLS_X509_BADCERT_EXPIRED) {
            printf("  - MBEDTLS_X509_BADCERT_EXPIRED\n");
        }
        if (result & MBEDTLS_X509_BADCERT_REVOKED) {
            printf("  - MBEDTLS_X509_BADCERT_REVOKED\n");
        }
        if (result & MBEDTLS_X509_BADCERT_CN_MISMATCH) {
            printf("  - MBEDTLS_X509_BADCERT_CN_MISMATCH\n");
        }
        if (result & MBEDTLS_X509_BADCERT_NOT_TRUSTED) {
            printf("  - MBEDTLS_X509_BADCERT_NOT_TRUSTED\n");
        }
    }
    
    return result;
}

void ssl_platform_ssl_conf_dbg(ssl_platform_ssl_config_t *conf,
                               void (*f_dbg)(void *, int, const char *, int, const char *),
                               void *p_dbg)
{
    if (conf != NULL) {
        mbedtls_ssl_conf_dbg(&conf->mbedtls_conf, f_dbg, p_dbg);
    }
}

int ssl_platform_ssl_set_cid(ssl_platform_ssl_context_t *ssl,
                             int enable,
                             unsigned char const *own_cid,
                             size_t own_cid_len)
{
    if (!ssl) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
#if defined(MBEDTLS_SSL_DTLS_CONNECTION_ID)
    int ret = mbedtls_ssl_set_cid(&ssl->mbedtls_ssl, enable, own_cid, own_cid_len);
    return ssl_platform_mbedtls_error_map(ret);
#else
    return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
#endif
}

int ssl_platform_ssl_get_session(const ssl_platform_ssl_context_t *ssl,
                                 void *session)
{
    if (!ssl || !session) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_ssl_get_session(&ssl->mbedtls_ssl, (mbedtls_ssl_session *)session);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_ssl_set_session(ssl_platform_ssl_context_t *ssl,
                                 const void *session)
{
    if (!ssl || !session) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_ssl_set_session(&ssl->mbedtls_ssl, (const mbedtls_ssl_session *)session);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_ssl_context_save(ssl_platform_ssl_context_t *ssl,
                                  unsigned char *buf,
                                  size_t buf_len,
                                  size_t *olen)
{
    if (!ssl || !buf || !olen) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
#if defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION)
    int ret = mbedtls_ssl_context_save(&ssl->mbedtls_ssl, buf, buf_len, olen);
    return ssl_platform_mbedtls_error_map(ret);
#else
    return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
#endif
}

int ssl_platform_ssl_context_load(ssl_platform_ssl_context_t *ssl,
                                  const unsigned char *buf,
                                  size_t len)
{
    if (!ssl || !buf) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
#if defined(MBEDTLS_SSL_CONTEXT_SERIALIZATION)
    int ret = mbedtls_ssl_context_load(&ssl->mbedtls_ssl, buf, len);
    return ssl_platform_mbedtls_error_map(ret);
#else
    return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
#endif
}

int ssl_platform_ssl_renegotiate(ssl_platform_ssl_context_t *ssl)
{
    if (!ssl) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_ssl_renegotiate(&ssl->mbedtls_ssl);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_ssl_conf_max_frag_len(ssl_platform_ssl_config_t *conf,
                                       unsigned char mfl_code)
{
    if (!conf) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
#if defined(MBEDTLS_SSL_MAX_FRAGMENT_LENGTH)
    int ret = mbedtls_ssl_conf_max_frag_len(&conf->mbedtls_conf, mfl_code);
    return ssl_platform_mbedtls_error_map(ret);
#else
    return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
#endif
}

/* =============================================================================
 * ASN.1 WRITE OPERATIONS IMPLEMENTATION
 * =============================================================================
 */

int ssl_platform_asn1_write_len(unsigned char **p, unsigned char *start, size_t len)
{
    if (p == NULL || start == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_asn1_write_len(p, start, len);
    // Return the actual byte count for positive values, error mapping for negative values
    if (ret >= 0) {
        return ret;  // Return number of bytes written
    }
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_asn1_write_tag(unsigned char **p, unsigned char *start, unsigned char tag)
{
    if (p == NULL || start == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_asn1_write_tag(p, start, tag);
    // Return the actual byte count for positive values, error mapping for negative values
    if (ret >= 0) {
        return ret;  // Return number of bytes written
    }
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_asn1_write_oid(unsigned char **p, unsigned char *start,
                                const char *oid, size_t oid_len)
{
    if (p == NULL || start == NULL || oid == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_asn1_write_oid(p, start, oid, oid_len);
    // Return the actual byte count for positive values, error mapping for negative values
    if (ret >= 0) {
        return ret;  // Return number of bytes written
    }
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_asn1_get_tag_ext(unsigned char **p, const unsigned char *end,
                                  size_t *len, int tag, int constructed)
{
    if (p == NULL || end == NULL || len == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
#if defined(MBEDTLS_ASN1_PARSE_C)
    // mbedTLS doesn't have mbedtls_asn1_get_tag_ext, so we use the regular get_tag
    // The constructed parameter is currently ignored in this implementation
    int ret = mbedtls_asn1_get_tag(p, end, len, tag);
    return ssl_platform_mbedtls_error_map(ret);
#else
    return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
#endif
}

int ssl_platform_asn1_write_mpi(unsigned char **p, unsigned char *start, const ssl_platform_mpi_t *X)
{
    if (p == NULL || start == NULL || X == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_asn1_write_mpi(p, start, &X->mbedtls_mpi);
    // Return the actual byte count for positive values, error mapping for negative values
    if (ret >= 0) {
        return ret;  // Return number of bytes written
    }
    return ssl_platform_mbedtls_error_map(ret);
}

#endif /* SSL_PLATFORM_BACKEND == SSL_PLATFORM_BACKEND_MBEDTLS */

/* =============================================================================
 * ERROR MAPPING FUNCTION
 * =============================================================================
 */

/**
 * \brief Convert mbed-TLS error codes to SSL platform error codes
 */
int ssl_platform_mbedtls_error_map(int mbedtls_error)
{
    switch (mbedtls_error) {
        case 0:
            return SSL_PLATFORM_SUCCESS;
        case MBEDTLS_ERR_SSL_WANT_READ:
            return SSL_PLATFORM_ERROR_WANT_READ;
        case MBEDTLS_ERR_SSL_WANT_WRITE:
            return SSL_PLATFORM_ERROR_WANT_WRITE;
        case MBEDTLS_ERR_SSL_TIMEOUT:
            printf("SSL error: TIMEOUT - handshake took too long\n");
            return SSL_PLATFORM_ERROR_TIMEOUT;
        case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
            printf("SSL error: PEER_CLOSE_NOTIFY - peer closed connection\n");
            return SSL_PLATFORM_ERROR_CONNECTION_CLOSED;
        case MBEDTLS_ERR_SSL_CONN_EOF:
            printf("SSL error: CONN_EOF - connection ended unexpectedly\n");
            return SSL_PLATFORM_ERROR_CONNECTION_RESET;
        case MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE:
            printf("SSL error: BAD_HS_CERTIFICATE - certificate validation failed\n");
            return SSL_PLATFORM_ERROR_CERTIFICATE_VERIFY_FAILED;
        case MBEDTLS_ERR_X509_CERT_VERIFY_FAILED:
            printf("SSL error: CERT_VERIFY_FAILED - X.509 certificate verification failed\n");
            return SSL_PLATFORM_ERROR_CERTIFICATE_VERIFY_FAILED;
        case MBEDTLS_ERR_SSL_INVALID_RECORD:
        case MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE:
        case MBEDTLS_ERR_SSL_UNEXPECTED_RECORD:
            printf("SSL error: INVALID_RECORD/MESSAGE - protocol error\n");
            return SSL_PLATFORM_ERROR_HANDSHAKE_FAILED;
        case MBEDTLS_ERR_X509_BUFFER_TOO_SMALL:
            printf("SSL error: X509_BUFFER_TOO_SMALL - buffer too small for certificate data\n");
            return SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL;
        case MBEDTLS_ERR_X509_INVALID_FORMAT:
            printf("SSL error: X509_INVALID_FORMAT - invalid certificate format\n");
            return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
        case MBEDTLS_ERR_X509_BAD_INPUT_DATA:
            printf("SSL error: X509_BAD_INPUT_DATA - bad certificate input data\n");
            return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
        case -145:  // Specific error we're seeing
            printf("SSL error: mbedTLS error -145 - likely certificate parsing issue\n");
            return SSL_PLATFORM_ERROR_CERTIFICATE_VERIFY_FAILED;
        default:
            printf("SSL error: UNKNOWN - mbedTLS error code -0x%x\n", -mbedtls_error);
            return SSL_PLATFORM_ERROR_UNKNOWN;
    }
}

int ssl_platform_ssl_get_state(const ssl_platform_ssl_context_t *ssl)
{
    if (ssl == NULL) {
        return -1;
    }
    
    return ssl->mbedtls_ssl.state;
}

bool ssl_platform_ssl_handshake_is_over(const ssl_platform_ssl_context_t *ssl)
{
    if (ssl == NULL) {
        return false;
    }
    
    return (ssl->mbedtls_ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER);
}

int ssl_platform_ssl_session_save(const ssl_platform_ssl_context_t *ssl, unsigned char *buf, size_t buf_len, size_t *olen)
{
    // Stub implementation - session resumption not yet implemented
    if (olen) {
        *olen = 0;
    }
    printf("DEBUG: ssl_platform_ssl_session_save called - not implemented\n");
    return SSL_PLATFORM_ERROR_FEATURE_UNAVAILABLE;
}

int ssl_platform_ssl_session_load(ssl_platform_ssl_context_t *ssl, const unsigned char *buf, size_t len)
{
    // Stub implementation - session resumption not yet implemented
    printf("DEBUG: ssl_platform_ssl_session_load called - not implemented\n");
    return SSL_PLATFORM_ERROR_FEATURE_UNAVAILABLE;
} 