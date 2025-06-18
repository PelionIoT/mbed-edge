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
#include <string.h>

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
        mbedtls_pk_init(&ctx->mbedtls_ctx);
    }
}

void ssl_platform_pk_free(ssl_platform_pk_context_t *ctx)
{
    if (ctx != NULL) {
        mbedtls_pk_free(&ctx->mbedtls_ctx);
    }
}

int ssl_platform_pk_parse_key(ssl_platform_pk_context_t *ctx,
                              const unsigned char *key, size_t keylen,
                              const unsigned char *pwd, size_t pwdlen)
{
    if (ctx == NULL || key == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_pk_parse_key(&ctx->mbedtls_ctx, key, keylen, pwd, pwdlen);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_pk_parse_public_key(ssl_platform_pk_context_t *ctx,
                                     const unsigned char *key, size_t keylen)
{
    if (!ctx || !key) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_pk_parse_public_key(&ctx->mbedtls_ctx, key, keylen);
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
    
    int ret = mbedtls_pk_verify(&ctx->mbedtls_ctx, mbedtls_md_alg, hash, hash_len, sig, sig_len);
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
    
    int ret = mbedtls_pk_sign(&ctx->mbedtls_ctx, mbedtls_md_alg, hash, hash_len, sig, sig_len, f_rng, p_rng);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_pk_setup(ssl_platform_pk_context_t *ctx, const void *info)
{
    if (!ctx || !info) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_pk_setup(&ctx->mbedtls_ctx, (const mbedtls_pk_info_t *)info);
    return ssl_platform_mbedtls_error_map(ret);
}

int ssl_platform_pk_write_key_der(ssl_platform_pk_context_t *ctx,
                                  unsigned char *buf, size_t size)
{
    if (!ctx || !buf) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_pk_write_key_der(&ctx->mbedtls_ctx, buf, size);
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
    
    int ret = mbedtls_pk_write_pubkey_der(&ctx->mbedtls_ctx, buf, size);
    if (ret < 0) {
        return ssl_platform_mbedtls_error_map(ret);
    }
    return ret;  // Return length on success
}

void *ssl_platform_pk_get_backend_context(ssl_platform_pk_context_t *ctx)
{
    if (!ctx) {
        return NULL;
    }
    return &ctx->mbedtls_ctx;
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
    int ret = mbedtls_pk_setup(&pk->mbedtls_ctx, mbedtls_pk_info_from_type(mbedtls_pk_get_type(&crt->mbedtls_crt.pk)));
    if (ret != 0) {
        return ssl_platform_mbedtls_error_map(ret);
    }
    
    ret = mbedtls_pk_check_pair(&crt->mbedtls_crt.pk, &pk->mbedtls_ctx);
    if (ret == 0) {
        // If check_pair succeeds, we can copy the key
        pk->mbedtls_ctx = crt->mbedtls_crt.pk;
    } else {
        // For public key extraction, we need to copy the public key part
        // This is a simplified implementation - copy the entire PK context
        memcpy(&pk->mbedtls_ctx, &crt->mbedtls_crt.pk, sizeof(mbedtls_pk_context));
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
    
    int ret = mbedtls_x509_dn_gets(buf, buf_size, &crt->mbedtls_crt.subject);
    return ssl_platform_mbedtls_error_map(ret);
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

/* =============================================================================
 * ENTROPY AND RANDOM NUMBER GENERATION IMPLEMENTATION
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

// Enhanced CTR-DRBG operations
int ssl_platform_ctr_drbg_reseed(ssl_platform_ctr_drbg_context_t *ctx, const unsigned char *additional, size_t len)
{
    if (ctx == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_ctr_drbg_reseed(&ctx->mbedtls_ctx, additional, len);
    return ssl_platform_mbedtls_error_map(ret);
}

/* =============================================================================
 * SSL/TLS OPERATIONS IMPLEMENTATION
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
    
    // Map cipher ID (currently only supports AES)
    mbedtls_cipher_id_t mbedtls_cipher_id;
    switch (cipher) {
        case 1:  // Assuming 1 maps to AES like in mbedTLS MBEDTLS_CIPHER_ID_AES
            mbedtls_cipher_id = MBEDTLS_CIPHER_ID_AES;
            break;
        default:
            return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
    }
    
    int ret = mbedtls_ccm_setkey(&ctx->mbedtls_ctx, mbedtls_cipher_id, key, keybits);
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
    
    if (length > 0 && input == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    if (add_len > 0 && add == NULL) {
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
    if (ctx == NULL || iv == NULL || output == NULL || tag == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    if (length > 0 && input == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    if (add_len > 0 && add == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_ccm_auth_decrypt(&ctx->mbedtls_ctx, length, iv, iv_len,
                                      add, add_len, input, output, tag, tag_len);
    return ssl_platform_mbedtls_error_map(ret);
}

// ASN.1 Writing/Encoding Functions - mbedTLS implementation
int ssl_platform_asn1_write_len(unsigned char **p, unsigned char *start, size_t len)
{
    return mbedtls_asn1_write_len(p, start, len);
}

int ssl_platform_asn1_write_tag(unsigned char **p, unsigned char *start, unsigned char tag)
{
    return mbedtls_asn1_write_tag(p, start, tag);
}

int ssl_platform_asn1_write_int(unsigned char **p, unsigned char *start, int val)
{
    return mbedtls_asn1_write_int(p, start, val);
}

int ssl_platform_asn1_write_mpi(unsigned char **p, unsigned char *start, const ssl_platform_mpi *X)
{
    return mbedtls_asn1_write_mpi(p, start, (const mbedtls_mpi *)X);
}

int ssl_platform_asn1_write_null(unsigned char **p, unsigned char *start)
{
    return mbedtls_asn1_write_null(p, start);
}

int ssl_platform_asn1_write_oid(unsigned char **p, unsigned char *start, 
                                const char *oid, size_t oid_len)
{
    return mbedtls_asn1_write_oid(p, start, oid, oid_len);
}

int ssl_platform_asn1_write_bool(unsigned char **p, unsigned char *start, int boolean)
{
    return mbedtls_asn1_write_bool(p, start, boolean);
}

int ssl_platform_asn1_write_ia5_string(unsigned char **p, unsigned char *start,
                                       const char *text, size_t text_len)
{
    return mbedtls_asn1_write_ia5_string(p, start, text, text_len);
}

int ssl_platform_asn1_write_utf8_string(unsigned char **p, unsigned char *start,
                                        const char *text, size_t text_len)
{
    return mbedtls_asn1_write_utf8_string(p, start, text, text_len);
}

int ssl_platform_asn1_write_printable_string(unsigned char **p, unsigned char *start,
                                             const char *text, size_t text_len)
{
    return mbedtls_asn1_write_printable_string(p, start, text, text_len);
}

int ssl_platform_asn1_write_bitstring(unsigned char **p, unsigned char *start,
                                      const unsigned char *buf, size_t bits)
{
    return mbedtls_asn1_write_bitstring(p, start, buf, bits);
}

int ssl_platform_asn1_write_octet_string(unsigned char **p, unsigned char *start,
                                         const unsigned char *buf, size_t size)
{
    return mbedtls_asn1_write_octet_string(p, start, buf, size);
}

int ssl_platform_asn1_write_sequence_tag(unsigned char **p, unsigned char *start, size_t len)
{
    return mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) +
           mbedtls_asn1_write_len(p, start, len);
}

int ssl_platform_asn1_write_set_tag(unsigned char **p, unsigned char *start, size_t len)
{
    return mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET) +
           mbedtls_asn1_write_len(p, start, len);
}

// Enhanced ASN.1 Tag Parsing Functions - mbedTLS implementation
int ssl_platform_asn1_get_tag_ext(unsigned char **p, const unsigned char *end,
                                  size_t *len, int tag, int constructed)
{
    return mbedtls_asn1_get_tag(p, end, len, tag);
}

int ssl_platform_asn1_get_sequence_of(unsigned char **p, const unsigned char *end,
                                      ssl_platform_asn1_sequence *cur, int tag)
{
    return mbedtls_asn1_get_sequence_of(p, end, (mbedtls_asn1_sequence *)cur, tag);
}

int ssl_platform_asn1_get_alg_null(unsigned char **p, const unsigned char *end,
                                   ssl_platform_x509_buf *alg)
{
    return mbedtls_asn1_get_alg_null(p, end, (mbedtls_x509_buf *)alg);
}

int ssl_platform_asn1_get_alg(unsigned char **p, const unsigned char *end,
                              ssl_platform_x509_buf *alg, ssl_platform_x509_buf *params)
{
    return mbedtls_asn1_get_alg(p, end, (mbedtls_x509_buf *)alg, (mbedtls_x509_buf *)params);
}

// OID Handling Functions - mbedTLS implementation
int ssl_platform_oid_get_attr_short_name(const ssl_platform_asn1_buf *oid, const char **short_name)
{
    return mbedtls_oid_get_attr_short_name((const mbedtls_asn1_buf *)oid, short_name);
}

int ssl_platform_oid_get_extended_key_usage(const ssl_platform_asn1_buf *oid, const char **desc)
{
    return mbedtls_oid_get_extended_key_usage((const mbedtls_asn1_buf *)oid, desc);
}

int ssl_platform_oid_get_sig_alg_desc(const ssl_platform_asn1_buf *oid, const char **desc)
{
    return mbedtls_oid_get_sig_alg_desc((const mbedtls_asn1_buf *)oid, desc);
}

int ssl_platform_oid_get_sig_alg(const ssl_platform_asn1_buf *oid,
                                 ssl_platform_md_type_t *md_alg, ssl_platform_pk_type_t *pk_alg)
{
    return mbedtls_oid_get_sig_alg((const mbedtls_asn1_buf *)oid, 
                                   (mbedtls_md_type_t *)md_alg, (mbedtls_pk_type_t *)pk_alg);
}

int ssl_platform_oid_get_pk_alg(const ssl_platform_asn1_buf *oid, ssl_platform_pk_type_t *pk_alg)
{
    return mbedtls_oid_get_pk_alg((const mbedtls_asn1_buf *)oid, (mbedtls_pk_type_t *)pk_alg);
}

int ssl_platform_oid_get_oid_by_sig_alg(ssl_platform_pk_type_t pk_alg, ssl_platform_md_type_t md_alg,
                                        const char **oid, size_t *oid_len)
{
    return mbedtls_oid_get_oid_by_sig_alg((mbedtls_pk_type_t)pk_alg, (mbedtls_md_type_t)md_alg, oid, oid_len);
}

int ssl_platform_oid_get_oid_by_pk_alg(ssl_platform_pk_type_t pk_alg,
                                       const char **oid, size_t *oid_len)
{
    return mbedtls_oid_get_oid_by_pk_alg((mbedtls_pk_type_t)pk_alg, oid, oid_len);
}

int ssl_platform_oid_get_oid_by_md(ssl_platform_md_type_t md_alg,
                                   const char **oid, size_t *oid_len)
{
    return mbedtls_oid_get_oid_by_md((mbedtls_md_type_t)md_alg, oid, oid_len);
}

int ssl_platform_oid_get_oid_by_ec_grp(ssl_platform_ecp_group_id grp_id,
                                       const char **oid, size_t *oid_len)
{
    return mbedtls_oid_get_oid_by_ec_grp((mbedtls_ecp_group_id)grp_id, oid, oid_len);
}

int ssl_platform_oid_get_ec_grp(const ssl_platform_asn1_buf *oid, ssl_platform_ecp_group_id *grp_id)
{
    return mbedtls_oid_get_ec_grp((const mbedtls_asn1_buf *)oid, (mbedtls_ecp_group_id *)grp_id);
}

// ASN.1 Sequence and Named Data Functions - mbedTLS implementation
void ssl_platform_asn1_sequence_free(ssl_platform_asn1_sequence *seq)
{
    mbedtls_asn1_sequence_free((mbedtls_asn1_sequence *)seq);
}

// Default callback that does nothing (just counts elements)
static int ssl_platform_asn1_default_cb(void *ctx, int tag, unsigned char *start, size_t len)
{
    (void)ctx;
    (void)tag;
    (void)start;
    (void)len;
    return 0; // Continue processing
}

int ssl_platform_asn1_traverse_sequence_of(unsigned char **p, const unsigned char *end,
                                           unsigned char tag_must_mask, unsigned char tag_must_val,
                                           unsigned char tag_may_mask, unsigned char tag_may_val)
{
    return mbedtls_asn1_traverse_sequence_of(p, end, tag_must_mask, tag_must_val, 
                                           tag_may_mask, tag_may_val, 
                                           ssl_platform_asn1_default_cb, NULL);
}

// ASN.1 Buffer and Utility Functions - mbedTLS implementation
int ssl_platform_asn1_buf_cmp(const ssl_platform_asn1_buf *a, const ssl_platform_asn1_buf *b)
{
    if (a->len != b->len)
        return (a->len < b->len) ? -1 : 1;
    
    if (a->len == 0)
        return 0;
        
    return memcmp(a->p, b->p, a->len);
}

void ssl_platform_asn1_named_data_free(ssl_platform_asn1_named_data *entry)
{
    mbedtls_asn1_free_named_data((mbedtls_asn1_named_data *)entry);
}

ssl_platform_asn1_named_data *ssl_platform_asn1_store_named_data(ssl_platform_asn1_named_data **head,
                                                                 const char *oid, size_t oid_len,
                                                                 const unsigned char *val, size_t val_len)
{
    return (ssl_platform_asn1_named_data *)mbedtls_asn1_store_named_data((mbedtls_asn1_named_data **)head,
                                                                         oid, oid_len, val, val_len);
}

#endif /* SSL_PLATFORM_BACKEND == SSL_PLATFORM_BACKEND_MBEDTLS */ 