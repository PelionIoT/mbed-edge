/*
 * SSL Platform Abstraction Layer - Mbed-TLS Backend Implementation
 * 
 * Copyright (c) 2024
 * 
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ssl_platform.h"

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
        case SSL_PLATFORM_HASH_SHA1:
            mbedtls_sha1_init(&ctx->ctx.sha1);
            break;
        case SSL_PLATFORM_HASH_SHA224:
        case SSL_PLATFORM_HASH_SHA256:
            mbedtls_sha256_init(&ctx->ctx.sha256);
            break;
        case SSL_PLATFORM_HASH_SHA384:
        case SSL_PLATFORM_HASH_SHA512:
            mbedtls_sha512_init(&ctx->ctx.sha512);
            break;
        case SSL_PLATFORM_HASH_MD5:
            mbedtls_md5_init(&ctx->ctx.md5);
            break;
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
        case SSL_PLATFORM_HASH_SHA1:
            mbedtls_sha1_free(&ctx->ctx.sha1);
            break;
        case SSL_PLATFORM_HASH_SHA224:
        case SSL_PLATFORM_HASH_SHA256:
            mbedtls_sha256_free(&ctx->ctx.sha256);
            break;
        case SSL_PLATFORM_HASH_SHA384:
        case SSL_PLATFORM_HASH_SHA512:
            mbedtls_sha512_free(&ctx->ctx.sha512);
            break;
        case SSL_PLATFORM_HASH_MD5:
            mbedtls_md5_free(&ctx->ctx.md5);
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
        case SSL_PLATFORM_HASH_SHA1:
            ret = mbedtls_sha1_starts_ret(&ctx->ctx.sha1);
            break;
        case SSL_PLATFORM_HASH_SHA224:
            ret = mbedtls_sha256_starts_ret(&ctx->ctx.sha256, 1);  /* 1 for SHA224 */
            break;
        case SSL_PLATFORM_HASH_SHA256:
            ret = mbedtls_sha256_starts_ret(&ctx->ctx.sha256, 0);  /* 0 for SHA256 */
            break;
        case SSL_PLATFORM_HASH_SHA384:
            ret = mbedtls_sha512_starts_ret(&ctx->ctx.sha512, 1);  /* 1 for SHA384 */
            break;
        case SSL_PLATFORM_HASH_SHA512:
            ret = mbedtls_sha512_starts_ret(&ctx->ctx.sha512, 0);  /* 0 for SHA512 */
            break;
        case SSL_PLATFORM_HASH_MD5:
            ret = mbedtls_md5_starts_ret(&ctx->ctx.md5);
            break;
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
        case SSL_PLATFORM_HASH_SHA1:
            ret = mbedtls_sha1_update_ret(&ctx->ctx.sha1, input, ilen);
            break;
        case SSL_PLATFORM_HASH_SHA224:
        case SSL_PLATFORM_HASH_SHA256:
            ret = mbedtls_sha256_update_ret(&ctx->ctx.sha256, input, ilen);
            break;
        case SSL_PLATFORM_HASH_SHA384:
        case SSL_PLATFORM_HASH_SHA512:
            ret = mbedtls_sha512_update_ret(&ctx->ctx.sha512, input, ilen);
            break;
        case SSL_PLATFORM_HASH_MD5:
            ret = mbedtls_md5_update_ret(&ctx->ctx.md5, input, ilen);
            break;
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
        case SSL_PLATFORM_HASH_SHA1:
            ret = mbedtls_sha1_finish_ret(&ctx->ctx.sha1, output);
            break;
        case SSL_PLATFORM_HASH_SHA224:
        case SSL_PLATFORM_HASH_SHA256:
            ret = mbedtls_sha256_finish_ret(&ctx->ctx.sha256, output);
            break;
        case SSL_PLATFORM_HASH_SHA384:
        case SSL_PLATFORM_HASH_SHA512:
            ret = mbedtls_sha512_finish_ret(&ctx->ctx.sha512, output);
            break;
        case SSL_PLATFORM_HASH_MD5:
            ret = mbedtls_md5_finish_ret(&ctx->ctx.md5, output);
            break;
        default:
            return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    return ssl_platform_mbedtls_error_map(ret);
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
    if (ctx == NULL || key == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = mbedtls_pk_parse_public_key(&ctx->mbedtls_ctx, key, keylen);
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

#endif /* SSL_PLATFORM_BACKEND == SSL_PLATFORM_BACKEND_MBEDTLS */ 