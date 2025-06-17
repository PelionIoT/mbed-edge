/*
 * SSL Platform Abstraction Layer - OpenSSL Backend Implementation
 * 
 * Copyright (c) 2024
 * 
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ssl_platform.h"

#if SSL_PLATFORM_BACKEND == SSL_PLATFORM_BACKEND_OPENSSL

#include <string.h>
#include <stdlib.h>

/* =============================================================================
 * BASE64 OPERATIONS IMPLEMENTATION
 * =============================================================================
 */

int ssl_platform_base64_encode(unsigned char *dst, size_t dlen, size_t *olen,
                              const unsigned char *src, size_t slen)
{
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    
    if (src == NULL || olen == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, src, slen);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    
    *olen = bufferPtr->length;
    
    if (dst == NULL || dlen < *olen) {
        BIO_free_all(bio);
        return (dst == NULL) ? SSL_PLATFORM_SUCCESS : SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL;
    }
    
    memcpy(dst, bufferPtr->data, *olen);
    BIO_free_all(bio);
    
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_base64_decode(unsigned char *dst, size_t dlen, size_t *olen,
                               const unsigned char *src, size_t slen)
{
    BIO *bio, *b64;
    int decode_len;
    
    if (src == NULL || olen == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    // Calculate expected output length
    *olen = (slen * 3) / 4;
    
    if (dst == NULL) {
        return SSL_PLATFORM_SUCCESS;
    }
    
    if (dlen < *olen) {
        return SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL;
    }
    
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(src, slen);
    bio = BIO_push(b64, bio);
    
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    decode_len = BIO_read(bio, dst, dlen);
    BIO_free_all(bio);
    
    if (decode_len < 0) {
        return SSL_PLATFORM_ERROR_INVALID_DATA;
    }
    
    *olen = decode_len;
    return SSL_PLATFORM_SUCCESS;
}

/* =============================================================================
 * AES OPERATIONS IMPLEMENTATION
 * =============================================================================
 */

void ssl_platform_aes_init(ssl_platform_aes_context_t *ctx)
{
    if (ctx != NULL) {
        memset(ctx, 0, sizeof(ssl_platform_aes_context_t));
    }
}

void ssl_platform_aes_free(ssl_platform_aes_context_t *ctx)
{
    if (ctx != NULL) {
        memset(ctx, 0, sizeof(ssl_platform_aes_context_t));
    }
}

int ssl_platform_aes_setkey_enc(ssl_platform_aes_context_t *ctx,
                                const unsigned char *key,
                                unsigned int keybits)
{
    if (ctx == NULL || key == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    ctx->key_bits = keybits;
    ctx->mode = SSL_PLATFORM_AES_ENCRYPT;
    
    if (AES_set_encrypt_key(key, keybits, &ctx->encrypt_key) < 0) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_aes_setkey_dec(ssl_platform_aes_context_t *ctx,
                                const unsigned char *key,
                                unsigned int keybits)
{
    if (ctx == NULL || key == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    ctx->key_bits = keybits;
    ctx->mode = SSL_PLATFORM_AES_DECRYPT;
    
    if (AES_set_decrypt_key(key, keybits, &ctx->decrypt_key) < 0) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_aes_crypt_ecb(ssl_platform_aes_context_t *ctx,
                               int mode,
                               const unsigned char input[16],
                               unsigned char output[16])
{
    if (ctx == NULL || input == NULL || output == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    if (mode == SSL_PLATFORM_AES_ENCRYPT) {
        AES_encrypt(input, output, &ctx->encrypt_key);
    } else {
        AES_decrypt(input, output, &ctx->decrypt_key);
    }
    
    return SSL_PLATFORM_SUCCESS;
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
    ctx->md_ctx = EVP_MD_CTX_new();
    if (ctx->md_ctx == NULL) {
        return SSL_PLATFORM_ERROR_MEMORY_ALLOCATION;
    }
    
    return SSL_PLATFORM_SUCCESS;
}

void ssl_platform_hash_free(ssl_platform_hash_context_t *ctx)
{
    if (ctx != NULL) {
        if (ctx->md_ctx != NULL) {
            EVP_MD_CTX_free(ctx->md_ctx);
            ctx->md_ctx = NULL;
        }
    }
}

int ssl_platform_hash_starts(ssl_platform_hash_context_t *ctx)
{
    if (ctx == NULL || ctx->md_ctx == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    const EVP_MD *md = ssl_platform_hash_type_to_openssl(ctx->type);
    if (md == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    if (EVP_DigestInit_ex(ctx->md_ctx, md, NULL) != 1) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_hash_update(ssl_platform_hash_context_t *ctx,
                             const unsigned char *input,
                             size_t ilen)
{
    if (ctx == NULL || ctx->md_ctx == NULL || input == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    if (EVP_DigestUpdate(ctx->md_ctx, input, ilen) != 1) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_hash_finish(ssl_platform_hash_context_t *ctx,
                             unsigned char *output)
{
    if (ctx == NULL || ctx->md_ctx == NULL || output == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    unsigned int digest_len;
    if (EVP_DigestFinal_ex(ctx->md_ctx, output, &digest_len) != 1) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    return SSL_PLATFORM_SUCCESS;
}

size_t ssl_platform_hash_get_size(ssl_platform_hash_type_t type)
{
    return ssl_platform_openssl_hash_get_size(type);
}

/* =============================================================================
 * PUBLIC KEY OPERATIONS IMPLEMENTATION
 * =============================================================================
 */

void ssl_platform_pk_init(ssl_platform_pk_context_t *ctx)
{
    if (ctx != NULL) {
        ctx->pkey = NULL;
        ctx->key_type = 0;
    }
}

void ssl_platform_pk_free(ssl_platform_pk_context_t *ctx)
{
    if (ctx != NULL) {
        if (ctx->pkey != NULL) {
            EVP_PKEY_free(ctx->pkey);
            ctx->pkey = NULL;
        }
        ctx->key_type = 0;
    }
}

int ssl_platform_pk_parse_key(ssl_platform_pk_context_t *ctx,
                              const unsigned char *key, size_t keylen,
                              const unsigned char *pwd, size_t pwdlen)
{
    if (ctx == NULL || key == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    BIO *bio = BIO_new_mem_buf(key, keylen);
    if (bio == NULL) {
        return SSL_PLATFORM_ERROR_MEMORY_ALLOCATION;
    }
    
    // Try PEM format first
    ctx->pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, (void*)pwd);
    if (ctx->pkey == NULL) {
        // Try DER format
        BIO_reset(bio);
        ctx->pkey = d2i_PrivateKey_bio(bio, NULL);
    }
    
    BIO_free(bio);
    
    if (ctx->pkey == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_DATA;
    }
    
    ctx->key_type = EVP_PKEY_base_id(ctx->pkey);
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_pk_parse_public_key(ssl_platform_pk_context_t *ctx,
                                     const unsigned char *key, size_t keylen)
{
    if (!ctx || !key) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    BIO *bio = BIO_new_mem_buf(key, (int)keylen);
    if (!bio) {
        return SSL_PLATFORM_ERROR_MEMORY_ALLOCATION;
    }
    
    EVP_PKEY *pkey = NULL;
    
    // Try DER format first
    BIO_reset(bio);
    pkey = d2i_PUBKEY_bio(bio, NULL);
    
    if (!pkey) {
        // Try PEM format
        BIO_reset(bio);
        pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    }
    
    BIO_free(bio);
    
    if (!pkey) {
        return SSL_PLATFORM_ERROR_INVALID_DATA;
    }
    
    if (ctx->pkey) {
        EVP_PKEY_free(ctx->pkey);
    }
    ctx->pkey = pkey;
    
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_pk_verify(ssl_platform_pk_context_t *ctx, ssl_platform_hash_type_t md_alg,
                           const unsigned char *hash, size_t hash_len,
                           const unsigned char *sig, size_t sig_len)
{
    if (!ctx || !ctx->pkey || !hash || !sig) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    const EVP_MD *md = NULL;
    switch (md_alg) {
        case SSL_PLATFORM_HASH_SHA1:
            md = EVP_sha1();
            break;
        case SSL_PLATFORM_HASH_SHA224:
            md = EVP_sha224();
            break;
        case SSL_PLATFORM_HASH_SHA256:
            md = EVP_sha256();
            break;
        case SSL_PLATFORM_HASH_SHA384:
            md = EVP_sha384();
            break;
        case SSL_PLATFORM_HASH_SHA512:
            md = EVP_sha512();
            break;
        case SSL_PLATFORM_HASH_MD5:
            md = EVP_md5();
            break;
        default:
            return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
    }
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        return SSL_PLATFORM_ERROR_MEMORY_ALLOCATION;
    }
    
    int ret = SSL_PLATFORM_ERROR_GENERIC;
    if (EVP_DigestVerifyInit(mdctx, NULL, md, NULL, ctx->pkey) == 1) {
        if (EVP_DigestVerify(mdctx, sig, sig_len, hash, hash_len) == 1) {
            ret = SSL_PLATFORM_SUCCESS;
        } else {
            ret = SSL_PLATFORM_ERROR_INVALID_DATA;
        }
    }
    
    EVP_MD_CTX_free(mdctx);
    return ret;
}

int ssl_platform_pk_sign(ssl_platform_pk_context_t *ctx, ssl_platform_hash_type_t md_alg,
                         const unsigned char *hash, size_t hash_len,
                         unsigned char *sig, size_t *sig_len,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    if (!ctx || !ctx->pkey || !hash || !sig || !sig_len) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    (void)f_rng;  // OpenSSL manages randomness internally
    (void)p_rng;
    
    const EVP_MD *md = NULL;
    switch (md_alg) {
        case SSL_PLATFORM_HASH_SHA1:
            md = EVP_sha1();
            break;
        case SSL_PLATFORM_HASH_SHA224:
            md = EVP_sha224();
            break;
        case SSL_PLATFORM_HASH_SHA256:
            md = EVP_sha256();
            break;
        case SSL_PLATFORM_HASH_SHA384:
            md = EVP_sha384();
            break;
        case SSL_PLATFORM_HASH_SHA512:
            md = EVP_sha512();
            break;
        case SSL_PLATFORM_HASH_MD5:
            md = EVP_md5();
            break;
        default:
            return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
    }
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        return SSL_PLATFORM_ERROR_MEMORY_ALLOCATION;
    }
    
    int ret = SSL_PLATFORM_ERROR_GENERIC;
    if (EVP_DigestSignInit(mdctx, NULL, md, NULL, ctx->pkey) == 1) {
        if (EVP_DigestSign(mdctx, sig, sig_len, hash, hash_len) == 1) {
            ret = SSL_PLATFORM_SUCCESS;
        }
    }
    
    EVP_MD_CTX_free(mdctx);
    return ret;
}

int ssl_platform_pk_setup(ssl_platform_pk_context_t *ctx, const void *info)
{
    if (!ctx) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    // OpenSSL doesn't require explicit setup like mbedTLS
    // This is a no-op for OpenSSL backend
    (void)info;
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_pk_write_key_der(ssl_platform_pk_context_t *ctx,
                                  unsigned char *buf, size_t size)
{
    if (!ctx || !ctx->pkey || !buf) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        return SSL_PLATFORM_ERROR_MEMORY_ALLOCATION;
    }
    
    int ret = SSL_PLATFORM_ERROR_GENERIC;
    if (i2d_PrivateKey_bio(bio, ctx->pkey) == 1) {
        BUF_MEM *mem;
        BIO_get_mem_ptr(bio, &mem);
        
        if (mem->length <= size) {
            memcpy(buf, mem->data, mem->length);
            ret = (int)mem->length;
        } else {
            ret = SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL;
        }
    }
    
    BIO_free(bio);
    return ret;
}

int ssl_platform_pk_write_pubkey_der(ssl_platform_pk_context_t *ctx,
                                     unsigned char *buf, size_t size)
{
    if (!ctx || !ctx->pkey || !buf) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        return SSL_PLATFORM_ERROR_MEMORY_ALLOCATION;
    }
    
    int ret = SSL_PLATFORM_ERROR_GENERIC;
    if (i2d_PUBKEY_bio(bio, ctx->pkey) == 1) {
        BUF_MEM *mem;
        BIO_get_mem_ptr(bio, &mem);
        
        if (mem->length <= size) {
            memcpy(buf, mem->data, mem->length);
            ret = (int)mem->length;
        } else {
            ret = SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL;
        }
    }
    
    BIO_free(bio);
    return ret;
}

void *ssl_platform_pk_get_backend_context(ssl_platform_pk_context_t *ctx)
{
    if (!ctx) {
        return NULL;
    }
    return ctx->pkey;
}

/* =============================================================================
 * X.509 CERTIFICATE OPERATIONS IMPLEMENTATION
 * =============================================================================
 */

void ssl_platform_x509_crt_init(ssl_platform_x509_crt_t *crt)
{
    if (crt != NULL) {
        crt->cert = NULL;
        crt->next = NULL;
    }
}

void ssl_platform_x509_crt_free(ssl_platform_x509_crt_t *crt)
{
    ssl_platform_x509_crt_t *current = crt;
    while (current != NULL) {
        ssl_platform_x509_crt_t *next = current->next;
        if (current->cert != NULL) {
            X509_free(current->cert);
            current->cert = NULL;
        }
        if (current != crt) { // Don't free the head node
            free(current);
        }
        current = next;
    }
    if (crt != NULL) {
        crt->next = NULL;
    }
}

int ssl_platform_x509_crt_parse(ssl_platform_x509_crt_t *chain,
                                const unsigned char *buf, size_t buflen)
{
    if (chain == NULL || buf == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    BIO *bio = BIO_new_mem_buf(buf, buflen);
    if (bio == NULL) {
        return SSL_PLATFORM_ERROR_MEMORY_ALLOCATION;
    }
    
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (cert == NULL) {
        // Try DER format
        BIO_reset(bio);
        cert = d2i_X509_bio(bio, NULL);
    }
    
    BIO_free(bio);
    
    if (cert == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_DATA;
    }
    
    if (chain->cert == NULL) {
        chain->cert = cert;
    } else {
        // Add to chain
        ssl_platform_x509_crt_t *new_node = malloc(sizeof(ssl_platform_x509_crt_t));
        if (new_node == NULL) {
            X509_free(cert);
            return SSL_PLATFORM_ERROR_MEMORY_ALLOCATION;
        }
        new_node->cert = cert;
        new_node->next = chain->next;
        chain->next = new_node;
    }
    
    return SSL_PLATFORM_SUCCESS;
}

/* =============================================================================
 * ENTROPY AND RANDOM NUMBER GENERATION IMPLEMENTATION
 * =============================================================================
 */

void ssl_platform_entropy_init(ssl_platform_entropy_context_t *ctx)
{
    if (ctx != NULL) {
        ctx->initialized = 1;
    }
}

void ssl_platform_entropy_free(ssl_platform_entropy_context_t *ctx)
{
    if (ctx != NULL) {
        ctx->initialized = 0;
    }
}

void ssl_platform_ctr_drbg_init(ssl_platform_ctr_drbg_context_t *ctx)
{
    if (ctx != NULL) {
        ctx->initialized = 0;
    }
}

void ssl_platform_ctr_drbg_free(ssl_platform_ctr_drbg_context_t *ctx)
{
    if (ctx != NULL) {
        ctx->initialized = 0;
    }
}

int ssl_platform_ctr_drbg_seed(ssl_platform_ctr_drbg_context_t *ctx,
                               int (*f_entropy)(void *, unsigned char *, size_t),
                               void *p_entropy,
                               const unsigned char *custom,
                               size_t len)
{
    if (ctx == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    // OpenSSL handles seeding internally
    ctx->initialized = 1;
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_ctr_drbg_random(void *p_rng, unsigned char *output, size_t output_len)
{
    if (output == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    if (RAND_bytes(output, output_len) != 1) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    return SSL_PLATFORM_SUCCESS;
}

/* =============================================================================
 * SSL/TLS OPERATIONS IMPLEMENTATION
 * =============================================================================
 */

void ssl_platform_ssl_init(ssl_platform_ssl_context_t *ssl)
{
    if (ssl != NULL) {
        ssl->ssl = NULL;
    }
}

void ssl_platform_ssl_free(ssl_platform_ssl_context_t *ssl)
{
    if (ssl != NULL) {
        if (ssl->ssl != NULL) {
            SSL_free(ssl->ssl);
            ssl->ssl = NULL;
        }
    }
}

void ssl_platform_ssl_config_init(ssl_platform_ssl_config_t *conf)
{
    if (conf != NULL) {
        conf->ssl_ctx = NULL;
        conf->endpoint = 0;
        conf->authmode = 0;
        conf->min_version = 0;
        conf->max_version = 0;
    }
}

void ssl_platform_ssl_config_free(ssl_platform_ssl_config_t *conf)
{
    if (conf != NULL) {
        if (conf->ssl_ctx != NULL) {
            SSL_CTX_free(conf->ssl_ctx);
            conf->ssl_ctx = NULL;
        }
    }
}

int ssl_platform_aes_crypt_ctr(ssl_platform_aes_context_t *ctx, size_t length, size_t *nc_off, unsigned char nonce_counter[16], unsigned char stream_block[16], const unsigned char *input, unsigned char *output) { return SSL_PLATFORM_ERROR_NOT_SUPPORTED; }
int ssl_platform_x509_get_tbs(ssl_platform_x509_crt_t *crt, unsigned char **buf, size_t *len) { return SSL_PLATFORM_ERROR_NOT_SUPPORTED; }

int ssl_platform_x509_get_subject_name(ssl_platform_x509_crt_t *crt, char *buf, size_t buf_size) { return SSL_PLATFORM_ERROR_NOT_SUPPORTED; }
int ssl_platform_x509_get_issuer_raw(ssl_platform_x509_crt_t *crt, unsigned char **buf, size_t *len) { return SSL_PLATFORM_ERROR_NOT_SUPPORTED; }
int ssl_platform_x509_get_subject_raw(ssl_platform_x509_crt_t *crt, unsigned char **buf, size_t *len) { return SSL_PLATFORM_ERROR_NOT_SUPPORTED; }
int ssl_platform_x509_get_validity(ssl_platform_x509_crt_t *crt, struct tm *not_before, struct tm *not_after) { return SSL_PLATFORM_ERROR_NOT_SUPPORTED; }
int ssl_platform_x509_get_signature(ssl_platform_x509_crt_t *crt, unsigned char **buf, size_t *len) { return SSL_PLATFORM_ERROR_NOT_SUPPORTED; }
int ssl_platform_x509_crt_check_extended_key_usage(ssl_platform_x509_crt_t *crt, const unsigned char *usage, size_t oid_len) { return SSL_PLATFORM_ERROR_NOT_SUPPORTED; }
int ssl_platform_x509_get_pubkey(ssl_platform_x509_crt_t *crt, ssl_platform_pk_context_t *pk) { return SSL_PLATFORM_ERROR_NOT_SUPPORTED; }
int ssl_platform_ctr_drbg_reseed(ssl_platform_ctr_drbg_context_t *ctx, const unsigned char *additional, size_t len) { return SSL_PLATFORM_SUCCESS; }
#endif /* SSL_PLATFORM_BACKEND == SSL_PLATFORM_BACKEND_OPENSSL */
