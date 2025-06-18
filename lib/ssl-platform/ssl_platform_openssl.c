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
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/cmac.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

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
    
    // Use the general cipher CMAC function with AES-ECB
    ssl_platform_cipher_type_t cipher_type;
    switch (keylen * 8) {
        case 128:
            cipher_type = SSL_PLATFORM_CIPHER_AES_128_ECB;
            break;
        case 192:
            cipher_type = SSL_PLATFORM_CIPHER_AES_192_ECB;
            break;
        case 256:
            cipher_type = SSL_PLATFORM_CIPHER_AES_256_ECB;
            break;
        default:
            return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    return ssl_platform_cipher_cmac(cipher_type, key, keylen * 8, input, ilen, output);
}

void ssl_platform_cipher_init(ssl_platform_cipher_context_t *ctx)
{
    if (ctx != NULL) {
        ctx->ctx = NULL;
        ctx->cipher = NULL;
        ctx->cipher_type = SSL_PLATFORM_CIPHER_AES_128_ECB; // Default
        ctx->cmac_key = NULL;
        ctx->cmac_key_len = 0;
    }
}

void ssl_platform_cipher_free(ssl_platform_cipher_context_t *ctx)
{
    if (ctx != NULL) {
        if (ctx->ctx != NULL) {
            EVP_CIPHER_CTX_free(ctx->ctx);
            ctx->ctx = NULL;
        }
        if (ctx->cmac_key != NULL) {
            OPENSSL_cleanse(ctx->cmac_key, ctx->cmac_key_len);
            free(ctx->cmac_key);
            ctx->cmac_key = NULL;
        }
        ctx->cmac_key_len = 0;
        ctx->cipher = NULL;
    }
}

int ssl_platform_cipher_setup(ssl_platform_cipher_context_t *ctx,
                              ssl_platform_cipher_type_t cipher_type)
{
    if (ctx == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    ctx->cipher = ssl_platform_cipher_type_to_openssl(cipher_type);
    if (ctx->cipher == NULL) {
        return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
    }
    
    ctx->ctx = EVP_CIPHER_CTX_new();
    if (ctx->ctx == NULL) {
        return SSL_PLATFORM_ERROR_MEMORY_ALLOCATION;
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
    
    size_t keylen = keybits / 8;
    
    // Store key for CMAC calculation
    if (ctx->cmac_key != NULL) {
        OPENSSL_cleanse(ctx->cmac_key, ctx->cmac_key_len);
        free(ctx->cmac_key);
    }
    
    ctx->cmac_key = malloc(keylen);
    if (ctx->cmac_key == NULL) {
        return SSL_PLATFORM_ERROR_MEMORY_ALLOCATION;
    }
    
    memcpy(ctx->cmac_key, key, keylen);
    ctx->cmac_key_len = keylen;
    
    // Initialize cipher context for CMAC
    if (EVP_EncryptInit_ex(ctx->ctx, ctx->cipher, NULL, key, NULL) != 1) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_cipher_cmac_update(ssl_platform_cipher_context_t *ctx,
                                    const unsigned char *input,
                                    size_t ilen)
{
    if (ctx == NULL || input == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    // OpenSSL doesn't have a direct streaming CMAC API like mbed-TLS
    // We'll need to buffer the data for the final computation
    // For simplicity, this implementation will be stateless per update
    // A more sophisticated implementation would maintain internal state
    
    // For now, just verify parameters - actual CMAC will be computed in finish
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_cipher_cmac_finish(ssl_platform_cipher_context_t *ctx,
                                    unsigned char *output)
{
    if (ctx == NULL || output == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    // OpenSSL CMAC calculation
    // Note: This is a simplified implementation. A full implementation
    // would need to track all the input data across updates.
    
    // For demo purposes, this will only work with the one-shot CMAC function
    // A production implementation would need to maintain buffered data
    
    return SSL_PLATFORM_ERROR_NOT_SUPPORTED; // Need buffered input data
}

int ssl_platform_cipher_cmac(ssl_platform_cipher_type_t cipher_type,
                             const unsigned char *key, size_t keybits,
                             const unsigned char *input, size_t ilen,
                             unsigned char *output)
{
    if (key == NULL || input == NULL || output == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    const EVP_CIPHER *cipher = ssl_platform_cipher_type_to_openssl(cipher_type);
    if (cipher == NULL) {
        return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
    }
    
    size_t keylen = keybits / 8;
    
#if defined(SSL_PLATFORM_OPENSSL_1_1_0_OR_LATER)
    // Use CMAC API available in OpenSSL 1.1.0+
    CMAC_CTX *cmac_ctx = CMAC_CTX_new();
    if (cmac_ctx == NULL) {
        return SSL_PLATFORM_ERROR_MEMORY_ALLOCATION;
    }
    
    int ret = SSL_PLATFORM_ERROR_GENERIC;
    size_t outlen = 0;
    
    if (CMAC_Init(cmac_ctx, key, keylen, cipher, NULL) == 1 &&
        CMAC_Update(cmac_ctx, input, ilen) == 1 &&
        CMAC_Final(cmac_ctx, output, &outlen) == 1) {
        ret = SSL_PLATFORM_SUCCESS;
    }
    
    CMAC_CTX_free(cmac_ctx);
    return ret;
    
#else
    // Fallback for older OpenSSL versions - implement CMAC manually
    // This is a simplified implementation and may not be complete
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return SSL_PLATFORM_ERROR_MEMORY_ALLOCATION;
    }
    
    int ret = SSL_PLATFORM_ERROR_GENERIC;
    
    // Initialize AES encryption
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL) == 1) {
        // Basic CMAC computation (simplified - missing subkey generation)
        unsigned char block[16] = {0};
        unsigned char temp[16];
        int outlen;
        
        // Process complete blocks
        size_t remaining = ilen;
        const unsigned char *data = input;
        
        while (remaining >= 16) {
            // XOR with previous block
            for (int i = 0; i < 16; i++) {
                block[i] ^= data[i];
            }
            
            // Encrypt block
            if (EVP_EncryptUpdate(ctx, temp, &outlen, block, 16) != 1) {
                goto cleanup;
            }
            memcpy(block, temp, 16);
            
            data += 16;
            remaining -= 16;
        }
        
        // Handle last block (simplified - missing proper padding)
        if (remaining > 0) {
            for (size_t i = 0; i < remaining; i++) {
                block[i] ^= data[i];
            }
            if (remaining < 16) {
                block[remaining] ^= 0x80; // Simple padding
            }
            
            if (EVP_EncryptUpdate(ctx, temp, &outlen, block, 16) == 1) {
                memcpy(output, temp, 16);
                ret = SSL_PLATFORM_SUCCESS;
            }
        } else {
            memcpy(output, block, 16);
            ret = SSL_PLATFORM_SUCCESS;
        }
    }
    
cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
#endif
}

const void *ssl_platform_cipher_info_from_type(ssl_platform_cipher_type_t cipher_type)
{
    return ssl_platform_cipher_type_to_openssl(cipher_type);
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
    
    size_t n = *nc_off;
    
    while (length--) {
        if (n == 0) {
            // Generate keystream block by encrypting the counter
            AES_encrypt(nonce_counter, stream_block, &ctx->encrypt_key);
            
            // Increment the counter (big-endian)
            for (int i = 15; i >= 0; i--) {
                if (++nonce_counter[i] != 0) {
                    break;
                }
            }
        }
        
        // XOR input with keystream to produce output
        *output++ = *input++ ^ stream_block[n];
        n = (n + 1) & 0x0F;
    }
    
    *nc_off = n;
    return SSL_PLATFORM_SUCCESS;
}
int ssl_platform_x509_get_tbs(ssl_platform_x509_crt_t *crt, unsigned char **buf, size_t *len)
{
    if (crt == NULL || crt->cert == NULL || buf == NULL || len == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    // Get the TBS (To Be Signed) portion of the certificate
    // This is the part that gets signed by the CA
    unsigned char *tbs_start = NULL;
    int tbs_len = i2d_re_X509_tbs(crt->cert, &tbs_start);
    
    if (tbs_len <= 0 || tbs_start == NULL) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    *buf = tbs_start;
    *len = (size_t)tbs_len;
    
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_x509_get_subject_name(ssl_platform_x509_crt_t *crt, char *buf, size_t buf_size)
{
    if (crt == NULL || crt->cert == NULL || buf == NULL || buf_size == 0) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    X509_NAME *subject = X509_get_subject_name(crt->cert);
    if (subject == NULL) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    // Convert X509_NAME to string
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        return SSL_PLATFORM_ERROR_MEMORY_ALLOCATION;
    }
    
    if (X509_NAME_print_ex(bio, subject, 0, XN_FLAG_RFC2253) <= 0) {
        BIO_free(bio);
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    BUF_MEM *mem;
    BIO_get_mem_ptr(bio, &mem);
    
    if (mem->length >= buf_size) {
        BIO_free(bio);
        return SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL;
    }
    
    memcpy(buf, mem->data, mem->length);
    buf[mem->length] = '\0';
    
    BIO_free(bio);
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_x509_get_issuer_raw(ssl_platform_x509_crt_t *crt, unsigned char **buf, size_t *len)
{
    if (crt == NULL || crt->cert == NULL || buf == NULL || len == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    X509_NAME *issuer = X509_get_issuer_name(crt->cert);
    if (issuer == NULL) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    // Convert X509_NAME to DER format
    unsigned char *der_buf = NULL;
    int der_len = i2d_X509_NAME(issuer, &der_buf);
    
    if (der_len <= 0 || der_buf == NULL) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    *buf = der_buf;
    *len = (size_t)der_len;
    
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_x509_get_subject_raw(ssl_platform_x509_crt_t *crt, unsigned char **buf, size_t *len)
{
    if (crt == NULL || crt->cert == NULL || buf == NULL || len == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    X509_NAME *subject = X509_get_subject_name(crt->cert);
    if (subject == NULL) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    // Convert X509_NAME to DER format
    unsigned char *der_buf = NULL;
    int der_len = i2d_X509_NAME(subject, &der_buf);
    
    if (der_len <= 0 || der_buf == NULL) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    *buf = der_buf;
    *len = (size_t)der_len;
    
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_x509_get_validity(ssl_platform_x509_crt_t *crt, struct tm *not_before, struct tm *not_after)
{
    if (crt == NULL || crt->cert == NULL || not_before == NULL || not_after == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    const ASN1_TIME *not_before_asn1 = X509_get0_notBefore(crt->cert);
    const ASN1_TIME *not_after_asn1 = X509_get0_notAfter(crt->cert);
    
    if (not_before_asn1 == NULL || not_after_asn1 == NULL) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    // Convert ASN1_TIME to struct tm
    if (ASN1_TIME_to_tm(not_before_asn1, not_before) != 1) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    if (ASN1_TIME_to_tm(not_after_asn1, not_after) != 1) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_x509_get_signature(ssl_platform_x509_crt_t *crt, unsigned char **buf, size_t *len)
{
    if (crt == NULL || crt->cert == NULL || buf == NULL || len == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    const ASN1_BIT_STRING *signature;
    const X509_ALGOR *alg;
    
    X509_get0_signature(&signature, &alg, crt->cert);
    
    if (signature == NULL) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    // Allocate buffer for signature data
    unsigned char *sig_buf = malloc(signature->length);
    if (sig_buf == NULL) {
        return SSL_PLATFORM_ERROR_MEMORY_ALLOCATION;
    }
    
    memcpy(sig_buf, signature->data, signature->length);
    
    *buf = sig_buf;
    *len = signature->length;
    
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_x509_crt_check_extended_key_usage(ssl_platform_x509_crt_t *crt, 
                                                   const unsigned char *usage, 
                                                   size_t oid_len)
{
    if (crt == NULL || crt->cert == NULL || usage == NULL || oid_len == 0) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    // Get the Extended Key Usage extension
    EXTENDED_KEY_USAGE *ext_key_usage = X509_get_ext_d2i(crt->cert, NID_ext_key_usage, NULL, NULL);
    if (ext_key_usage == NULL) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    // Convert usage OID string to ASN1_OBJECT
    ASN1_OBJECT *target_oid = OBJ_txt2obj((const char *)usage, 1);
    if (target_oid == NULL) {
        EXTENDED_KEY_USAGE_free(ext_key_usage);
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    // Check if the target OID is present in the extension
    int found = 0;
    for (int i = 0; i < sk_ASN1_OBJECT_num(ext_key_usage); i++) {
        ASN1_OBJECT *oid = sk_ASN1_OBJECT_value(ext_key_usage, i);
        if (OBJ_cmp(oid, target_oid) == 0) {
            found = 1;
            break;
        }
    }
    
    ASN1_OBJECT_free(target_oid);
    EXTENDED_KEY_USAGE_free(ext_key_usage);
    
    return found ? SSL_PLATFORM_SUCCESS : SSL_PLATFORM_ERROR_GENERIC;
}

int ssl_platform_x509_get_pubkey(ssl_platform_x509_crt_t *crt, ssl_platform_pk_context_t *pk)
{
    if (crt == NULL || crt->cert == NULL || pk == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    EVP_PKEY *pubkey = X509_get_pubkey(crt->cert);
    if (pubkey == NULL) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    // Free any existing key in the PK context
    if (pk->pkey != NULL) {
        EVP_PKEY_free(pk->pkey);
    }
    
    pk->pkey = pubkey;
    pk->key_type = EVP_PKEY_base_id(pubkey);
    
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_ctr_drbg_reseed(ssl_platform_ctr_drbg_context_t *ctx, 
                                 const unsigned char *additional, 
                                 size_t len)
{
    if (ctx == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    // OpenSSL handles reseeding internally through RAND_bytes
    // Additional entropy can be added to the pool
    if (additional != NULL && len > 0) {
        RAND_add(additional, len, len * 0.1);  // Conservative entropy estimate
    }
    
    return SSL_PLATFORM_SUCCESS;
}

/* MPI Implementation */
struct ssl_platform_mpi {
    BIGNUM *bn;
};

int ssl_platform_mpi_init(ssl_platform_mpi_t *X)
{
    if (!X) return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    
    X = malloc(sizeof(struct ssl_platform_mpi));
    if (!X) return SSL_PLATFORM_ERROR_MEMORY_ALLOCATION;
    
    X->bn = BN_new();
    if (!X->bn) {
        free(X);
        return SSL_PLATFORM_ERROR_MEMORY_ALLOCATION;
    }
    
    return SSL_PLATFORM_SUCCESS;
}

void ssl_platform_mpi_free(ssl_platform_mpi_t *X)
{
    if (X) {
        BN_free(X->bn);
        free(X);
    }
}

size_t ssl_platform_mpi_size(const ssl_platform_mpi_t *X)
{
    if (!X || !X->bn) return 0;
    return BN_num_bytes(X->bn);
}

int ssl_platform_mpi_write_binary(const ssl_platform_mpi_t *X, unsigned char *buf, size_t buflen)
{
    if (!X || !X->bn || !buf) return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    
    int bn_size = BN_num_bytes(X->bn);
    if (buflen < bn_size) return SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL;
    
    // Pad with leading zeros if necessary
    memset(buf, 0, buflen - bn_size);
    BN_bn2bin(X->bn, buf + (buflen - bn_size));
    
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_mpi_read_binary(ssl_platform_mpi_t *X, const unsigned char *buf, size_t buflen)
{
    if (!X || !X->bn || !buf) return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    
    if (!BN_bin2bn(buf, buflen, X->bn)) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    return SSL_PLATFORM_SUCCESS;
}

/* ECP Group Implementation */
struct ssl_platform_ecp_group {
    EC_GROUP *group;
};

int ssl_platform_ecp_group_init(ssl_platform_ecp_group_t *grp)
{
    if (!grp) return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    
    grp = malloc(sizeof(struct ssl_platform_ecp_group));
    if (!grp) return SSL_PLATFORM_ERROR_MEMORY_ALLOCATION;
    
    grp->group = NULL; // Will be set in load function
    return SSL_PLATFORM_SUCCESS;
}

void ssl_platform_ecp_group_free(ssl_platform_ecp_group_t *grp)
{
    if (grp) {
        EC_GROUP_free(grp->group);
        free(grp);
    }
}

int ssl_platform_ecp_group_load(ssl_platform_ecp_group_t *grp, ssl_platform_ecp_group_id_t id)
{
    if (!grp) return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    
    int nid;
    switch (id) {
        case SSL_PLATFORM_ECP_DP_SECP256R1:
            nid = NID_X9_62_prime256v1;
            break;
        case SSL_PLATFORM_ECP_DP_SECP384R1:
            nid = NID_secp384r1;
            break;
        case SSL_PLATFORM_ECP_DP_SECP521R1:
            nid = NID_secp521r1;
            break;
        default:
            return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
    }
    
    grp->group = EC_GROUP_new_by_curve_name(nid);
    if (!grp->group) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    return SSL_PLATFORM_SUCCESS;
}

/* ECP Point Implementation */
struct ssl_platform_ecp_point {
    EC_POINT *point;
    EC_GROUP *group; // Keep reference to group for operations
};

int ssl_platform_ecp_point_init(ssl_platform_ecp_point_t *pt)
{
    if (!pt) return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    
    pt = malloc(sizeof(struct ssl_platform_ecp_point));
    if (!pt) return SSL_PLATFORM_ERROR_MEMORY_ALLOCATION;
    
    pt->point = NULL; // Will be created when needed
    pt->group = NULL;
    return SSL_PLATFORM_SUCCESS;
}

void ssl_platform_ecp_point_free(ssl_platform_ecp_point_t *pt)
{
    if (pt) {
        EC_POINT_free(pt->point);
        // Note: don't free group as it's owned by the caller
        free(pt);
    }
}

int ssl_platform_ecp_point_write_binary(const ssl_platform_ecp_group_t *grp,
                                        const ssl_platform_ecp_point_t *pt,
                                        int format, size_t *olen,
                                        unsigned char *buf, size_t buflen)
{
    if (!grp || !grp->group || !pt || !pt->point || !olen || !buf) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    point_conversion_form_t openssl_format = (format == SSL_PLATFORM_ECP_PF_UNCOMPRESSED) ?
                                            POINT_CONVERSION_UNCOMPRESSED : POINT_CONVERSION_COMPRESSED;
    
    size_t ret = EC_POINT_point2oct(grp->group, pt->point, openssl_format, buf, buflen, NULL);
    if (ret == 0) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    *olen = ret;
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_ecp_point_read_binary(const ssl_platform_ecp_group_t *grp,
                                       ssl_platform_ecp_point_t *pt,
                                       const unsigned char *buf, size_t buflen)
{
    if (!grp || !grp->group || !pt || !buf) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    if (!pt->point) {
        pt->point = EC_POINT_new(grp->group);
        if (!pt->point) return SSL_PLATFORM_ERROR_MEMORY_ALLOCATION;
        pt->group = grp->group; // Keep reference
    }
    
    if (!EC_POINT_oct2point(grp->group, pt->point, buf, buflen, NULL)) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    return SSL_PLATFORM_SUCCESS;
}

/* ECP Keypair Implementation */
struct ssl_platform_ecp_keypair {
    EVP_PKEY *pkey;
    EC_KEY *ec_key;
};

ssl_platform_ecp_keypair_t *ssl_platform_pk_get_ecp_keypair(ssl_platform_pk_context_t *ctx)
{
    if (!ctx) return NULL;
    
    // Get the underlying OpenSSL context
    EVP_PKEY *pkey = (EVP_PKEY *)ssl_platform_pk_get_backend_context(ctx);
    if (!pkey || EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
        return NULL;
    }
    
    ssl_platform_ecp_keypair_t *keypair = malloc(sizeof(ssl_platform_ecp_keypair_t));
    if (!keypair) return NULL;
    
    keypair->pkey = pkey;
    keypair->ec_key = EVP_PKEY_get1_EC_KEY(pkey);
    if (!keypair->ec_key) {
        free(keypair);
        return NULL;
    }
    
    return keypair;
}

ssl_platform_ecp_group_t *ssl_platform_ecp_keypair_get_group(ssl_platform_ecp_keypair_t *keypair)
{
    if (!keypair || !keypair->ec_key) return NULL;
    
    ssl_platform_ecp_group_t *grp = malloc(sizeof(ssl_platform_ecp_group_t));
    if (!grp) return NULL;
    
    // Get reference to the group (don't duplicate)
    grp->group = (EC_GROUP *)EC_KEY_get0_group(keypair->ec_key);
    return grp;
}

ssl_platform_ecp_point_t *ssl_platform_ecp_keypair_get_point(ssl_platform_ecp_keypair_t *keypair)
{
    if (!keypair || !keypair->ec_key) return NULL;
    
    ssl_platform_ecp_point_t *pt = malloc(sizeof(ssl_platform_ecp_point_t));
    if (!pt) return NULL;
    
    // Get reference to the public key point (don't duplicate)
    pt->point = (EC_POINT *)EC_KEY_get0_public_key(keypair->ec_key);
    pt->group = (EC_GROUP *)EC_KEY_get0_group(keypair->ec_key);
    return pt;
}

ssl_platform_mpi_t *ssl_platform_ecp_keypair_get_private(ssl_platform_ecp_keypair_t *keypair)
{
    if (!keypair || !keypair->ec_key) return NULL;
    
    ssl_platform_mpi_t *mpi = malloc(sizeof(ssl_platform_mpi_t));
    if (!mpi) return NULL;
    
    // Get reference to the private key BIGNUM (don't duplicate)
    mpi->bn = (BIGNUM *)EC_KEY_get0_private_key(keypair->ec_key);
    return mpi;
}

/* Enhanced PK Operations */
const void *ssl_platform_pk_info_from_type(ssl_platform_pk_type_t type)
{
    // OpenSSL doesn't use info structures like mbedTLS
    // Return the type itself as identifier
    switch (type) {
        case SSL_PLATFORM_PK_ECKEY:
        case SSL_PLATFORM_PK_ECDSA:
            return (void *)(intptr_t)EVP_PKEY_EC;
        case SSL_PLATFORM_PK_RSA:
            return (void *)(intptr_t)EVP_PKEY_RSA;
        default:
            return NULL;
    }
}

int ssl_platform_pk_setup_info(ssl_platform_pk_context_t *ctx, const void *info)
{
    if (!ctx || !info) return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    
    // Get the underlying OpenSSL context
    EVP_PKEY *pkey = (EVP_PKEY *)ssl_platform_pk_get_backend_context(ctx);
    if (!pkey) return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    
    int key_type = (int)(intptr_t)info;
    
    switch (key_type) {
        case EVP_PKEY_EC: {
            EC_KEY *ec_key = EC_KEY_new();
            if (!ec_key) return SSL_PLATFORM_ERROR_MEMORY_ALLOCATION;
            
            if (EVP_PKEY_assign_EC_KEY(pkey, ec_key) != 1) {
                EC_KEY_free(ec_key);
                return SSL_PLATFORM_ERROR_GENERIC;
            }
            break;
        }
        case EVP_PKEY_RSA: {
            RSA *rsa = RSA_new();
            if (!rsa) return SSL_PLATFORM_ERROR_MEMORY_ALLOCATION;
            
            if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
                RSA_free(rsa);
                return SSL_PLATFORM_ERROR_GENERIC;
            }
            break;
        }
        default:
            return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
    }
    
    return SSL_PLATFORM_SUCCESS;
}

/* =============================================================================
 * CCM OPERATIONS IMPLEMENTATION
 * =============================================================================
 */

void ssl_platform_ccm_init(ssl_platform_ccm_context_t *ctx)
{
    if (ctx != NULL) {
        ctx->ctx = EVP_CIPHER_CTX_new();
        ctx->cipher = NULL;
        ctx->key_bits = 0;
        ctx->key_len = 0;
        memset(ctx->key, 0, sizeof(ctx->key));
    }
}

void ssl_platform_ccm_free(ssl_platform_ccm_context_t *ctx)
{
    if (ctx != NULL) {
        if (ctx->ctx != NULL) {
            EVP_CIPHER_CTX_free(ctx->ctx);
            ctx->ctx = NULL;
        }
        ctx->cipher = NULL;
        ctx->key_bits = 0;
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
    
    if (ctx->ctx == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    // Only AES is supported (cipher == 1 typically corresponds to AES)
    if (cipher != 1) {
        return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
    }
    
    // Get the appropriate CCM cipher
    ctx->cipher = ssl_platform_ccm_cipher_from_keybits(keybits);
    if (ctx->cipher == NULL) {
        return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
    }
    
    ctx->key_bits = keybits;
    ctx->key_len = keybits / 8;
    
    // Store the key for later use
    if (ctx->key_len > sizeof(ctx->key)) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    memcpy(ctx->key, key, ctx->key_len);
    
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_ccm_encrypt_and_tag(ssl_platform_ccm_context_t *ctx,
                                     size_t length,
                                     const unsigned char *iv, size_t iv_len,
                                     const unsigned char *add, size_t add_len,
                                     const unsigned char *input,
                                     unsigned char *output,
                                     unsigned char *tag, size_t tag_len)
{
    if (ctx == NULL || ctx->ctx == NULL || ctx->cipher == NULL || 
        iv == NULL || output == NULL || tag == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    if (length > 0 && input == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    if (add_len > 0 && add == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = 1;
    int outlen = 0;
    
    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx->ctx, ctx->cipher, NULL, NULL, NULL) != 1) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx->ctx, EVP_CTRL_CCM_SET_IVLEN, iv_len, NULL) != 1) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    // Set tag length
    if (EVP_CIPHER_CTX_ctrl(ctx->ctx, EVP_CTRL_CCM_SET_TAG, tag_len, NULL) != 1) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    // Set key and IV
    if (EVP_EncryptInit_ex(ctx->ctx, NULL, NULL, ctx->key, iv) != 1) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    // Set plaintext length (required for CCM)
    if (EVP_EncryptUpdate(ctx->ctx, NULL, &outlen, NULL, length) != 1) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    // Provide additional data if present
    if (add_len > 0) {
        if (EVP_EncryptUpdate(ctx->ctx, NULL, &outlen, add, add_len) != 1) {
            return SSL_PLATFORM_ERROR_GENERIC;
        }
    }
    
    // Encrypt plaintext
    if (length > 0) {
        if (EVP_EncryptUpdate(ctx->ctx, output, &outlen, input, length) != 1) {
            return SSL_PLATFORM_ERROR_GENERIC;
        }
    }
    
    // Finalize
    if (EVP_EncryptFinal_ex(ctx->ctx, output + outlen, &outlen) != 1) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    // Get tag
    if (EVP_CIPHER_CTX_ctrl(ctx->ctx, EVP_CTRL_CCM_GET_TAG, tag_len, tag) != 1) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_ccm_auth_decrypt(ssl_platform_ccm_context_t *ctx,
                                  size_t length,
                                  const unsigned char *iv, size_t iv_len,
                                  const unsigned char *add, size_t add_len,
                                  const unsigned char *input,
                                  unsigned char *output,
                                  const unsigned char *tag, size_t tag_len)
{
    if (ctx == NULL || ctx->ctx == NULL || ctx->cipher == NULL || 
        iv == NULL || output == NULL || tag == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    if (length > 0 && input == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    if (add_len > 0 && add == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int ret = 1;
    int outlen = 0;
    
    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx->ctx, ctx->cipher, NULL, NULL, NULL) != 1) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx->ctx, EVP_CTRL_CCM_SET_IVLEN, iv_len, NULL) != 1) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    // Set tag
    if (EVP_CIPHER_CTX_ctrl(ctx->ctx, EVP_CTRL_CCM_SET_TAG, tag_len, (unsigned char *)tag) != 1) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    // Set key and IV
    if (EVP_DecryptInit_ex(ctx->ctx, NULL, NULL, ctx->key, iv) != 1) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    // Set ciphertext length (required for CCM)
    if (EVP_DecryptUpdate(ctx->ctx, NULL, &outlen, NULL, length) != 1) {
        return SSL_PLATFORM_ERROR_GENERIC;
    }
    
    // Provide additional data if present
    if (add_len > 0) {
        if (EVP_DecryptUpdate(ctx->ctx, NULL, &outlen, add, add_len) != 1) {
            return SSL_PLATFORM_ERROR_GENERIC;
        }
    }
    
    // Decrypt ciphertext
    if (length > 0) {
        if (EVP_DecryptUpdate(ctx->ctx, output, &outlen, input, length) != 1) {
            return SSL_PLATFORM_ERROR_GENERIC;
        }
    }
    
    // Finalize and verify tag
    ret = EVP_DecryptFinal_ex(ctx->ctx, output + outlen, &outlen);
    if (ret <= 0) {
        return SSL_PLATFORM_ERROR_INVALID_DATA;  // Authentication failed
    }
    
    return SSL_PLATFORM_SUCCESS;
}

// ASN.1 Writing/Encoding Functions - OpenSSL implementation
int ssl_platform_asn1_write_len(unsigned char **p, unsigned char *start, size_t len)
{
    if (p == NULL || start == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    // OpenSSL doesn't have direct ASN.1 write functions like mbedTLS
    // We need to implement the ASN.1 length encoding manually
    if (len < 0x80) {
        // Short form
        if (*p - start < 1) return SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL;
        *--(*p) = (unsigned char) len;
        return 1;
    } else {
        // Long form
        int len_bytes = 0;
        size_t tmp_len = len;
        
        // Count bytes needed
        while (tmp_len > 0) {
            len_bytes++;
            tmp_len >>= 8;
        }
        
        if (*p - start < len_bytes + 1) return SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL;
        
        // Write length bytes
        tmp_len = len;
        for (int i = 0; i < len_bytes; i++) {
            *--(*p) = (unsigned char)(tmp_len & 0xFF);
            tmp_len >>= 8;
        }
        
        // Write length of length with bit 7 set
        *--(*p) = 0x80 | len_bytes;
        return len_bytes + 1;
    }
}

int ssl_platform_asn1_write_tag(unsigned char **p, unsigned char *start, unsigned char tag)
{
    if (p == NULL || start == NULL || *p <= start) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    *--(*p) = tag;
    return 1;
}

int ssl_platform_asn1_write_int(unsigned char **p, unsigned char *start, int val)
{
    int ret = 0;
    unsigned char *start_p = *p;
    
    if (val == 0) {
        if (*p - start < 1) return SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL;
        *--(*p) = 0;
        ret = 1;
    } else {
        int is_negative = (val < 0);
        unsigned int uval = is_negative ? -val : val;
        
        // Count bytes needed
        int bytes_needed = 0;
        unsigned int temp = uval;
        while (temp > 0) {
            bytes_needed++;
            temp >>= 8;
        }
        
        // Check if we need an extra byte for sign
        if (!is_negative && ((uval >> ((bytes_needed - 1) * 8)) & 0x80)) {
            bytes_needed++;
        }
        
        if (*p - start < bytes_needed) return SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL;
        
        // Write bytes
        for (int i = 0; i < bytes_needed; i++) {
            if (i == bytes_needed - 1 && !is_negative && bytes_needed > 1 && 
                ((uval >> ((bytes_needed - 2) * 8)) & 0x80)) {
                *--(*p) = 0; // Extra zero byte for positive numbers with high bit set
            } else {
                *--(*p) = (unsigned char)((uval >> (i * 8)) & 0xFF);
            }
        }
        
        if (is_negative) {
            // Two's complement
            unsigned char *tmp = *p;
            int carry = 1;
            while (tmp < start_p) {
                *tmp = ~(*tmp);
                if (carry) {
                    (*tmp)++;
                    carry = (*tmp == 0);
                }
                tmp++;
            }
        }
        
        ret = bytes_needed;
    }
    
    // Write length and tag
    int len_ret = ssl_platform_asn1_write_len(p, start, ret);
    if (len_ret < 0) return len_ret;
    
    int tag_ret = ssl_platform_asn1_write_tag(p, start, 0x02); // INTEGER tag
    if (tag_ret < 0) return tag_ret;
    
    return ret + len_ret + tag_ret;
}

int ssl_platform_asn1_write_mpi(unsigned char **p, unsigned char *start, const ssl_platform_mpi *X)
{
    if (p == NULL || start == NULL || X == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    // Use OpenSSL BIGNUM operations
    const BIGNUM *bn = (const BIGNUM *)X;
    
    int bn_size = BN_num_bytes(bn);
    if (*p - start < bn_size + 10) return SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL; // Some extra space for encoding
    
    // Get binary representation
    unsigned char *bin_start = *p - bn_size;
    BN_bn2bin(bn, bin_start);
    
    // Check if we need extra zero byte
    int needs_zero = (bin_start[0] & 0x80) ? 1 : 0;
    if (needs_zero) {
        if (*p - start < bn_size + 1) return SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL;
        memmove(bin_start - 1, bin_start, bn_size);
        bin_start--;
        bin_start[0] = 0;
        bn_size++;
    }
    
    *p = bin_start;
    
    // Write length and tag
    int len_ret = ssl_platform_asn1_write_len(p, start, bn_size);
    if (len_ret < 0) return len_ret;
    
    int tag_ret = ssl_platform_asn1_write_tag(p, start, 0x02); // INTEGER tag
    if (tag_ret < 0) return tag_ret;
    
    return bn_size + len_ret + tag_ret;
}

int ssl_platform_asn1_write_null(unsigned char **p, unsigned char *start)
{
    if (p == NULL || start == NULL || *p - start < 2) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    *--(*p) = 0x00; // NULL value (empty)
    *--(*p) = 0x05; // NULL tag
    return 2;
}

int ssl_platform_asn1_write_oid(unsigned char **p, unsigned char *start, 
                                const char *oid, size_t oid_len)
{
    if (p == NULL || start == NULL || oid == NULL || oid_len == 0) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    // For simplicity, assume oid is already in binary DER format
    if (*p - start < (int)oid_len) return SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL;
    
    *p -= oid_len;
    memcpy(*p, oid, oid_len);
    
    // Write length and tag
    int len_ret = ssl_platform_asn1_write_len(p, start, oid_len);
    if (len_ret < 0) return len_ret;
    
    int tag_ret = ssl_platform_asn1_write_tag(p, start, 0x06); // OID tag
    if (tag_ret < 0) return tag_ret;
    
    return oid_len + len_ret + tag_ret;
}

int ssl_platform_asn1_write_bool(unsigned char **p, unsigned char *start, int boolean)
{
    if (p == NULL || start == NULL || *p - start < 3) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    *--(*p) = boolean ? 0xFF : 0x00;
    *--(*p) = 0x01; // Length = 1
    *--(*p) = 0x01; // BOOLEAN tag
    return 3;
}

int ssl_platform_asn1_write_ia5_string(unsigned char **p, unsigned char *start,
                                       const char *text, size_t text_len)
{
    if (p == NULL || start == NULL || text == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    if (*p - start < (int)text_len) return SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL;
    
    *p -= text_len;
    memcpy(*p, text, text_len);
    
    int len_ret = ssl_platform_asn1_write_len(p, start, text_len);
    if (len_ret < 0) return len_ret;
    
    int tag_ret = ssl_platform_asn1_write_tag(p, start, 0x16); // IA5String tag
    if (tag_ret < 0) return tag_ret;
    
    return text_len + len_ret + tag_ret;
}

int ssl_platform_asn1_write_utf8_string(unsigned char **p, unsigned char *start,
                                        const char *text, size_t text_len)
{
    if (p == NULL || start == NULL || text == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    if (*p - start < (int)text_len) return SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL;
    
    *p -= text_len;
    memcpy(*p, text, text_len);
    
    int len_ret = ssl_platform_asn1_write_len(p, start, text_len);
    if (len_ret < 0) return len_ret;
    
    int tag_ret = ssl_platform_asn1_write_tag(p, start, 0x0C); // UTF8String tag
    if (tag_ret < 0) return tag_ret;
    
    return text_len + len_ret + tag_ret;
}

int ssl_platform_asn1_write_printable_string(unsigned char **p, unsigned char *start,
                                             const char *text, size_t text_len)
{
    if (p == NULL || start == NULL || text == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    if (*p - start < (int)text_len) return SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL;
    
    *p -= text_len;
    memcpy(*p, text, text_len);
    
    int len_ret = ssl_platform_asn1_write_len(p, start, text_len);
    if (len_ret < 0) return len_ret;
    
    int tag_ret = ssl_platform_asn1_write_tag(p, start, 0x13); // PrintableString tag
    if (tag_ret < 0) return tag_ret;
    
    return text_len + len_ret + tag_ret;
}

int ssl_platform_asn1_write_bitstring(unsigned char **p, unsigned char *start,
                                      const unsigned char *buf, size_t bits)
{
    if (p == NULL || start == NULL || buf == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    size_t bytes = (bits + 7) / 8;
    int unused_bits = bits % 8 ? 8 - (bits % 8) : 0;
    
    if (*p - start < (int)(bytes + 1)) return SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL;
    
    *p -= bytes;
    memcpy(*p, buf, bytes);
    
    // Add unused bits byte
    *--(*p) = unused_bits;
    
    int len_ret = ssl_platform_asn1_write_len(p, start, bytes + 1);
    if (len_ret < 0) return len_ret;
    
    int tag_ret = ssl_platform_asn1_write_tag(p, start, 0x03); // BIT STRING tag
    if (tag_ret < 0) return tag_ret;
    
    return bytes + 1 + len_ret + tag_ret;
}

int ssl_platform_asn1_write_octet_string(unsigned char **p, unsigned char *start,
                                         const unsigned char *buf, size_t size)
{
    if (p == NULL || start == NULL || buf == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    if (*p - start < (int)size) return SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL;
    
    *p -= size;
    memcpy(*p, buf, size);
    
    int len_ret = ssl_platform_asn1_write_len(p, start, size);
    if (len_ret < 0) return len_ret;
    
    int tag_ret = ssl_platform_asn1_write_tag(p, start, 0x04); // OCTET STRING tag
    if (tag_ret < 0) return tag_ret;
    
    return size + len_ret + tag_ret;
}

int ssl_platform_asn1_write_sequence_tag(unsigned char **p, unsigned char *start, size_t len)
{
    int len_ret = ssl_platform_asn1_write_len(p, start, len);
    if (len_ret < 0) return len_ret;
    
    int tag_ret = ssl_platform_asn1_write_tag(p, start, 0x30); // SEQUENCE tag
    if (tag_ret < 0) return tag_ret;
    
    return len_ret + tag_ret;
}

int ssl_platform_asn1_write_set_tag(unsigned char **p, unsigned char *start, size_t len)
{
    int len_ret = ssl_platform_asn1_write_len(p, start, len);
    if (len_ret < 0) return len_ret;
    
    int tag_ret = ssl_platform_asn1_write_tag(p, start, 0x31); // SET tag
    if (tag_ret < 0) return tag_ret;
    
    return len_ret + tag_ret;
}

// Enhanced ASN.1 Tag Parsing Functions - OpenSSL implementation
int ssl_platform_asn1_get_tag_ext(unsigned char **p, const unsigned char *end,
                                  size_t *len, int tag, int constructed)
{
    if (p == NULL || end == NULL || len == NULL || *p >= end) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    unsigned char found_tag = **p;
    if (tag >= 0 && found_tag != tag) {
        return SSL_PLATFORM_ERROR_ASN1_UNEXPECTED_TAG;
    }
    
    (*p)++;
    
    // Parse length
    if (*p >= end) return SSL_PLATFORM_ERROR_ASN1_OUT_OF_DATA;
    
    if (**p & 0x80) {
        // Long form
        int len_bytes = **p & 0x7F;
        (*p)++;
        
        if (len_bytes == 0) return SSL_PLATFORM_ERROR_ASN1_INVALID_LENGTH;
        if (*p + len_bytes > end) return SSL_PLATFORM_ERROR_ASN1_OUT_OF_DATA;
        
        *len = 0;
        for (int i = 0; i < len_bytes; i++) {
            *len = (*len << 8) | **p;
            (*p)++;
        }
    } else {
        // Short form
        *len = **p;
        (*p)++;
    }
    
    if (*p + *len > end) return SSL_PLATFORM_ERROR_ASN1_OUT_OF_DATA;
    
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_asn1_get_sequence_of(unsigned char **p, const unsigned char *end,
                                      ssl_platform_asn1_sequence *cur, int tag)
{
    if (p == NULL || end == NULL || cur == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    // This is a simplified implementation
    // In a full implementation, we would parse the sequence and populate cur
    return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
}

int ssl_platform_asn1_get_alg_null(unsigned char **p, const unsigned char *end,
                                   ssl_platform_x509_buf *alg)
{
    if (p == NULL || end == NULL || alg == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    // This is a simplified implementation
    return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
}

int ssl_platform_asn1_get_alg(unsigned char **p, const unsigned char *end,
                              ssl_platform_x509_buf *alg, ssl_platform_x509_buf *params)
{
    if (p == NULL || end == NULL || alg == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    // This is a simplified implementation
    return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
}

// OID Handling Functions - OpenSSL implementation
int ssl_platform_oid_get_attr_short_name(const ssl_platform_asn1_buf *oid, const char **short_name)
{
    if (oid == NULL || short_name == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    // Use OpenSSL's OBJ_* functions
    ASN1_OBJECT *obj = ASN1_OBJECT_create(NID_undef, (unsigned char *)oid->p, oid->len, NULL, NULL);
    if (obj == NULL) return SSL_PLATFORM_ERROR_OID_NOT_FOUND;
    
    int nid = OBJ_obj2nid(obj);
    ASN1_OBJECT_free(obj);
    
    if (nid == NID_undef) return SSL_PLATFORM_ERROR_OID_NOT_FOUND;
    
    *short_name = OBJ_nid2sn(nid);
    return *short_name ? SSL_PLATFORM_SUCCESS : SSL_PLATFORM_ERROR_OID_NOT_FOUND;
}

int ssl_platform_oid_get_extended_key_usage(const ssl_platform_asn1_buf *oid, const char **desc)
{
    if (oid == NULL || desc == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    ASN1_OBJECT *obj = ASN1_OBJECT_create(NID_undef, (unsigned char *)oid->p, oid->len, NULL, NULL);
    if (obj == NULL) return SSL_PLATFORM_ERROR_OID_NOT_FOUND;
    
    int nid = OBJ_obj2nid(obj);
    ASN1_OBJECT_free(obj);
    
    if (nid == NID_undef) return SSL_PLATFORM_ERROR_OID_NOT_FOUND;
    
    *desc = OBJ_nid2ln(nid);
    return *desc ? SSL_PLATFORM_SUCCESS : SSL_PLATFORM_ERROR_OID_NOT_FOUND;
}

int ssl_platform_oid_get_sig_alg_desc(const ssl_platform_asn1_buf *oid, const char **desc)
{
    return ssl_platform_oid_get_extended_key_usage(oid, desc);
}

int ssl_platform_oid_get_sig_alg(const ssl_platform_asn1_buf *oid,
                                 ssl_platform_md_type_t *md_alg, ssl_platform_pk_type_t *pk_alg)
{
    if (oid == NULL || md_alg == NULL || pk_alg == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    ASN1_OBJECT *obj = ASN1_OBJECT_create(NID_undef, (unsigned char *)oid->p, oid->len, NULL, NULL);
    if (obj == NULL) return SSL_PLATFORM_ERROR_OID_NOT_FOUND;
    
    int nid = OBJ_obj2nid(obj);
    ASN1_OBJECT_free(obj);
    
    // Map common signature algorithm NIDs
    switch (nid) {
        case NID_sha1WithRSAEncryption:
            *md_alg = SSL_PLATFORM_MD_SHA1;
            *pk_alg = SSL_PLATFORM_PK_RSA;
            break;
        case NID_sha256WithRSAEncryption:
            *md_alg = SSL_PLATFORM_MD_SHA256;
            *pk_alg = SSL_PLATFORM_PK_RSA;
            break;
        case NID_sha384WithRSAEncryption:
            *md_alg = SSL_PLATFORM_MD_SHA384;
            *pk_alg = SSL_PLATFORM_PK_RSA;
            break;
        case NID_sha512WithRSAEncryption:
            *md_alg = SSL_PLATFORM_MD_SHA512;
            *pk_alg = SSL_PLATFORM_PK_RSA;
            break;
        case NID_ecdsa_with_SHA1:
            *md_alg = SSL_PLATFORM_MD_SHA1;
            *pk_alg = SSL_PLATFORM_PK_ECDSA;
            break;
        case NID_ecdsa_with_SHA256:
            *md_alg = SSL_PLATFORM_MD_SHA256;
            *pk_alg = SSL_PLATFORM_PK_ECDSA;
            break;
        case NID_ecdsa_with_SHA384:
            *md_alg = SSL_PLATFORM_MD_SHA384;
            *pk_alg = SSL_PLATFORM_PK_ECDSA;
            break;
        case NID_ecdsa_with_SHA512:
            *md_alg = SSL_PLATFORM_MD_SHA512;
            *pk_alg = SSL_PLATFORM_PK_ECDSA;
            break;
        default:
            return SSL_PLATFORM_ERROR_OID_NOT_FOUND;
    }
    
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_oid_get_pk_alg(const ssl_platform_asn1_buf *oid, ssl_platform_pk_type_t *pk_alg)
{
    if (oid == NULL || pk_alg == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    ASN1_OBJECT *obj = ASN1_OBJECT_create(NID_undef, (unsigned char *)oid->p, oid->len, NULL, NULL);
    if (obj == NULL) return SSL_PLATFORM_ERROR_OID_NOT_FOUND;
    
    int nid = OBJ_obj2nid(obj);
    ASN1_OBJECT_free(obj);
    
    switch (nid) {
        case NID_rsaEncryption:
            *pk_alg = SSL_PLATFORM_PK_RSA;
            break;
        case NID_X9_62_id_ecPublicKey:
            *pk_alg = SSL_PLATFORM_PK_ECDSA;
            break;
        case NID_dsa:
            *pk_alg = SSL_PLATFORM_PK_DSA;
            break;
        default:
            return SSL_PLATFORM_ERROR_OID_NOT_FOUND;
    }
    
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_oid_get_oid_by_sig_alg(ssl_platform_pk_type_t pk_alg, ssl_platform_md_type_t md_alg,
                                        const char **oid, size_t *oid_len)
{
    if (oid == NULL || oid_len == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int nid = NID_undef;
    
    if (pk_alg == SSL_PLATFORM_PK_RSA) {
        switch (md_alg) {
            case SSL_PLATFORM_MD_SHA1:
                nid = NID_sha1WithRSAEncryption;
                break;
            case SSL_PLATFORM_MD_SHA256:
                nid = NID_sha256WithRSAEncryption;
                break;
            case SSL_PLATFORM_MD_SHA384:
                nid = NID_sha384WithRSAEncryption;
                break;
            case SSL_PLATFORM_MD_SHA512:
                nid = NID_sha512WithRSAEncryption;
                break;
            default:
                return SSL_PLATFORM_ERROR_OID_NOT_FOUND;
        }
    } else if (pk_alg == SSL_PLATFORM_PK_ECDSA) {
        switch (md_alg) {
            case SSL_PLATFORM_MD_SHA1:
                nid = NID_ecdsa_with_SHA1;
                break;
            case SSL_PLATFORM_MD_SHA256:
                nid = NID_ecdsa_with_SHA256;
                break;
            case SSL_PLATFORM_MD_SHA384:
                nid = NID_ecdsa_with_SHA384;
                break;
            case SSL_PLATFORM_MD_SHA512:
                nid = NID_ecdsa_with_SHA512;
                break;
            default:
                return SSL_PLATFORM_ERROR_OID_NOT_FOUND;
        }
    } else {
        return SSL_PLATFORM_ERROR_OID_NOT_FOUND;
    }
    
    ASN1_OBJECT *obj = OBJ_nid2obj(nid);
    if (obj == NULL) return SSL_PLATFORM_ERROR_OID_NOT_FOUND;
    
    *oid = (const char *)obj->data;
    *oid_len = obj->length;
    
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_oid_get_oid_by_pk_alg(ssl_platform_pk_type_t pk_alg,
                                       const char **oid, size_t *oid_len)
{
    if (oid == NULL || oid_len == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int nid = NID_undef;
    
    switch (pk_alg) {
        case SSL_PLATFORM_PK_RSA:
            nid = NID_rsaEncryption;
            break;
        case SSL_PLATFORM_PK_ECDSA:
            nid = NID_X9_62_id_ecPublicKey;
            break;
        case SSL_PLATFORM_PK_DSA:
            nid = NID_dsa;
            break;
        default:
            return SSL_PLATFORM_ERROR_OID_NOT_FOUND;
    }
    
    ASN1_OBJECT *obj = OBJ_nid2obj(nid);
    if (obj == NULL) return SSL_PLATFORM_ERROR_OID_NOT_FOUND;
    
    *oid = (const char *)obj->data;
    *oid_len = obj->length;
    
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_oid_get_oid_by_md(ssl_platform_md_type_t md_alg,
                                   const char **oid, size_t *oid_len)
{
    if (oid == NULL || oid_len == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int nid = NID_undef;
    
    switch (md_alg) {
        case SSL_PLATFORM_MD_SHA1:
            nid = NID_sha1;
            break;
        case SSL_PLATFORM_MD_SHA256:
            nid = NID_sha256;
            break;
        case SSL_PLATFORM_MD_SHA384:
            nid = NID_sha384;
            break;
        case SSL_PLATFORM_MD_SHA512:
            nid = NID_sha512;
            break;
        case SSL_PLATFORM_MD_MD5:
            nid = NID_md5;
            break;
        default:
            return SSL_PLATFORM_ERROR_OID_NOT_FOUND;
    }
    
    ASN1_OBJECT *obj = OBJ_nid2obj(nid);
    if (obj == NULL) return SSL_PLATFORM_ERROR_OID_NOT_FOUND;
    
    *oid = (const char *)obj->data;
    *oid_len = obj->length;
    
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_oid_get_oid_by_ec_grp(ssl_platform_ecp_group_id grp_id,
                                       const char **oid, size_t *oid_len)
{
    if (oid == NULL || oid_len == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    int nid = NID_undef;
    
    switch (grp_id) {
        case SSL_PLATFORM_ECP_DP_SECP256R1:
            nid = NID_X9_62_prime256v1;
            break;
        case SSL_PLATFORM_ECP_DP_SECP384R1:
            nid = NID_secp384r1;
            break;
        case SSL_PLATFORM_ECP_DP_SECP521R1:
            nid = NID_secp521r1;
            break;
        default:
            return SSL_PLATFORM_ERROR_OID_NOT_FOUND;
    }
    
    ASN1_OBJECT *obj = OBJ_nid2obj(nid);
    if (obj == NULL) return SSL_PLATFORM_ERROR_OID_NOT_FOUND;
    
    *oid = (const char *)obj->data;
    *oid_len = obj->length;
    
    return SSL_PLATFORM_SUCCESS;
}

int ssl_platform_oid_get_ec_grp(const ssl_platform_asn1_buf *oid, ssl_platform_ecp_group_id *grp_id)
{
    if (oid == NULL || grp_id == NULL) {
        return SSL_PLATFORM_ERROR_INVALID_PARAMETER;
    }
    
    ASN1_OBJECT *obj = ASN1_OBJECT_create(NID_undef, (unsigned char *)oid->p, oid->len, NULL, NULL);
    if (obj == NULL) return SSL_PLATFORM_ERROR_OID_NOT_FOUND;
    
    int nid = OBJ_obj2nid(obj);
    ASN1_OBJECT_free(obj);
    
    switch (nid) {
        case NID_X9_62_prime256v1:
            *grp_id = SSL_PLATFORM_ECP_DP_SECP256R1;
            break;
        case NID_secp384r1:
            *grp_id = SSL_PLATFORM_ECP_DP_SECP384R1;
            break;
        case NID_secp521r1:
            *grp_id = SSL_PLATFORM_ECP_DP_SECP521R1;
            break;
        default:
            return SSL_PLATFORM_ERROR_OID_NOT_FOUND;
    }
    
    return SSL_PLATFORM_SUCCESS;
}

// ASN.1 Sequence and Named Data Functions - OpenSSL implementation
void ssl_platform_asn1_sequence_free(ssl_platform_asn1_sequence *seq)
{
    // This is a simplified implementation
    // In a full implementation, we would properly free the sequence structure
    if (seq != NULL) {
        // Free any allocated memory in the sequence
        memset(seq, 0, sizeof(ssl_platform_asn1_sequence));
    }
}

int ssl_platform_asn1_traverse_sequence_of(unsigned char **p, const unsigned char *end,
                                           unsigned char tag_must_mask, unsigned char tag_must_val,
                                           unsigned char tag_may_mask, unsigned char tag_may_val)
{
    // This is a simplified implementation
    return SSL_PLATFORM_ERROR_NOT_SUPPORTED;
}

// ASN.1 Buffer and Utility Functions - OpenSSL implementation
int ssl_platform_asn1_buf_cmp(const ssl_platform_asn1_buf *a, const ssl_platform_asn1_buf *b)
{
    if (a == NULL || b == NULL) {
        return (a == b) ? 0 : ((a == NULL) ? -1 : 1);
    }
    
    if (a->len != b->len) {
        return (a->len < b->len) ? -1 : 1;
    }
    
    if (a->len == 0) {
        return 0;
    }
    
    return memcmp(a->p, b->p, a->len);
}

void ssl_platform_asn1_named_data_free(ssl_platform_asn1_named_data *entry)
{
    if (entry != NULL) {
        if (entry->oid.p != NULL) {
            free((void *)entry->oid.p);
        }
        if (entry->val.p != NULL) {
            free((void *)entry->val.p);
        }
        memset(entry, 0, sizeof(ssl_platform_asn1_named_data));
    }
}

ssl_platform_asn1_named_data *ssl_platform_asn1_store_named_data(ssl_platform_asn1_named_data **head,
                                                                 const char *oid, size_t oid_len,
                                                                 const unsigned char *val, size_t val_len)
{
    if (head == NULL || oid == NULL || (val_len > 0 && val == NULL)) {
        return NULL;
    }
    
    // Find existing entry or create new one
    ssl_platform_asn1_named_data *cur = *head;
    while (cur != NULL) {
        if (cur->oid.len == oid_len && memcmp(cur->oid.p, oid, oid_len) == 0) {
            // Found existing entry, update value
            if (cur->val.p != NULL) {
                free((void *)cur->val.p);
            }
            
            cur->val.p = malloc(val_len);
            if (cur->val.p == NULL) return NULL;
            
            memcpy((void *)cur->val.p, val, val_len);
            cur->val.len = val_len;
            return cur;
        }
        cur = cur->next;
    }
    
    // Create new entry
    ssl_platform_asn1_named_data *new_entry = malloc(sizeof(ssl_platform_asn1_named_data));
    if (new_entry == NULL) return NULL;
    
    memset(new_entry, 0, sizeof(ssl_platform_asn1_named_data));
    
    // Copy OID
    new_entry->oid.p = malloc(oid_len);
    if (new_entry->oid.p == NULL) {
        free(new_entry);
        return NULL;
    }
    memcpy((void *)new_entry->oid.p, oid, oid_len);
    new_entry->oid.len = oid_len;
    
    // Copy value
    if (val_len > 0) {
        new_entry->val.p = malloc(val_len);
        if (new_entry->val.p == NULL) {
            free((void *)new_entry->oid.p);
            free(new_entry);
            return NULL;
        }
        memcpy((void *)new_entry->val.p, val, val_len);
        new_entry->val.len = val_len;
    }
    
    // Add to head of list
    new_entry->next = *head;
    *head = new_entry;
    
    return new_entry;
}

#endif /* SSL_PLATFORM_BACKEND == SSL_PLATFORM_BACKEND_OPENSSL */
