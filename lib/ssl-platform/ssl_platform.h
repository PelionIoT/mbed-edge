/*
 * SSL Platform Abstraction Layer
 * 
 * Copyright (c) 2024
 * 
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SSL_PLATFORM_H
#define SSL_PLATFORM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Configuration macros for backend selection */
#define SSL_PLATFORM_BACKEND_MBEDTLS  1
#define SSL_PLATFORM_BACKEND_OPENSSL  2

#ifndef SSL_PLATFORM_BACKEND
#define SSL_PLATFORM_BACKEND SSL_PLATFORM_BACKEND_MBEDTLS  /* Default to mbed-TLS */
#endif

/* Error codes */
#define SSL_PLATFORM_SUCCESS                    0
#define SSL_PLATFORM_ERROR_GENERIC             -1
#define SSL_PLATFORM_ERROR_INVALID_PARAMETER   -2
#define SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL    -3
#define SSL_PLATFORM_ERROR_INVALID_DATA        -4
#define SSL_PLATFORM_ERROR_MEMORY_ALLOCATION   -5
#define SSL_PLATFORM_ERROR_NOT_SUPPORTED       -6

/* AES modes */
typedef enum {
    SSL_PLATFORM_AES_ENCRYPT = 1,
    SSL_PLATFORM_AES_DECRYPT = 0
} ssl_platform_aes_mode_t;

/* Hash algorithms */
typedef enum {
    SSL_PLATFORM_HASH_SHA1,
    SSL_PLATFORM_HASH_SHA224,
    SSL_PLATFORM_HASH_SHA256,
    SSL_PLATFORM_HASH_SHA384,
    SSL_PLATFORM_HASH_SHA512,
    SSL_PLATFORM_HASH_MD5
} ssl_platform_hash_type_t;

/* Cipher modes */
typedef enum {
    SSL_PLATFORM_CIPHER_AES_128_ECB,
    SSL_PLATFORM_CIPHER_AES_192_ECB,
    SSL_PLATFORM_CIPHER_AES_256_ECB,
    SSL_PLATFORM_CIPHER_AES_128_CBC,
    SSL_PLATFORM_CIPHER_AES_192_CBC,
    SSL_PLATFORM_CIPHER_AES_256_CBC,
    SSL_PLATFORM_CIPHER_AES_128_GCM,
    SSL_PLATFORM_CIPHER_AES_192_GCM,
    SSL_PLATFORM_CIPHER_AES_256_GCM,
    SSL_PLATFORM_CIPHER_AES_128_CCM,
    SSL_PLATFORM_CIPHER_AES_192_CCM,
    SSL_PLATFORM_CIPHER_AES_256_CCM
} ssl_platform_cipher_type_t;

/* ECC curves */
typedef enum {
    SSL_PLATFORM_ECP_DP_SECP256R1,
    SSL_PLATFORM_ECP_DP_SECP384R1,
    SSL_PLATFORM_ECP_DP_SECP521R1
} ssl_platform_ecp_group_id_t;

/* Forward declarations for opaque types */
typedef struct ssl_platform_aes_context ssl_platform_aes_context_t;
typedef struct ssl_platform_hash_context ssl_platform_hash_context_t;
typedef struct ssl_platform_pk_context ssl_platform_pk_context_t;
typedef struct ssl_platform_x509_crt ssl_platform_x509_crt_t;
typedef struct ssl_platform_entropy_context ssl_platform_entropy_context_t;
typedef struct ssl_platform_ctr_drbg_context ssl_platform_ctr_drbg_context_t;
typedef struct ssl_platform_ssl_context ssl_platform_ssl_context_t;
typedef struct ssl_platform_ssl_config ssl_platform_ssl_config_t;

/* =============================================================================
 * BASE64 OPERATIONS
 * =============================================================================
 */

/**
 * \brief          Encode a buffer into base64 format
 *
 * \param dst      destination buffer
 * \param dlen     size of the destination buffer
 * \param olen     number of bytes written
 * \param src      source buffer
 * \param slen     amount of data to be encoded
 *
 * \return         SSL_PLATFORM_SUCCESS if successful, or SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL.
 *                 *olen is always updated to reflect the amount
 *                 of data that has (or would have) been written.
 */
int ssl_platform_base64_encode(unsigned char *dst, size_t dlen, size_t *olen,
                              const unsigned char *src, size_t slen);

/**
 * \brief          Decode a base64-formatted buffer
 *
 * \param dst      destination buffer (can be NULL for checking size)
 * \param dlen     size of the destination buffer
 * \param olen     number of bytes written
 * \param src      source buffer
 * \param slen     amount of data to be decoded
 *
 * \return         SSL_PLATFORM_SUCCESS if successful, SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL, or
 *                 SSL_PLATFORM_ERROR_INVALID_DATA if the input data is not correct.
 */
int ssl_platform_base64_decode(unsigned char *dst, size_t dlen, size_t *olen,
                               const unsigned char *src, size_t slen);

/* =============================================================================
 * AES OPERATIONS
 * =============================================================================
 */

/**
 * \brief          Initialize AES context
 *
 * \param ctx      AES context to be initialized
 */
void ssl_platform_aes_init(ssl_platform_aes_context_t *ctx);

/**
 * \brief          Clear AES context
 *
 * \param ctx      AES context to be cleared
 */
void ssl_platform_aes_free(ssl_platform_aes_context_t *ctx);

/**
 * \brief          AES key schedule (encryption)
 *
 * \param ctx      AES context to be initialized
 * \param key      encryption key
 * \param keybits  must be 128, 192 or 256
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_aes_setkey_enc(ssl_platform_aes_context_t *ctx,
                                const unsigned char *key,
                                unsigned int keybits);

/**
 * \brief          AES key schedule (decryption)
 *
 * \param ctx      AES context to be initialized
 * \param key      decryption key
 * \param keybits  must be 128, 192 or 256
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_aes_setkey_dec(ssl_platform_aes_context_t *ctx,
                                const unsigned char *key,
                                unsigned int keybits);

/**
 * \brief          AES-ECB block encryption/decryption
 *
 * \param ctx      AES context
 * \param mode     SSL_PLATFORM_AES_ENCRYPT or SSL_PLATFORM_AES_DECRYPT
 * \param input    16-byte input block
 * \param output   16-byte output block
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_aes_crypt_ecb(ssl_platform_aes_context_t *ctx,
                               int mode,
                               const unsigned char input[16],
                               unsigned char output[16]);

/**
 * \brief          AES-CTR buffer encryption/decryption
 *
 * \param ctx      AES context
 * \param length   The length of the input data.
 * \param nc_off   The offset in the current stream_block
 * \param nonce_counter The 128-bit nonce and counter.
 * \param stream_block The saved stream-block for resuming.
 * \param input    The input data stream
 * \param output   The output data stream
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_aes_crypt_ctr(ssl_platform_aes_context_t *ctx,
                               size_t length,
                               size_t *nc_off,
                               unsigned char nonce_counter[16],
                               unsigned char stream_block[16],
                               const unsigned char *input,
                               unsigned char *output);

/* =============================================================================
 * CMAC OPERATIONS
 * =============================================================================
 */

/**
 * \brief          Output = CMAC_128( K, input buffer )
 *
 * \param key      CMAC key
 * \param keylen   length of the CMAC key in bits
 * \param input    buffer holding the input data
 * \param ilen     length of the input data
 * \param output   CMAC result
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_aes_cmac(const unsigned char *key, size_t keylen,
                          const unsigned char *input, size_t ilen,
                          unsigned char *output);

/* =============================================================================
 * HMAC OPERATIONS  
 * =============================================================================
 */

/**
 * \brief          Output = HMAC_SHA256( hmac key, input buffer )
 *
 * \param key      HMAC secret key
 * \param keylen   length of the HMAC key
 * \param input    buffer holding the input data
 * \param ilen     length of the input data
 * \param output   HMAC-SHA256 result
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_hmac_sha256(const unsigned char *key, size_t keylen,
                             const unsigned char *input, size_t ilen,
                             unsigned char *output);

/* =============================================================================
 * HASH OPERATIONS
 * =============================================================================
 */

/**
 * \brief          Initialize hash context
 *
 * \param ctx      Hash context to be initialized
 * \param type     Hash algorithm type
 */
int ssl_platform_hash_init(ssl_platform_hash_context_t *ctx, ssl_platform_hash_type_t type);

/**
 * \brief          Clear hash context
 *
 * \param ctx      Hash context to be cleared
 */
void ssl_platform_hash_free(ssl_platform_hash_context_t *ctx);

/**
 * \brief          Start hash operation
 *
 * \param ctx      Hash context
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_hash_starts(ssl_platform_hash_context_t *ctx);

/**
 * \brief          Hash update
 *
 * \param ctx      Hash context
 * \param input    buffer holding the data
 * \param ilen     length of the input data
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_hash_update(ssl_platform_hash_context_t *ctx,
                             const unsigned char *input,
                             size_t ilen);

/**
 * \brief          Hash finish
 *
 * \param ctx      Hash context
 * \param output   hash checksum result
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_hash_finish(ssl_platform_hash_context_t *ctx,
                             unsigned char *output);

/**
 * \brief          Clone hash context
 *
 * \param dst      Destination hash context
 * \param src      Source hash context
 */
void ssl_platform_hash_clone(ssl_platform_hash_context_t *dst,
                             const ssl_platform_hash_context_t *src);

/**
 * \brief          Get hash output size
 *
 * \param type     Hash algorithm type
 *
 * \return         Hash output size in bytes
 */
size_t ssl_platform_hash_get_size(ssl_platform_hash_type_t type);

/* =============================================================================
 * PUBLIC KEY OPERATIONS
 * =============================================================================
 */

/**
 * \brief          Initialize a PK context
 *
 * \param ctx      Context to be initialized
 */
void ssl_platform_pk_init(ssl_platform_pk_context_t *ctx);

/**
 * \brief          Free the components of a PK context
 *
 * \param ctx      Context to be freed
 */
void ssl_platform_pk_free(ssl_platform_pk_context_t *ctx);

/**
 * \brief          Parse a private key in PEM or DER format
 *
 * \param ctx      The PK context to fill. It must have been initialized
 *                 but not set up.
 * \param key      Input buffer to parse. The buffer must contain the input
 *                 exactly, with no extra trailing material.
 * \param keylen   Size of \b key in bytes.
 * \param pwd      Optional password for decryption
 * \param pwdlen   Size of the password in bytes
 *
 * \return         SSL_PLATFORM_SUCCESS on success, or a specific error code.
 */
int ssl_platform_pk_parse_key(ssl_platform_pk_context_t *ctx,
                              const unsigned char *key, size_t keylen,
                              const unsigned char *pwd, size_t pwdlen);

/**
 * \brief          Parse a public key in PEM or DER format
 *
 * \param ctx      The PK context to fill. It must have been initialized
 *                 but not set up.
 * \param key      Input buffer to parse. The buffer must contain the input
 *                 exactly, with no extra trailing material.
 * \param keylen   Size of \b key in bytes.
 *
 * \return         SSL_PLATFORM_SUCCESS on success, or a specific error code.
 */
int ssl_platform_pk_parse_public_key(ssl_platform_pk_context_t *ctx,
                                     const unsigned char *key, size_t keylen);

/**
 * \brief          Verify signature (including any type of signature, RSA or ECDSA)
 *
 * \param ctx      PK context to use
 * \param md_alg   Hash algorithm used (see notes)
 * \param hash     Hash of the message to sign
 * \param hash_len Hash length or 0 (see notes)
 * \param sig      Signature buffer
 * \param sig_len  Signature length
 *
 * \return         SSL_PLATFORM_SUCCESS on success (signature is valid),
 *                 SSL_PLATFORM_ERROR_INVALID_DATA on failure (signature check failed).
 */
int ssl_platform_pk_verify(ssl_platform_pk_context_t *ctx, ssl_platform_hash_type_t md_alg,
                           const unsigned char *hash, size_t hash_len,
                           const unsigned char *sig, size_t sig_len);

/**
 * \brief          Make signature, including padding if relevant.
 *
 * \param ctx      PK context to use
 * \param md_alg   Hash algorithm used (see notes)
 * \param hash     Hash of the message to sign
 * \param hash_len Hash length or 0 (see notes)
 * \param sig      Place to write signature
 * \param sig_len  Number of bytes written
 * \param f_rng    RNG function
 * \param p_rng    RNG parameter
 *
 * \return         SSL_PLATFORM_SUCCESS on success, or a specific error code.
 */
int ssl_platform_pk_sign(ssl_platform_pk_context_t *ctx, ssl_platform_hash_type_t md_alg,
                         const unsigned char *hash, size_t hash_len,
                         unsigned char *sig, size_t *sig_len,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);

/**
 * \brief          Initialize a PK context with the given key type and setup
 *
 * \param ctx      Context to initialize and setup
 * \param info     Information structure for the key type
 *
 * \return         SSL_PLATFORM_SUCCESS on success, or SSL_PLATFORM_ERROR_* on failure.
 */
int ssl_platform_pk_setup(ssl_platform_pk_context_t *ctx, const void *info);

/**
 * \brief          Write a private key to a PKCS#1 or SEC1 DER structure
 *
 * \param ctx      PK context which must contain a valid private key.
 * \param buf      buffer to write to
 * \param size     size of the buffer
 *
 * \return         length of data written if successful, or a specific
 *                 error code
 */
int ssl_platform_pk_write_key_der(ssl_platform_pk_context_t *ctx,
                                  unsigned char *buf, size_t size);

/**
 * \brief          Write a public key to a SubjectPublicKeyInfo DER structure
 *
 * \param ctx      PK context which must contain a valid public or private key.
 * \param buf      buffer to write to
 * \param size     size of the buffer
 *
 * \return         length of data written if successful, or a specific
 *                 error code
 */
int ssl_platform_pk_write_pubkey_der(ssl_platform_pk_context_t *ctx,
                                     unsigned char *buf, size_t size);

/**
 * \brief          Get access to the underlying backend context
 *                 
 * This function provides access to the underlying crypto library context
 * for advanced operations that are not yet abstracted by ssl_platform.
 * Use with caution as this breaks backend independence.
 *
 * \param ctx      PK context
 *
 * \return         Pointer to underlying context (mbedtls_pk_context* for mbed-TLS,
 *                 EVP_PKEY* for OpenSSL), or NULL on error
 */
void *ssl_platform_pk_get_backend_context(ssl_platform_pk_context_t *ctx);

/* =============================================================================
 * X.509 CERTIFICATE OPERATIONS
 * =============================================================================
 */

/**
 * \brief          Initialize a certificate
 *
 * \param crt      Certificate to initialize
 */
void ssl_platform_x509_crt_init(ssl_platform_x509_crt_t *crt);

/**
 * \brief          Unallocate all certificate data
 *
 * \param crt      Certificate to free
 */
void ssl_platform_x509_crt_free(ssl_platform_x509_crt_t *crt);

/**
 * \brief          Parse one DER-encoded or one or more concatenated PEM-encoded certificates
 *
 * \param chain    Certificate chain to fill
 * \param buf      Buffer holding the certificate data in PEM or DER format
 * \param buflen   Size of the buffer
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_x509_crt_parse(ssl_platform_x509_crt_t *chain,
                                const unsigned char *buf, size_t buflen);

/**
 * \brief          Verify a certificate against CA chain
 *
 * \param crt         Certificate to verify
 * \param trust_ca    CA chain to verify against (can be NULL)
 * \param flags       Verification flags output
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_x509_crt_verify(ssl_platform_x509_crt_t *crt, 
                                 ssl_platform_x509_crt_t *trust_ca,
                                 uint32_t *flags);

/**
 * \brief          Check extended key usage extension
 *
 * \param crt      Certificate to check
 * \param usage    Extended key usage OID
 * \param oid_len  Length of OID
 *
 * \return         SSL_PLATFORM_SUCCESS if usage is found
 */
int ssl_platform_x509_crt_check_extended_key_usage(ssl_platform_x509_crt_t *crt,
                                                   const unsigned char *usage,
                                                   size_t oid_len);

/**
 * \brief          Extract public key from certificate
 *
 * \param crt      Certificate
 * \param pk       Public key context to fill
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_x509_get_pubkey(ssl_platform_x509_crt_t *crt,
                                 ssl_platform_pk_context_t *pk);

/**
 * \brief          Get issuer name in raw DER format
 *
 * \param crt      Certificate
 * \param buf      Buffer to store raw issuer data
 * \param len      Length of the issuer data
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_x509_get_issuer_raw(ssl_platform_x509_crt_t *crt,
                                     unsigned char **buf, size_t *len);

/**
 * \brief          Get subject name in raw DER format
 *
 * \param crt      Certificate
 * \param buf      Buffer to store raw subject data
 * \param len      Length of the subject data
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_x509_get_subject_raw(ssl_platform_x509_crt_t *crt,
                                      unsigned char **buf, size_t *len);

/**
 * \brief          Get certificate validity period
 *
 * \param crt         Certificate
 * \param not_before  Valid from time
 * \param not_after   Valid to time
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_x509_get_validity(ssl_platform_x509_crt_t *crt,
                                   struct tm *not_before, struct tm *not_after);

/**
 * \brief          Get certificate signature
 *
 * \param crt      Certificate
 * \param buf      Buffer to store signature data
 * \param len      Length of the signature data
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_x509_get_signature(ssl_platform_x509_crt_t *crt,
                                    unsigned char **buf, size_t *len);

/**
 * \brief          Get certificate TBS (To Be Signed) data
 *
 * \param crt      Certificate
 * \param buf      Buffer to store TBS data
 * \param len      Length of the TBS data
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_x509_get_tbs(ssl_platform_x509_crt_t *crt,
                              unsigned char **buf, size_t *len);

/* =============================================================================
 * ASN.1 PARSING OPERATIONS
 * =============================================================================
 */

/**
 * \brief          Get tag and length of the element
 *
 * \param p        Pointer to the beginning of the ASN.1 element
 * \param end      End of data
 * \param len      Length of the element
 * \param tag      Expected tag
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_asn1_get_tag(unsigned char **p, const unsigned char *end,
                              size_t *len, int tag);

/* =============================================================================
 * ENTROPY AND RANDOM NUMBER GENERATION
 * =============================================================================
 */

/**
 * \brief          Initialize entropy context
 *
 * \param ctx      Entropy context to initialize
 */
void ssl_platform_entropy_init(ssl_platform_entropy_context_t *ctx);

/**
 * \brief          Free entropy context
 *
 * \param ctx      Entropy context to free
 */
void ssl_platform_entropy_free(ssl_platform_entropy_context_t *ctx);

/**
 * \brief          Initialize CTR-DRBG context
 *
 * \param ctx      CTR-DRBG context to be initialized
 */
void ssl_platform_ctr_drbg_init(ssl_platform_ctr_drbg_context_t *ctx);

/**
 * \brief          Free CTR-DRBG context
 *
 * \param ctx      CTR-DRBG context to be freed
 */
void ssl_platform_ctr_drbg_free(ssl_platform_ctr_drbg_context_t *ctx);

/**
 * \brief          Check if CTR-DRBG is seeded
 *
 * \param ctx      CTR-DRBG context
 *
 * \return         SSL_PLATFORM_SUCCESS if seeded, error otherwise
 */
int ssl_platform_ctr_drbg_is_seeded(ssl_platform_ctr_drbg_context_t *ctx);

/**
 * \brief          Seed CTR-DRBG context
 *
 * \param ctx      CTR-DRBG context
 * \param f_entropy Entropy function
 * \param p_entropy Entropy context
 * \param custom   Custom seed data
 * \param len      Length of custom data
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_ctr_drbg_seed(ssl_platform_ctr_drbg_context_t *ctx,
                               int (*f_entropy)(void *, unsigned char *, size_t),
                               void *p_entropy,
                               const unsigned char *custom,
                               size_t len);

/**
 * \brief          Generate random data
 *
 * \param p_rng    RNG state
 * \param output   Buffer to fill
 * \param output_len Length of the buffer
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_ctr_drbg_random(void *p_rng, unsigned char *output, size_t output_len);

/* =============================================================================
 * SSL/TLS OPERATIONS
 * =============================================================================
 */

/**
 * \brief          Initialize SSL context
 *
 * \param ssl      SSL context
 */
void ssl_platform_ssl_init(ssl_platform_ssl_context_t *ssl);

/**
 * \brief          Free SSL context
 *
 * \param ssl      SSL context
 */
void ssl_platform_ssl_free(ssl_platform_ssl_context_t *ssl);

/**
 * \brief          Initialize SSL configuration
 *
 * \param conf     SSL configuration
 */
void ssl_platform_ssl_config_init(ssl_platform_ssl_config_t *conf);

/**
 * \brief          Free SSL configuration
 *
 * \param conf     SSL configuration
 */
void ssl_platform_ssl_config_free(ssl_platform_ssl_config_t *conf);

/* =============================================================================
 * BACKEND-SPECIFIC INCLUDES
 * =============================================================================
 */

#if SSL_PLATFORM_BACKEND == SSL_PLATFORM_BACKEND_MBEDTLS
#include "ssl_platform_mbedtls.h"
#elif SSL_PLATFORM_BACKEND == SSL_PLATFORM_BACKEND_OPENSSL
#include "ssl_platform_openssl.h"
#else
#error "Unknown SSL platform backend"
#endif

#ifdef __cplusplus
}
#endif

#endif /* SSL_PLATFORM_H */ 