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
#include <time.h>
#include <stdbool.h>

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
#define SSL_PLATFORM_ERROR_ASN1_UNEXPECTED_TAG -7
#define SSL_PLATFORM_ERROR_ASN1_OUT_OF_DATA    -8
#define SSL_PLATFORM_ERROR_ASN1_INVALID_LENGTH -9
#define SSL_PLATFORM_ERROR_OID_NOT_FOUND       -10

/* SSL/TLS specific error codes */
#define SSL_PLATFORM_ERROR_WANT_READ           -11
#define SSL_PLATFORM_ERROR_WANT_WRITE          -12
#define SSL_PLATFORM_ERROR_TIMEOUT             -13
#define SSL_PLATFORM_ERROR_CLIENT_RECONNECT    -14
#define SSL_PLATFORM_ERROR_PEER_CLOSE_NOTIFY   -15
#define SSL_PLATFORM_ERROR_HELLO_VERIFY_REQUIRED -18
#define SSL_PLATFORM_ERROR_BAD_INPUT_DATA      -17

/* SSL/TLS configuration constants */
#define SSL_PLATFORM_SSL_IS_CLIENT             0
#define SSL_PLATFORM_SSL_IS_SERVER             1
#define SSL_PLATFORM_SSL_TRANSPORT_STREAM      0
#define SSL_PLATFORM_SSL_TRANSPORT_DATAGRAM    1
#define SSL_PLATFORM_SSL_PRESET_DEFAULT        0

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

/* Message digest types (for compatibility) */
typedef ssl_platform_hash_type_t ssl_platform_md_type_t;

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

/* ECC curve identifiers */
typedef enum {
    SSL_PLATFORM_ECP_DP_NONE = 0,
    SSL_PLATFORM_ECP_DP_SECP256R1,    /* secp256r1 */
    SSL_PLATFORM_ECP_DP_SECP384R1,    /* secp384r1 */
    SSL_PLATFORM_ECP_DP_SECP521R1,    /* secp521r1 */
} ssl_platform_ecp_group_id_t;

/* ASN.1 buffer structure */
typedef struct ssl_platform_asn1_buf {
    int tag;                /**< ASN1 type, e.g. MBEDTLS_ASN1_UTF8_STRING. */
    size_t len;             /**< ASN1 length, in octets. */
    unsigned char *p;       /**< ASN1 data, e.g. in ASCII. */
} ssl_platform_asn1_buf;

/* X.509 buffer (alias for ASN.1 buffer) */
typedef ssl_platform_asn1_buf ssl_platform_x509_buf;

/* ASN.1 sequence structure */
typedef struct ssl_platform_asn1_sequence {
    ssl_platform_asn1_buf buf;                   /**< Buffer containing the given ASN.1 item. */
    struct ssl_platform_asn1_sequence *next;    /**< The next entry in the sequence. */
} ssl_platform_asn1_sequence;

/* ASN.1 named data structure */
typedef struct ssl_platform_asn1_named_data {
    ssl_platform_asn1_buf oid;                         /**< The object identifier. */
    ssl_platform_asn1_buf val;                         /**< The named value. */
    struct ssl_platform_asn1_named_data *next;         /**< The next entry in the sequence. */
    unsigned char next_merged;                          /**< Merge next item into the current one? */
} ssl_platform_asn1_named_data;

/* Forward declarations for opaque types */
typedef struct ssl_platform_aes_context ssl_platform_aes_context_t;
typedef struct ssl_platform_hash_context ssl_platform_hash_context_t;
typedef struct ssl_platform_pk_context ssl_platform_pk_context_t;
typedef struct ssl_platform_x509_crt ssl_platform_x509_crt_t;
typedef struct ssl_platform_entropy_context ssl_platform_entropy_context_t;
typedef struct ssl_platform_ctr_drbg_context ssl_platform_ctr_drbg_context_t;
typedef struct ssl_platform_ssl_context ssl_platform_ssl_context_t;
typedef struct ssl_platform_ssl_config ssl_platform_ssl_config_t;
typedef struct ssl_platform_cipher_context ssl_platform_cipher_context_t;
typedef struct ssl_platform_ccm_context ssl_platform_ccm_context_t;
typedef struct ssl_platform_mpi ssl_platform_mpi_t;
typedef struct ssl_platform_ecp_group ssl_platform_ecp_group_t;
typedef struct ssl_platform_ecp_point ssl_platform_ecp_point_t;
typedef struct ssl_platform_ecp_keypair ssl_platform_ecp_keypair_t;

/* ECC point format constants */
#define SSL_PLATFORM_ECP_PF_UNCOMPRESSED    0    /**< Uncompressed point format */
#define SSL_PLATFORM_ECP_PF_COMPRESSED      1    /**< Compressed point format */

/* Include backend-specific definitions */
#if SSL_PLATFORM_BACKEND == SSL_PLATFORM_BACKEND_MBEDTLS
#include "ssl_platform_mbedtls.h"
#elif SSL_PLATFORM_BACKEND == SSL_PLATFORM_BACKEND_OPENSSL
#include "ssl_platform_openssl.h"
#else
#error "SSL_PLATFORM_BACKEND must be set to either SSL_PLATFORM_BACKEND_MBEDTLS or SSL_PLATFORM_BACKEND_OPENSSL"
#endif

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
 * CIPHER CONTEXT OPERATIONS (CMAC)
 * =============================================================================
 */

/**
 * \brief          Initialize cipher context
 *
 * \param ctx      Cipher context to be initialized
 */
void ssl_platform_cipher_init(ssl_platform_cipher_context_t *ctx);

/**
 * \brief          Free cipher context
 *
 * \param ctx      Cipher context to be freed
 */
void ssl_platform_cipher_free(ssl_platform_cipher_context_t *ctx);

/**
 * \brief          Setup cipher context for CMAC operations
 *
 * \param ctx      Cipher context
 * \param cipher_type Cipher type (e.g., SSL_PLATFORM_CIPHER_AES_128_ECB)
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_cipher_setup(ssl_platform_cipher_context_t *ctx,
                              ssl_platform_cipher_type_t cipher_type);

/**
 * \brief          Start CMAC operation
 *
 * \param ctx      Cipher context
 * \param key      CMAC key
 * \param keybits  Length of the CMAC key in bits
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_cipher_cmac_starts(ssl_platform_cipher_context_t *ctx,
                                    const unsigned char *key,
                                    size_t keybits);

/**
 * \brief          Update CMAC operation with additional data
 *
 * \param ctx      Cipher context
 * \param input    Buffer holding the input data
 * \param ilen     Length of the input data
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_cipher_cmac_update(ssl_platform_cipher_context_t *ctx,
                                    const unsigned char *input,
                                    size_t ilen);

/**
 * \brief          Finish CMAC operation
 *
 * \param ctx      Cipher context
 * \param output   Buffer for the CMAC result
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_cipher_cmac_finish(ssl_platform_cipher_context_t *ctx,
                                    unsigned char *output);

/**
 * \brief          One-shot CMAC calculation
 *
 * \param cipher_type Cipher type (e.g., SSL_PLATFORM_CIPHER_AES_128_ECB)
 * \param key      CMAC key
 * \param keybits  Length of the CMAC key in bits
 * \param input    Buffer holding the input data
 * \param ilen     Length of the input data
 * \param output   Buffer for the CMAC result
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_cipher_cmac(ssl_platform_cipher_type_t cipher_type,
                             const unsigned char *key, size_t keybits,
                             const unsigned char *input, size_t ilen,
                             unsigned char *output);

/**
 * \brief          Get cipher information from type
 *
 * \param cipher_type Cipher type
 *
 * \return         Pointer to cipher info (backend-specific) or NULL on error
 */
const void *ssl_platform_cipher_info_from_type(ssl_platform_cipher_type_t cipher_type);

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
 * CCM OPERATIONS (Counter with CBC-MAC)
 * =============================================================================
 */

/**
 * \brief          Initialize CCM context
 *
 * \param ctx      CCM context to be initialized
 */
void ssl_platform_ccm_init(ssl_platform_ccm_context_t *ctx);

/**
 * \brief          Free CCM context
 *
 * \param ctx      CCM context to be freed
 */
void ssl_platform_ccm_free(ssl_platform_ccm_context_t *ctx);

/**
 * \brief          Set CCM key
 *
 * \param ctx      CCM context
 * \param cipher   The cipher to use (a 128-bit block cipher)
 *                 Currently only MBEDTLS_CIPHER_ID_AES is supported
 * \param key      Encryption key
 * \param keybits  Key size in bits (must be 128, 192 or 256)
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_ccm_setkey(ssl_platform_ccm_context_t *ctx,
                            int cipher,
                            const unsigned char *key,
                            unsigned int keybits);

/**
 * \brief          CCM buffer authenticated encryption
 *
 * \param ctx      CCM context
 * \param length   Length of the input data in bytes
 * \param iv       Initialization vector (nonce)
 * \param iv_len   Length of IV in bytes
 *                 Must be 7, 8, 9, 10, 11, 12, or 13 bytes
 * \param add      Additional data (can be NULL if add_len == 0)
 * \param add_len  Length of additional data in bytes
 * \param input    Buffer holding the input data (can be NULL if length == 0)
 * \param output   Buffer for holding the output data
 *                 Must be at least length bytes wide
 * \param tag      Buffer for holding the authentication tag
 * \param tag_len  Length of the authentication tag to generate in bytes
 *                 Must be 4, 6, 8, 10, 12, 14 or 16
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_ccm_encrypt_and_tag(ssl_platform_ccm_context_t *ctx,
                                     size_t length,
                                     const unsigned char *iv, size_t iv_len,
                                     const unsigned char *add, size_t add_len,
                                     const unsigned char *input,
                                     unsigned char *output,
                                     unsigned char *tag, size_t tag_len);

/**
 * \brief          CCM buffer authenticated decryption
 *
 * \param ctx      CCM context
 * \param length   Length of the input data in bytes
 * \param iv       Initialization vector (nonce)
 * \param iv_len   Length of IV in bytes
 *                 Must be 7, 8, 9, 10, 11, 12, or 13 bytes
 * \param add      Additional data (can be NULL if add_len == 0)
 * \param add_len  Length of additional data in bytes
 * \param input    Buffer holding the input data (can be NULL if length == 0)
 * \param output   Buffer for holding the output data
 *                 Must be at least length bytes wide
 * \param tag      Buffer for holding the authentication tag
 * \param tag_len  Length of the authentication tag in bytes
 *                 Must be 4, 6, 8, 10, 12, 14 or 16
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_ccm_auth_decrypt(ssl_platform_ccm_context_t *ctx,
                                  size_t length,
                                  const unsigned char *iv, size_t iv_len,
                                  const unsigned char *add, size_t add_len,
                                  const unsigned char *input,
                                  unsigned char *output,
                                  const unsigned char *tag, size_t tag_len);

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
 * \brief          Write private key to DER format
 *
 * \param ctx      PK context to use
 * \param buf      Buffer to write to (or NULL to determine required size)
 * \param size     Size of the buffer
 *
 * \return         Number of bytes written on success, or negative error code
 */
int ssl_platform_pk_write_pubkey_der(ssl_platform_pk_context_t *ctx,
                                     unsigned char *buf, size_t size);

/**
 * \brief          Get the underlying backend context for compatibility
 *
 * \param ctx      SSL platform PK context
 *
 * \return         Pointer to the underlying backend context, or NULL on error
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

/**
 * \brief          Get subject name in a human-readable format
 *
 * \param crt      Certificate
 * \param buf      Buffer to store subject name
 * \param buf_size Size of the buffer
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_x509_get_subject_name(ssl_platform_x509_crt_t *crt, char *buf, size_t buf_size);

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
 * \brief          Initialize global entropy system for PAL use
 *                 This creates and initializes a global entropy context for PAL operations
 *
 * \return         SSL_PLATFORM_SUCCESS on success, error code otherwise
 */
int ssl_platform_pal_entropy_init(void);

/**
 * \brief          Get the global PAL entropy context
 *                 Returns the global entropy context for use by PAL functions
 *
 * \return         Pointer to global entropy context, NULL if not initialized
 */
void* ssl_platform_pal_entropy_get(void);

/**
 * \brief          Cleanup global entropy system for PAL use
 *                 This frees the global entropy context used by PAL operations
 *
 * \return         SSL_PLATFORM_SUCCESS on success, error code otherwise
 */
int ssl_platform_pal_entropy_cleanup(void);

/**
 * \brief          Add entropy source to global PAL entropy context
 *
 * \param f_source Entropy source callback function
 * \param p_source Entropy source context
 * \param threshold Minimum bytes required from this source per call
 * \param strong   Whether this is a strong entropy source
 *
 * \return         SSL_PLATFORM_SUCCESS on success, error code otherwise
 */
int ssl_platform_pal_entropy_add_source(int (*f_source)(void *, unsigned char *, size_t, size_t *),
                                        void *p_source, size_t threshold, int strong);

/**
 * \brief          Entropy function wrapper for PAL use
 *                 Compatible with ssl_platform_ctr_drbg_seed entropy function signature
 *
 * \param data     Entropy context (should be PAL entropy context)
 * \param output   Buffer to write entropy data to
 * \param len      Number of bytes to write
 *
 * \return         0 on success, error code otherwise
 */
int ssl_platform_entropy_func(void *data, unsigned char *output, size_t len);

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

/**
 * \brief          Re-seed CTR-DRBG context
 *
 * \param ctx      CTR-DRBG context
 * \param additional Additional seed data
 * \param len      Length of additional seed data
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_ctr_drbg_reseed(ssl_platform_ctr_drbg_context_t *ctx, const unsigned char *additional, size_t len);

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

/**
 * \brief          Set up SSL context with configuration
 *
 * \param ssl      SSL context to set up
 * \param conf     SSL configuration to use
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_ssl_setup(ssl_platform_ssl_context_t *ssl, const ssl_platform_ssl_config_t *conf);

/**
 * \brief          Set SSL configuration defaults
 *
 * \param conf     SSL configuration
 * \param endpoint SSL_PLATFORM_SSL_IS_CLIENT or SSL_PLATFORM_SSL_IS_SERVER
 * \param transport SSL_PLATFORM_SSL_TRANSPORT_STREAM or SSL_PLATFORM_SSL_TRANSPORT_DATAGRAM
 * \param preset   Configuration preset (SSL_PLATFORM_SSL_PRESET_DEFAULT)
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_ssl_config_defaults(ssl_platform_ssl_config_t *conf,
                                    int endpoint, int transport, int preset);

/**
 * \brief          Perform TLS handshake
 *
 * \param ssl      SSL context
 *
 * \return         SSL_PLATFORM_SUCCESS when handshake is finished,
 *                 SSL_PLATFORM_ERROR_WANT_READ/WRITE if handshake is ongoing
 */
int ssl_platform_ssl_handshake(ssl_platform_ssl_context_t *ssl);

/**
 * \brief          Perform one step of TLS handshake
 *
 * \param ssl      SSL context
 *
 * \return         SSL_PLATFORM_SUCCESS when handshake is finished,
 *                 SSL_PLATFORM_ERROR_WANT_READ/WRITE if handshake is ongoing
 */
int ssl_platform_ssl_handshake_step(ssl_platform_ssl_context_t *ssl);

/**
 * \brief          Read data from SSL connection
 *
 * \param ssl      SSL context
 * \param buf      Buffer to read into
 * \param len      Length of buffer
 *
 * \return         Number of bytes read, or a negative error code
 */
int ssl_platform_ssl_read(ssl_platform_ssl_context_t *ssl, unsigned char *buf, size_t len);

/**
 * \brief          Write data to SSL connection
 *
 * \param ssl      SSL context
 * \param buf      Buffer to write from
 * \param len      Length of data to write
 *
 * \return         Number of bytes written, or a negative error code
 */
int ssl_platform_ssl_write(ssl_platform_ssl_context_t *ssl, const unsigned char *buf, size_t len);

/**
 * \brief          Send close notify alert
 *
 * \param ssl      SSL context
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_ssl_close_notify(ssl_platform_ssl_context_t *ssl);

/**
 * \brief          Set RNG function for SSL configuration
 *
 * \param conf     SSL configuration
 * \param f_rng    RNG function
 * \param p_rng    RNG parameter
 */
void ssl_platform_ssl_conf_rng(ssl_platform_ssl_config_t *conf,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng);

/**
 * \brief          Set authentication mode
 *
 * \param conf     SSL configuration
 * \param authmode Authentication mode
 */
void ssl_platform_ssl_conf_authmode(ssl_platform_ssl_config_t *conf, int authmode);

/**
 * \brief          Set certificate chain and private key
 *
 * \param conf     SSL configuration
 * \param own_cert Certificate chain
 * \param pk_key   Private key
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_ssl_conf_own_cert(ssl_platform_ssl_config_t *conf,
                                   ssl_platform_x509_crt_t *own_cert,
                                   ssl_platform_pk_context_t *pk_key);

/**
 * \brief          Set CA certificate chain
 *
 * \param conf     SSL configuration
 * \param ca_chain CA certificate chain
 * \param ca_crl   Certificate revocation list (can be NULL)
 */
void ssl_platform_ssl_conf_ca_chain(ssl_platform_ssl_config_t *conf,
                                    ssl_platform_x509_crt_t *ca_chain,
                                    void *ca_crl);

/**
 * \brief          Set cipher suites list
 *
 * \param conf     SSL configuration
 * \param ciphersuites Array of cipher suite IDs, terminated by 0
 */
void ssl_platform_ssl_conf_ciphersuites(ssl_platform_ssl_config_t *conf,
                                        const int *ciphersuites);

/**
 * \brief          Set handshake timeout
 *
 * \param conf     SSL configuration
 * \param min      Minimum timeout in milliseconds
 * \param max      Maximum timeout in milliseconds
 */
void ssl_platform_ssl_conf_handshake_timeout(ssl_platform_ssl_config_t *conf,
                                             uint32_t min, uint32_t max);

/**
 * \brief          Set pre-shared key and identity
 *
 * \param conf     SSL configuration
 * \param psk      Pre-shared key
 * \param psk_len  Length of PSK
 * \param psk_identity PSK identity
 * \param psk_identity_len Length of PSK identity
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
#if defined(MBEDTLS_KEY_EXCHANGE_SOME_PSK_ENABLED)
int ssl_platform_ssl_conf_psk(ssl_platform_ssl_config_t *conf,
                              const unsigned char *psk, size_t psk_len,
                              const unsigned char *psk_identity, size_t psk_identity_len);
#endif

/**
 * \brief          Set hostname for SNI (Server Name Indication)
 *
 * \param ssl      SSL context
 * \param hostname Server hostname (can be NULL to clear)
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_ssl_set_hostname(ssl_platform_ssl_context_t *ssl, const char *hostname);

/**
 * \brief          Set BIO callbacks
 *
 * \param ssl      SSL context
 * \param p_bio    BIO context
 * \param f_send   Send function
 * \param f_recv   Receive function
 * \param f_recv_timeout Receive with timeout function
 */
void ssl_platform_ssl_set_bio(ssl_platform_ssl_context_t *ssl,
                              void *p_bio,
                              int (*f_send)(void *, const unsigned char *, size_t),
                              int (*f_recv)(void *, unsigned char *, size_t),
                              int (*f_recv_timeout)(void *, unsigned char *, size_t, uint32_t));

/**
 * \brief          Set timer callbacks for DTLS
 *
 * \param ssl      SSL context
 * \param p_timer  Timer context
 * \param f_set_timer Set timer function
 * \param f_get_timer Get timer function
 */
void ssl_platform_ssl_set_timer_cb(ssl_platform_ssl_context_t *ssl,
                                   void *p_timer,
                                   void (*f_set_timer)(void *, uint32_t, uint32_t),
                                   int (*f_get_timer)(void *));

/**
 * \brief          Get verification result
 *
 * \param ssl      SSL context
 *
 * \return         Verification result flags
 */
uint32_t ssl_platform_ssl_get_verify_result(const ssl_platform_ssl_context_t *ssl);

/**
 * \brief          Set debug callback
 *
 * \param conf     SSL configuration
 * \param f_dbg    Debug function
 * \param p_dbg    Debug context
 */
void ssl_platform_ssl_conf_dbg(ssl_platform_ssl_config_t *conf,
                               void (*f_dbg)(void *, int, const char *, int, const char *),
                               void *p_dbg);

/**
 * \brief          Set connection ID for DTLS
 *
 * \param ssl      SSL context
 * \param enable   Whether to enable CID
 * \param own_cid  Own connection ID (can be NULL)
 * \param own_cid_len Length of own connection ID
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_ssl_set_cid(ssl_platform_ssl_context_t *ssl,
                             int enable,
                             unsigned char const *own_cid,
                             size_t own_cid_len);

/**
 * \brief          Get current SSL session
 *
 * \param ssl      SSL context
 * \param session  Session structure to fill
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_ssl_get_session(const ssl_platform_ssl_context_t *ssl,
                                 void *session);

/**
 * \brief          Set SSL session for resumption
 *
 * \param ssl      SSL context
 * \param session  Session structure to use
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_ssl_set_session(ssl_platform_ssl_context_t *ssl,
                                 const void *session);

/**
 * \brief          Save SSL context to buffer
 *
 * \param ssl      SSL context
 * \param buf      Buffer to save to
 * \param buf_len  Buffer length
 * \param olen     Actual length written
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_ssl_context_save(ssl_platform_ssl_context_t *ssl,
                                  unsigned char *buf,
                                  size_t buf_len,
                                  size_t *olen);

/**
 * \brief          Load SSL context from buffer
 *
 * \param ssl      SSL context
 * \param buf      Buffer to load from
 * \param len      Buffer length
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_ssl_context_load(ssl_platform_ssl_context_t *ssl,
                                  const unsigned char *buf,
                                  size_t len);

/**
 * \brief          Initiate SSL renegotiation
 *
 * \param ssl      SSL context
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_ssl_renegotiate(ssl_platform_ssl_context_t *ssl);

/**
 * \brief          Set maximum fragment length
 *
 * \param conf     SSL configuration context
 * \param mfl_code Maximum fragment length code
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_ssl_conf_max_frag_len(ssl_platform_ssl_config_t *conf,
                                       unsigned char mfl_code);

/* SSL/TLS constants */
#define SSL_PLATFORM_SSL_IS_CLIENT                  0
#define SSL_PLATFORM_SSL_IS_SERVER                  1

#define SSL_PLATFORM_SSL_TRANSPORT_STREAM           0
#define SSL_PLATFORM_SSL_TRANSPORT_DATAGRAM         1

#define SSL_PLATFORM_SSL_PRESET_DEFAULT             0

#define SSL_PLATFORM_SSL_VERIFY_NONE                0
#define SSL_PLATFORM_SSL_VERIFY_OPTIONAL            1
#define SSL_PLATFORM_SSL_VERIFY_REQUIRED            2



/* =============================================================================
 * MULTI-PRECISION INTEGER (MPI) OPERATIONS
 * =============================================================================
 */

/**
 * \brief          Initialize an MPI context
 *
 * \param X        MPI context to initialize
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_mpi_init(ssl_platform_mpi_t *X);

/**
 * \brief          Free the components of an MPI context
 *
 * \param X        MPI context to free
 */
void ssl_platform_mpi_free(ssl_platform_mpi_t *X);

/**
 * \brief          Return the number of bytes needed to store the value of X in binary
 *
 * \param X        MPI to use
 *
 * \return         Number of bytes needed to represent X in binary
 */
size_t ssl_platform_mpi_size(const ssl_platform_mpi_t *X);

/**
 * \brief          Export X into unsigned binary data, big endian
 *
 * \param X        Source MPI
 * \param buf      Output buffer
 * \param buflen   Length of the output buffer
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_mpi_write_binary(const ssl_platform_mpi_t *X, unsigned char *buf, size_t buflen);

/**
 * \brief          Import X from unsigned binary data, big endian
 *
 * \param X        Destination MPI
 * \param buf      Input buffer
 * \param buflen   Input buffer size
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_mpi_read_binary(ssl_platform_mpi_t *X, const unsigned char *buf, size_t buflen);

/**
 * \brief          Export X into a hexadecimal string
 *
 * \param X        Source MPI
 * \param radix    Output radix (only 16 is supported)
 * \param buf      Output buffer
 * \param buflen   Size of output buffer
 * \param olen     The number of bytes written to buf
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_mpi_write_string(const ssl_platform_mpi_t *X, int radix,
                                   char *buf, size_t buflen, size_t *olen);

/**
 * \brief          Import X from a hexadecimal string
 *
 * \param X        Destination MPI
 * \param radix    Input radix (only 16 is supported)
 * \param s        Input string
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_mpi_read_string(ssl_platform_mpi_t *X, int radix, const char *s);

/**
 * \brief          Compare signed values
 *
 * \param X        Left-hand side MPI
 * \param Y        Right-hand side MPI
 *
 * \return         1 if X is greater than Y,
 *                -1 if X is lesser than Y or
 *                 0 if X is equal to Y
 */
int ssl_platform_mpi_cmp_mpi(const ssl_platform_mpi_t *X, const ssl_platform_mpi_t *Y);

/**
 * \brief          Compare signed values
 *
 * \param X        Left-hand side MPI
 * \param z        Right-hand side int
 *
 * \return         1 if X is greater than z,
 *                -1 if X is lesser than z or
 *                 0 if X is equal to z
 */
int ssl_platform_mpi_cmp_int(const ssl_platform_mpi_t *X, int z);

/**
 * \brief          Copy the contents of Y into X
 *
 * \param X        Destination MPI
 * \param Y        Source MPI
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_mpi_copy(ssl_platform_mpi_t *X, const ssl_platform_mpi_t *Y);

/**
 * \brief          Set bit to a specific value
 *
 * \param X        MPI to use
 * \param pos      Zero-based index of the bit to modify
 * \param val      Desired value of the bit (0 or 1)
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_mpi_set_bit(ssl_platform_mpi_t *X, size_t pos, unsigned char val);

/**
 * \brief          Get a specific bit from X
 *
 * \param X        MPI to use
 * \param pos      Zero-based index of the bit to query
 *
 * \return         0 or 1 on success, negative on error
 */
int ssl_platform_mpi_get_bit(const ssl_platform_mpi_t *X, size_t pos);

/* =============================================================================
 * ECC GROUP OPERATIONS
 * =============================================================================
 */

/**
 * \brief          Initialize an ECP group context
 *
 * \param grp      Group context to initialize
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_ecp_group_init(ssl_platform_ecp_group_t *grp);

/**
 * \brief          Free the components of an ECP group
 *
 * \param grp      Group context to free
 */
void ssl_platform_ecp_group_free(ssl_platform_ecp_group_t *grp);

/**
 * \brief          Set an ECP group from an identifier
 *
 * \param grp      Destination group
 * \param id       Curve identifier
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_ecp_group_load(ssl_platform_ecp_group_t *grp, ssl_platform_ecp_group_id_t id);

/* =============================================================================
 * ECC POINT OPERATIONS
 * =============================================================================
 */

/**
 * \brief          Initialize an ECP point context
 *
 * \param pt       Point context to initialize
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_ecp_point_init(ssl_platform_ecp_point_t *pt);

/**
 * \brief          Free the components of an ECP point
 *
 * \param pt       Point context to free
 */
void ssl_platform_ecp_point_free(ssl_platform_ecp_point_t *pt);

/**
 * \brief          Export a point as a byte string
 *
 * \param grp      ECP group
 * \param pt       Point to export
 * \param format   Point format (compressed or uncompressed)
 * \param olen     Length of the actual output
 * \param buf      Output buffer
 * \param buflen   Length of the output buffer
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_ecp_point_write_binary(const ssl_platform_ecp_group_t *grp,
                                        const ssl_platform_ecp_point_t *pt,
                                        int format, size_t *olen,
                                        unsigned char *buf, size_t buflen);

/**
 * \brief          Import a point from a byte string
 *
 * \param grp      ECP group
 * \param pt       Destination point
 * \param buf      Input buffer
 * \param buflen   Input buffer length
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_ecp_point_read_binary(const ssl_platform_ecp_group_t *grp,
                                       ssl_platform_ecp_point_t *pt,
                                       const unsigned char *buf, size_t buflen);

/* =============================================================================
 * ECC KEYPAIR OPERATIONS
 * =============================================================================
 */

/**
 * \brief          Get ECC keypair from PK context
 *
 * \param ctx      PK context containing an ECC key
 *
 * \return         Pointer to keypair or NULL on error
 */
void *ssl_platform_pk_get_ecp_keypair(ssl_platform_pk_context_t *ctx);

/**
 * \brief          Get group from ECC keypair
 *
 * \param keypair  ECC keypair
 *
 * \return         Pointer to group or NULL on error
 */
void *ssl_platform_ecp_keypair_get_group(ssl_platform_ecp_keypair_t *keypair);

/**
 * \brief          Get public point from ECC keypair
 *
 * \param keypair  ECC keypair
 *
 * \return         Pointer to public point or NULL on error
 */
ssl_platform_ecp_point_t *ssl_platform_ecp_keypair_get_point(ssl_platform_ecp_keypair_t *keypair);

/**
 * \brief          Get private value from ECC keypair
 *
 * \param keypair  ECC keypair
 *
 * \return         Pointer to private key MPI or NULL on error
 */
ssl_platform_mpi_t *ssl_platform_ecp_keypair_get_private(ssl_platform_ecp_keypair_t *keypair);

/**
 * \brief          Initialize ECC keypair context
 *
 * \param keypair  ECC keypair to initialize
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_ecp_keypair_init(ssl_platform_ecp_keypair_t *keypair);

/**
 * \brief          Free the components of an ECC keypair
 *
 * \param keypair  ECC keypair to free
 */
void ssl_platform_ecp_keypair_free(ssl_platform_ecp_keypair_t *keypair);

/**
 * \brief          Generate ECC keypair
 *
 * \param grp_id   ECC group identifier
 * \param keypair  Destination keypair
 * \param f_rng    RNG function
 * \param p_rng    RNG parameter
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_ecp_gen_key(ssl_platform_ecp_group_id_t grp_id,
                             ssl_platform_ecp_keypair_t *keypair,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng);

/**
 * \brief          Check that a private key is valid for this curve
 *
 * \param grp      ECC group
 * \param d        Private key (MPI)
 *
 * \return         SSL_PLATFORM_SUCCESS if valid
 */
int ssl_platform_ecp_check_privkey(const ssl_platform_ecp_group_t *grp,
                                   const ssl_platform_mpi_t *d);

/**
 * \brief          Check that a point is valid as a public key
 *
 * \param grp      ECC group
 * \param pt       Point to check
 *
 * \return         SSL_PLATFORM_SUCCESS if valid
 */
int ssl_platform_ecp_check_pubkey(const ssl_platform_ecp_group_t *grp,
                                  const ssl_platform_ecp_point_t *pt);

/**
 * \brief          Compute shared secret using ECDH
 *
 * \param grp      ECC group
 * \param z        Destination MPI (shared secret)
 * \param Q        Peer's public key point
 * \param d        Our private key
 * \param f_rng    RNG function
 * \param p_rng    RNG parameter
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_ecdh_compute_shared(const ssl_platform_ecp_group_t *grp,
                                     ssl_platform_mpi_t *z,
                                     const ssl_platform_ecp_point_t *Q,
                                     const ssl_platform_mpi_t *d,
                                     int (*f_rng)(void *, unsigned char *, size_t),
                                     void *p_rng);

/* =============================================================================
 * ENHANCED PK OPERATIONS
 * =============================================================================
 */

typedef enum {
    SSL_PLATFORM_PK_ECKEY,
    SSL_PLATFORM_PK_ECDSA,
    SSL_PLATFORM_PK_RSA,
    SSL_PLATFORM_PK_DSA
} ssl_platform_pk_type_t;

/**
 * \brief          Get key type information structure
 *
 * \param type     Key type
 *
 * \return         Pointer to key info structure
 */
const void *ssl_platform_pk_info_from_type(ssl_platform_pk_type_t type);

/**
 * \brief          Setup PK context with specific key type
 *
 * \param ctx      PK context to setup
 * \param info     Key type information (from ssl_platform_pk_info_from_type)
 *
 * \return         SSL_PLATFORM_SUCCESS on success
 */
int ssl_platform_pk_setup_info(ssl_platform_pk_context_t *ctx, const void *info);

/* =============================================================================
 * ASN.1 WRITING/ENCODING FUNCTIONS
 * =============================================================================
 */

// ASN.1 Writing/Encoding Functions
int ssl_platform_asn1_write_len(unsigned char **p, unsigned char *start, size_t len);
int ssl_platform_asn1_write_tag(unsigned char **p, unsigned char *start, unsigned char tag);
int ssl_platform_asn1_write_int(unsigned char **p, unsigned char *start, int val);
int ssl_platform_asn1_write_mpi(unsigned char **p, unsigned char *start, const ssl_platform_mpi_t *X);
int ssl_platform_asn1_write_null(unsigned char **p, unsigned char *start);
int ssl_platform_asn1_write_oid(unsigned char **p, unsigned char *start, 
                                const char *oid, size_t oid_len);
int ssl_platform_asn1_write_bool(unsigned char **p, unsigned char *start, int boolean);
int ssl_platform_asn1_write_ia5_string(unsigned char **p, unsigned char *start,
                                       const char *text, size_t text_len);
int ssl_platform_asn1_write_utf8_string(unsigned char **p, unsigned char *start,
                                        const char *text, size_t text_len);
int ssl_platform_asn1_write_printable_string(unsigned char **p, unsigned char *start,
                                             const char *text, size_t text_len);
int ssl_platform_asn1_write_bitstring(unsigned char **p, unsigned char *start,
                                      const unsigned char *buf, size_t bits);
int ssl_platform_asn1_write_octet_string(unsigned char **p, unsigned char *start,
                                         const unsigned char *buf, size_t size);
int ssl_platform_asn1_write_sequence_tag(unsigned char **p, unsigned char *start, size_t len);
int ssl_platform_asn1_write_set_tag(unsigned char **p, unsigned char *start, size_t len);

// Enhanced ASN.1 Tag Parsing Functions
int ssl_platform_asn1_get_tag_ext(unsigned char **p, const unsigned char *end,
                                  size_t *len, int tag, int constructed);
int ssl_platform_asn1_get_sequence_of(unsigned char **p, const unsigned char *end,
                                      ssl_platform_asn1_sequence *cur, int tag);
int ssl_platform_asn1_get_alg_null(unsigned char **p, const unsigned char *end,
                                   ssl_platform_x509_buf *alg);
int ssl_platform_asn1_get_alg(unsigned char **p, const unsigned char *end,
                              ssl_platform_x509_buf *alg, ssl_platform_x509_buf *params);

// OID Handling Functions
int ssl_platform_oid_get_attr_short_name(const ssl_platform_asn1_buf *oid, const char **short_name);
int ssl_platform_oid_get_extended_key_usage(const ssl_platform_asn1_buf *oid, const char **desc);
int ssl_platform_oid_get_sig_alg_desc(const ssl_platform_asn1_buf *oid, const char **desc);
int ssl_platform_oid_get_sig_alg(const ssl_platform_asn1_buf *oid,
                                 ssl_platform_md_type_t *md_alg, ssl_platform_pk_type_t *pk_alg);
int ssl_platform_oid_get_pk_alg(const ssl_platform_asn1_buf *oid, ssl_platform_pk_type_t *pk_alg);
int ssl_platform_oid_get_oid_by_sig_alg(ssl_platform_pk_type_t pk_alg, ssl_platform_md_type_t md_alg,
                                        const char **oid, size_t *oid_len);
int ssl_platform_oid_get_oid_by_pk_alg(ssl_platform_pk_type_t pk_alg,
                                       const char **oid, size_t *oid_len);
int ssl_platform_oid_get_oid_by_md(ssl_platform_md_type_t md_alg,
                                   const char **oid, size_t *oid_len);
int ssl_platform_oid_get_oid_by_ec_grp(ssl_platform_ecp_group_id_t grp_id,
                                       const char **oid, size_t *oid_len);
int ssl_platform_oid_get_ec_grp(const ssl_platform_asn1_buf *oid, ssl_platform_ecp_group_id_t *grp_id);

// ASN.1 Sequence and Named Data Functions
void ssl_platform_asn1_sequence_free(ssl_platform_asn1_sequence *seq);
int ssl_platform_asn1_traverse_sequence_of(unsigned char **p, const unsigned char *end,
                                           unsigned char tag_must_mask, unsigned char tag_must_val,
                                           unsigned char tag_may_mask, unsigned char tag_may_val);

// ASN.1 Buffer and Utility Functions
int ssl_platform_asn1_buf_cmp(const ssl_platform_asn1_buf *a, const ssl_platform_asn1_buf *b);
void ssl_platform_asn1_named_data_free(ssl_platform_asn1_named_data *entry);
ssl_platform_asn1_named_data *ssl_platform_asn1_store_named_data(ssl_platform_asn1_named_data **head,
                                                                 const char *oid, size_t oid_len,
                                                                 const unsigned char *val, size_t val_len);

/**
 * \brief          Get the ECC keypair from a PK context
 *
 * \param ctx      SSL platform PK context
 *
 * \return         Pointer to the underlying ECC keypair, or NULL on error
 */
void *ssl_platform_pk_get_ecp_keypair(ssl_platform_pk_context_t *ctx);

/**
 * \brief          Get the private key MPI from an ECC keypair
 *
 * \param keypair  SSL platform ECC keypair
 *
 * \return         Pointer to the private key MPI, or NULL on error
 */
void *ssl_platform_ecp_keypair_get_private_key(ssl_platform_ecp_keypair_t *keypair);

/**
 * \brief          Get the public key point from an ECC keypair
 *
 * \param keypair  SSL platform ECC keypair
 *
 * \return         Pointer to the public key point, or NULL on error
 */
void *ssl_platform_ecp_keypair_get_public_key(ssl_platform_ecp_keypair_t *keypair);

/**
 * \brief          Get the group from an ECC keypair
 *
 * \param keypair  SSL platform ECC keypair
 *
 * \return         Pointer to the ECC group, or NULL on error
 */
void *ssl_platform_ecp_keypair_get_group(ssl_platform_ecp_keypair_t *keypair);

/**
 * \brief          Get the group ID from an ECC group
 *
 * \param group    SSL platform ECC group
 *
 * \return         The group ID, or 0 on error
 */
int ssl_platform_ecp_group_get_id(ssl_platform_ecp_group_t *group);

/**
 * \brief          Get the underlying MPI backend context
 *
 * \param mpi      SSL platform MPI context
 *
 * \return         Pointer to the underlying MPI backend context, or NULL on error
 */
void *ssl_platform_mpi_get_backend_context(ssl_platform_mpi_t *mpi);

/**
 * \brief          Get SSL context state
 *
 * \param ssl      SSL context
 *
 * \return         Current SSL state, or -1 on error
 */
int ssl_platform_ssl_get_state(const ssl_platform_ssl_context_t *ssl);

/**
 * \brief          Check if SSL handshake is complete
 *
 * \param ssl      SSL context
 *
 * \return         true if handshake is complete, false otherwise
 */
bool ssl_platform_ssl_handshake_is_over(const ssl_platform_ssl_context_t *ssl);

/**
 * \brief          Save SSL session for resumption
 *
 * \param ssl      SSL context
 * \param buf      Buffer to save session data
 * \param buf_len  Buffer length
 * \param olen     Actual length of saved session data
 *
 * \return         0 if successful, or error code
 */
int ssl_platform_ssl_session_save(const ssl_platform_ssl_context_t *ssl, unsigned char *buf, size_t buf_len, size_t *olen);

/**
 * \brief          Load SSL session for resumption
 *
 * \param ssl      SSL context
 * \param buf      Buffer containing session data
 * \param len      Length of session data
 *
 * \return         0 if successful, or error code
 */
int ssl_platform_ssl_session_load(ssl_platform_ssl_context_t *ssl, const unsigned char *buf, size_t len);

// Additional error codes for better handshake debugging
#define SSL_PLATFORM_ERROR_CONNECTION_CLOSED   -19
#define SSL_PLATFORM_ERROR_CONNECTION_RESET    -20
#define SSL_PLATFORM_ERROR_HANDSHAKE_FAILED    -21
#define SSL_PLATFORM_ERROR_CERTIFICATE_VERIFY_FAILED -22
#define SSL_PLATFORM_ERROR_UNKNOWN             -23
#define SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL    -24
#define SSL_PLATFORM_ERROR_FEATURE_UNAVAILABLE -25

#ifdef __cplusplus
}
#endif

#endif /* SSL_PLATFORM_H */ 