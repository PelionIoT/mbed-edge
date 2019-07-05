/*
 * ----------------------------------------------------------------------------
 * Copyright 2019 ARM Ltd.
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
 * ----------------------------------------------------------------------------
 */

#ifndef PT_API_VERSION
#define PT_API_VERSION 2
#endif
#if PT_API_VERSION != 2
#error "Including mixed versions of Protocol API"
#endif

#ifndef PT_CRYPTO_API_H_
#define PT_CRYPTO_API_H_

#include <stdint.h>
#include "pt-client-2/pt_common_api.h"

/**
 * \addtogroup EDGE_PT_API_V2
 * @{
 */

/**
 * \file pt-client-2/pt_crypto_api.h
 * \brief API for crypto operations and retrieving certificates and public keys from storage.
 */

/**
 * \brief Type definition for a generic success handler returning a single buffer.
 * \param connection_id ID of the protocol translator connection.
 * \param data Buffer containing the retrieved data.
 * \param size Size of the retrieved data.
 * \param userdata The user-supplied context.
 */
typedef void (*pt_crypto_success_handler)(const connection_id_t connection_id, const uint8_t *data, const size_t size, void *userdata);

/**
 * \brief Type definition for a generic failure response handler.
 * \param connection_id ID of the protocol translator connection.
 * \param error_code Error code indicating reason for failure.
 * \param userdata The user-supplied context.
 */
typedef void (*pt_crypto_failure_handler)(const connection_id_t connection_id, int error_code, void *userdata);

/**
 * \brief Type definition for `pt_crypto_get_item_success_handler` response success handler.
 */
typedef pt_crypto_success_handler pt_crypto_get_item_success_handler;

/**
 * \brief Type definition for `pt_crypto_get_item_failure_handler` response failure handler.
 * \param connection_id ID of the protocol translator connection.
 * \param userdata The user-supplied context.
 */
typedef void (*pt_crypto_get_item_failure_handler)(const connection_id_t connection_id, void *userdata);

/**
 * \brief Retrieve a certificate from secure storage.
 * \param connection_id ID of the protocol translator connection.
 * \param name Name of the certificate to retrieve.
 * \param success_handler This function is called if the certificate is retrieved successfully. Must not be NULL.
 * \param failure_handler This function is called if the certificate retrieval fails. Must not be NULL.
 * \param userdata The user-supplied context.
 * \return PT_STATUS_SUCCESS if certificate retrieval request was sent successfully.\n
 *         Other error codes on failure.
 */
pt_status_t pt_crypto_get_certificate(const connection_id_t connection_id,
                                      const char *name,
                                      pt_crypto_get_item_success_handler success_handler,
                                      pt_crypto_get_item_failure_handler failure_handler,
                                      void *userdata);

/**
 * \brief Retrieve a public key from secure storage.
 * \param connection_id ID of the protocol translator connection.
 * \param name Name of the public key to retrieve.
 * \param success_handler This function is called if the public key is retrieved successfully. Must not be NULL.
 * \param failure_handler This function is called if the public key retrieval fails. Must not be NULL.
 * \param userdata The user-supplied context.
 * \return PT_STATUS_SUCCESS if public key retrieval request was sent successfully.\n
 *         Other error codes on failure.
 */
pt_status_t pt_crypto_get_public_key(const connection_id_t connection_id,
                                     const char *name,
                                     pt_crypto_get_item_success_handler success_handler,
                                     pt_crypto_get_item_failure_handler failure_handler,
                                     void *userdata);

/**
 * \brief Generate and retrieve a random buffer from Device Management Edge.
 * \param connection_id ID of the protocol translator connection.
 * \param size Size of the random buffer to generate.
 * \param success_handler This function is called if the random buffer is generated successfully. Must not be NULL.
 * \param failure_handler This function is called if the random buffer generation fails. Must not be NULL.
 * \param userdata The user-supplied context.
 * \return PT_STATUS_SUCCESS if random buffer was generation request was sent successfully.\n
 *         Other error codes on failure.
 */
pt_status_t pt_crypto_generate_random(const connection_id_t connection_id,
                                      const size_t size,
                                      pt_crypto_success_handler success_handler,
                                      pt_crypto_failure_handler failure_handler,
                                      void *userdata);

/**
 * \brief Perform asymmetric sign operation using given hash digest and private key stored in secure storage on Device Management Edge.
 * \param connection_id ID of the protocol translator connection.
 * \param private_key_name Name of the private key to use.
 * \param hash_digest Hash digest to sign.
 * \param hash_digest_size Size of the hash digest buffer.
 * \param success_handler This function is called if the asymmetric sign operation was successful. Must not be NULL.
 * \param failure_handler This function is called if the asymmetric sign operation failed. Must not be NULL.
 * \param userdata The user-supplied context.
 * \return PT_STATUS_SUCCESS if the asymmetric sign request was sent successfully.\n
 *         Other error codes on failure.
 */
pt_status_t pt_crypto_asymmetric_sign(const connection_id_t connection_id,
                                      const char *private_key_name,
                                      const char *hash_digest,
                                      const size_t hash_digest_size,
                                      pt_crypto_success_handler success_handler,
                                      pt_crypto_failure_handler failure_handler,
                                      void *userdata);

/**
 * \brief Perform asymmetric verify operation on given signature and hash digest using public key stored in secure storage on Device Management Edge.
 * \param connection_id ID of the protocol translator connection.
 * \param public_key_name Name of the public key to use.
 * \param hash_digest Hash digest to verify.
 * \param hash_digest_size Size of the hash digest buffer.
 * \param signature Signature to verify.
 * \param signature_size Size of the signature buffer.
 * \param success_handler This function is called if the asymmetric verify operation was successful. Must not be NULL.
 * \param failure_handler This function is called if the asymmetric verify operation failed. Must not be NULL.
 * \param userdata The user-supplied context.
 * \return PT_STATUS_SUCCESS if the asymmetric verify request was sent successfully.\n
 *         Other error codes on failure.
 */
pt_status_t pt_crypto_asymmetric_verify(const connection_id_t connection_id,
                                        const char *public_key_name,
                                        const char *hash_digest,
                                        const size_t hash_digest_size,
                                        const char *signature,
                                        const size_t signature_size,
                                        pt_crypto_success_handler success_handler,
                                        pt_crypto_failure_handler failure_handler,
                                        void *userdata);

/**
 * \brief Perform ECDH key agreement using given peer public key and a private key stored in secure storage on Device Management Edge.
 * \param connection_id ID of the protocol translator connection.
 * \param private_key_name Name of the private key to use.
 * \param peer_public_key Peer public key in DER format.
 * \param peer_public_key_size Size of the peer public key buffer.
 * \param success_handler This function is called if the ECDH key agreement operation was successful. Must not be NULL.
 * \param failure_handler This function is called if the ECDH key agreement operation failed. Must not be NULL.
 * \param userdata The user-supplied context.
 * \return PT_STATUS_SUCCESS if the ECDH key agreement request was sent successfully.\n
 *         Other error codes on failure.
 */
pt_status_t pt_crypto_ecdh_key_agreement(const connection_id_t connection_id,
                                         const char *private_key_name,
                                         const char *peer_public_key,
                                         const size_t peer_public_key_size,
                                         pt_crypto_success_handler success_handler,
                                         pt_crypto_failure_handler failure_handler,
                                         void *userdata);

/**
 * @}
 * Close EDGE_PT_API_V2 addtogroup
 */

#endif /* PT_CRYPTO_API_H_ */
