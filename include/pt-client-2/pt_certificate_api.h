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

#ifndef PT_CERTIFICATE_API_H_
#define PT_CERTIFICATE_API_H_

#include <stddef.h>
#include <stdbool.h>
#include "pt-client-2/pt_common_api.h"

/**
 * \addtogroup EDGE_PT_API_V2
 * @{
 */

#define CE_STATUS_RANGE_BASE 0x0500
#define CE_STATUS_RANGE_END 0x0600

typedef enum {
    CE_STATUS_SUCCESS = 0,                    //!< Operation completed successfully.
    CE_STATUS_ERROR = CE_STATUS_RANGE_BASE,   //!< Operation ended with an unspecified error.
    CE_STATUS_INVALID_PARAMETER,              //!< A parameter provided to the function was invalid.
    CE_STATUS_INSUFFICIENT_BUFFER,            //!< The provided buffer size was insufficient for the required output.
    CE_STATUS_OUT_OF_MEMORY,                  //!< An out-of-memory condition occurred.
    CE_STATUS_ITEM_NOT_FOUND,                 //!< The item was not found in the storage.
    CE_STATUS_DEVICE_BUSY,                    //!< The device is processing too many certificate renewals.
    CE_STATUS_BAD_INPUT_FROM_SERVER,          //!< The server sent a TLV that is either unsupported or malformed
    CE_STATUS_EST_ERROR,                      //!< An error during enrollment over secure transport (EST) occurred.
    CE_STATUS_STORAGE_ERROR,                  //!< The storage operation ended with an error.
    CE_STATUS_RENEWAL_ITEM_VALIDATION_ERROR,  //!< Operation failed to validate renewal items.
    CE_STATUS_BACKUP_ITEM_ERROR,              //!< Operation failed to create/read/validate backup items.
    CE_STATUS_ORIGINAL_ITEM_ERROR,            //!< Operation failed to create/read/validate original items.
    CE_STATUS_RESTORE_BACKUP_ERROR,           //!< Operation failed to restore backup items.
    CE_STATUS_RENEWAL_STATUS_ERROR,           //!< Operation failed to create/validate/delete the renewal status file.
    CE_STATUS_FORBIDDEN_REQUEST,              //!< The server asked for a forbidden operation (for example: the server is not allowed to renew the device's bootstrap certificate).
    CE_STATUS_ITEM_IS_EMPTY,                  //!< The item was found in the storage but its length is zero.
    CE_STATUS_NOT_INITIALIZED,                //!< Called CertificateEnrollmentClient API before the initialization of the module.
    CE_STATUS_INIT_FAILED,                    //!< Initialization of the Certificate Enrollment module has failed. This error may be passed into MbedCloudClient::error callback.
    CE_STATUS_PENDING = 0x5ff,                //!< Operation will be complete asynchronously.
    CE_MAX_STATUS = CE_STATUS_RANGE_END
} pt_ce_status_e;

/**
 * \file pt-client-2/pt_certificate_api.h
 * \brief API for subscribing certificate renewal notications and renewing certificates.
 *
 * To be able to renew a certificate:
 *   1. The certificate renewal notification handler needs to be set correctly using `pt_client_create`.
 *   2. The certificate needs to be added (`pt_certificate_list_add`) to certificate list that was created using
 *      `pt_certificate_list_create`.
 *   3. The certification list needs to be send to Edge using `pt_certificate_renewal_list_set`.
 *   4. The `pt_certificate_renew` must be called for the certificates that were added to the list.
 *
 * After setting notification callback and subscribing to certificate renewals, the client must also be prepared to
 * receive certificate renewal notification callback also for cloud initiated certificate renewal.
 */

/**
 * \brief Structures for subscribing to certificate renew notifications.
 */
struct pt_certificate_list;
typedef struct pt_certificate_list pt_certificate_list_t;

/**
 * The structure describing a certificate within a certificate chain from EST enrollment.
 * \param cert_length, The length of the certificate.
 * \param cert, A buffer containing the certificate.
 * \param next, A pointer to the next certificate in chain, NULL if last certificate.
 */
struct cert_context_s {
    uint16_t cert_length;
    uint8_t *cert;
    struct cert_context_s *next;
};

/**
 * The structure describing a certificate chain from EST enrollment.
 * \param chain_length, The number of certificates in the certificate chain.
 * \param certs, A pointer to the first certificate in chain.
 */
struct cert_chain_context_s {
    uint8_t chain_length;
    struct cert_context_s *certs;
};

/**
 * \brief Type definition for certificate renewal notification.
 *        This callback will be called to notify the status when a certificate renewal completes.
 * \param connection_id ID of the protocol translator connection.
 * \param name The name of the certificate.
 * \param initiator 0 - device initiated the renewal \n
 *                  1 - cloud initiated the renewal
 * \param status Status of the certificate renewal.
 *               0 - for success. \n
 *               Non-zero if error happened. See error codes in `pt_ce_status_e` enum.
 * \param description Description of the status in string form for human readability.
 * \param userdata. The Userdata which was passed to `pt_client_start`.
 */
typedef void (*pt_certificate_renewal_notification_handler)(const connection_id_t connection_id,
                                                            const char *name,
                                                            int32_t initiator,
                                                            int32_t status,
                                                            const char *description,
                                                            void *userdata);

/**
 * \brief Type definition for certificate renewal notification for device certificate.
 *        This callback will be called to notify the status when a certificate renewal completes for
 *        device certificate.
 * \param connection_id ID of the protocol translator connection.
 * \param device_id The device ID.
 * \param name The name of the certificate.
 * \param status Status of the certificate renewal.
 *               0 - for success. \n
 *               Non-zero if error happened. See error codes in `pt_ce_status_e` enum.
 * \param cert_chain Structure containing the renewed certificate chain. This MUST be free'd using
 *        `pt_free_certificate_chain_context` function when callback is done with the data.
 * \param userdata. The Userdata which was passed to `pt_client_start`.
 */
typedef void (*pt_device_certificate_renew_response_handler)(const connection_id_t connection_id,
                                                             const char *device_id,
                                                             const char *name,
                                                             int32_t status,
                                                             struct cert_chain_context_s *cert_chain,
                                                             void *userdata);

/**
 * \brief Type definition for certificate renewal request handler for device certificate.
 *        This callback will be called when the cloud requests a device certificate to be
 *        renewed.
 * \param connection_id ID of the protocol translator connection.
 * \param device_id The device ID.
 * \param name The name of the certificate.
 * \param userdata. The Userdata which was passed to `pt_client_start`.
 *
 * \return The callback should return PT_STATUS_SUCCESS if the renewal process was started succesfully.
 *         If the renewal could not be started or there was some error, an error should be returned.
 *         See ::pt_status_t for possible error codes.
 */
typedef pt_status_t (*pt_device_certificate_renew_request_handler)(const connection_id_t connection_id,
                                                                   const char *device_id,
                                                                   const char *name,
                                                                   void *userdata);

/**
 * \brief Type definition for `pt_certificate_renewal_list_set` response success and failure handlers.
 * \param connection_id ID of the protocol translator connection.
 * \param userdata User data given in `pt_certificate_renewal_list_set`.
 */
typedef void (*pt_certificates_set_response_handler)(const connection_id_t connection_id, void *userdata);

/**
 * \brief Type definition for `pt_certificate_renew` response success and failure handlers.
 */
typedef void (*pt_certificate_renew_response_handler)(const connection_id_t connection_id, void *userdata);

/**
 * \brief Creates a certificate list.
 * \return New certificate list. Delete it with `pt_certificate_list_destroy`.
 */
pt_certificate_list_t *pt_certificate_list_create();

/**
 * \brief Destroys the certificate list.
 *        Frees all the certificates added to the list.
 */
void pt_certificate_list_destroy(pt_certificate_list_t *list);

/**
 * \brief Adds a certificate to certificate list.
 * \param list The certificate list. May not be NULL.
 * \param name The name of the certificate. May not be NULL.
 * \return PT_STATUS_SUCCESS if certificate was added successfully.\n
 *         Other error codes on failure.
 */
pt_status_t pt_certificate_list_add(pt_certificate_list_t *list, const char *name);

/**
 * \brief Sends the certificate list to Edge, triggering renewal subscriptions of the certificates in the list.
 * \param connection_id ID of the protocol translator connection.
 * \param list The certificate list. Must be valid and may not be NULL.
 * \param success_handler This function is called if certificate list was set successfully. May not be NULL.
 * \param failure_handler This function is called if setting the certificate list failed. May not be NULL.
 * \param userdata The user-supplied context.
 * \return PT_STATUS_SUCCESS if certificate setting request was successfully sent.\n
 *         Other error codes on failure.
 */
pt_status_t pt_certificate_renewal_list_set(const connection_id_t connection_id,
                                            pt_certificate_list_t *list,
                                            pt_certificates_set_response_handler success_handler,
                                            pt_certificates_set_response_handler failure_handler,
                                            void *userdata);

/**
 * \brief Requests the renewal of the certificate specified by the `name` parameter.
 * \param connection_id ID of the protocol translator connection.
 * \param name The name of the certificate. May not be NULL.
 * \param success_handler This function is called if certificate renewal was successfully initiated. May not be NULL.
 * \param failure_handler This function is called if certificate renewal failed. May not be NULL.
 * \param userdata The user-supplied context.
 * \return PT_STATUS_SUCCESS if certificate renewal request was successfully sent.\n
 *         Other error codes on failure.
 */
pt_status_t pt_certificate_renew(const connection_id_t connection_id,
                                 const char *name,
                                 pt_certificate_renew_response_handler success_handler,
                                 pt_certificate_renew_response_handler failure_handler,
                                 void *userdata);

/**
 * \brief Requests the renewal of the certificate specified by the `name` parameter using the
 * certificate signing request specified by the `csr` parameter.
 * \param connection_id ID of the protocol translator connection.
 * \param device_id The device ID.
 * \param name The name of the certificate. May not be NULL.
 * \param csr The certificate signing request. May not be NULL.
 * \param csr_length Length of the certificate signing request.
 * \param success_handler This function is called if the certificate renewal was successful. May not be NULL.
 * \param failure_handler This function is called if the certificate renewal failed. May not be NULL.
 * \param userdata The user-supplied context.
 * \return PT_STATUS_SUCCESS if certificate renewal request was successfully sent.\n
 *         Other error codes on failure.
 */
pt_status_t pt_device_certificate_renew(const connection_id_t connection_id,
                                        const char *device_id,
                                        const char *name,
                                        const char *csr,
                                        const size_t csr_length,
                                        pt_device_certificate_renew_response_handler success_handler,
                                        pt_device_certificate_renew_response_handler failure_handler,
                                        void *userdata);

/**
 * \brief Finish device certificate renewal request.
 * \param connection_id ID of the protocol translator connection.
 * \param device_id The ID of device.
 * \param status The status of the certificate renewal process, CE_STATUS_SUCCESS for successful renewal,
 *        see `pt_ce_status_e` enum for possible error codes.
 * \return PT_STATUS_SUCCESS if certificate renewal was finished successfully.\n
 *         Other error codes on failure.
 */
pt_status_t pt_device_certificate_renew_request_finish(const connection_id_t connection_id,
                                                       const char *device_id,
                                                       const pt_ce_status_e status);

/**
 * \brief Free a cert_chain_context_s structure passed to the certificate renewal notification callback..
 * \param context Pointer to the cert_chain_context_s structure to free.
 */
void pt_free_certificate_chain_context(struct cert_chain_context_s *context);

/**
 * @}
 * Close EDGE_PT_API_V2 addtogroup
 */

#endif /* PT_CERTIFICATE_API_H_ */

