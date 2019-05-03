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

#include "pt-client-2/pt_common_api.h"

/**
 * \addtogroup EDGE_PT_API_V2
 * @{
 */

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
 * \return PT_STATUS_SUCCESS if certificate renewal request was successfully sent.\n
 *         Other error codes on failure.
 */
pt_status_t pt_certificate_renew(const connection_id_t connection_id,
                                 const char *name,
                                 pt_certificate_renew_response_handler success_handler,
                                 pt_certificate_renew_response_handler failure_handler,
                                 void *userdata);

/**
 * @}
 * Close EDGE_PT_API_V2 addtogroup
 */

#endif /* PT_CERTIFICATE_API_H_ */

