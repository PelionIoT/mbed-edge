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

#ifndef PT_CLIENT_API_H
#define PT_CLIENT_API_H

#include "pt-client-2/pt_common_api.h"
#include "pt-client-2/pt_certificate_api.h"

/**
 * \addtogroup EDGE_PT_API_V2
 * @{
 */

/**
 * \file pt-client-2/pt_client_api.h
 * \brief Contains the interface to create, connect, register, unregister and shut down the protocol translator client.
 * Also contains call declaration of call-back which is called if client is disconnected.
 */

/**
 * \brief Use this function to initialize the PT API.
 *
 * This function should be called in the beginning in the PT API application's main thread and only once.
 * \return 0 if init succeeded
 *         1 in case of an error.
 */
int pt_api_init();

/**
 * \brief A function pointer type definition for callbacks given in the protocol translator API functions as an
 * argument. This function definition is used for providing success and failure callback handlers.
 *
 * The callbacks are run on the same thread as the event loop of the protocol translator client.
 * If the related functionality of the callback is running a long process, you need to move it to a worker thread.
 * If the process runs directly in the callback, it blocks the event loop, and thus the whole protocol translator.
 *
 * \param[in] userdata The user-supplied context given as an argument in the protocol translator
 * API functions.
 */
typedef void (*pt_response_handler)(void *userdata);

/**
 * \brief A function prototype for calling the client code when the connection is ready for passing messages
 *
 * \param[in] connection_id The ID of the connection which is ready.
 * \param[in] name The name of the protocol translator.
 * \param[in] userdata The user supplied data to pass back when the handler is called.
 *                     The `userdata` was given to `pt_client_start()`.
 */
typedef void (*pt_connection_ready_cb)(connection_id_t connection_id, const char *name, void *userdata);

/**
 * \brief A function prototype for calling the client code when the connection is disconnected.
 *
 * \param[in] connection_id The ID of the connection which disconnected.
 * \param[in] userdata The user supplied data to pass back the the handler is called.
 *                     The `userdata` was given to `pt_client_start()`.
 */
typedef void (*pt_disconnected_cb)(connection_id_t connection_id, void *userdata);

/**
 * \brief A function prototype for calling the client code when the connection is shutting down
 *
 * \param[in] connection_id The ID of the protocol translator client connection.
 * \param[in] userdata The user supplied data to pass back when the handler is called.
 *                     The `userdata` was given to `pt_client_start()`.
 */
typedef void (*pt_connection_shutdown_cb)(connection_id_t connection_id, void *userdata);

/**
 * \brief A structure to hold the callbacks of the protocol translator
 */
typedef struct protocol_translator_callbacks {
    pt_connection_ready_cb connection_ready_cb;
    pt_disconnected_cb disconnected_cb;
    pt_connection_shutdown_cb connection_shutdown_cb;
    pt_certificate_renewal_notification_handler certificate_renewal_notifier_cb;
    pt_device_certificate_renew_request_handler device_certificate_renew_request_cb;
} protocol_translator_callbacks_t;

/**
 * \brief Creates an instance of a PT API client.
 *
 * \param[in] socket_path The path to AF_UNIX domain socket to connect.
 * \param[in] pt_cbs A struct containing the callbacks to the customer side implementation.
 *
 * \return Protocol translator client instance.
 */
pt_client_t *pt_client_create(const char *socket_path,
                              const protocol_translator_callbacks_t *pt_cbs);

/**
 * \brief Frees the PT API client.
 *
 * \param[in] client The protocol translator client structure to free.
 */
void pt_client_free(pt_client_t *client);

/**
 * \brief May be used to get the connection ID from the client
 *
 * \param[in] client The client instance allocated using `pt_client_create()`.
 *
 * \return the id of the connection. PT_CONNECTION_ID_INVALID is returned if there is no active connection.
 */
connection_id_t pt_client_get_connection_id(pt_client_t *client);

/**
 * \brief Starts the protocol translator client event loop and tries to connect to a local instance
 * of Device Management Edge. When a connection is established, it tries to register the protocol translator.
 * When registering succeeds the `success_handler` will be called. If registering fails the `failure_handler` will be
 * called. This could happen for example, if the protocol translator name is already in use in Device Management Edge
 * instance.
 *
 * \param[in] client Client's data which can be created with `pt_client_create()`.
 * \param[in] success_handler A function pointer to be called when the protocol translator registration
 *                            is successful.
 * \param[in] failure_handler A function pointer to be called when the protocol translator registration
 *                            fails.
 * \param[in] name The protocol translator name, must be unique in the Device Management Edge instance.
 * \param[in] userdata The user-supplied context given as an argument to success and failure handler
 *                     functions.
 *
 * \return 1 if there is an error in configuring or starting the event loop.\n
 *         The function returns when the event loop is shut down and the return value is 0.
 */
int pt_client_start(pt_client_t *client,
                    pt_response_handler success_handler,
                    pt_response_handler failure_handler,
                    const char *name,
                    void *userdata);

/**
 * \brief Gracefully shuts down the protocol translator client.
 *
 * \param[in] client The client created using `pt_client_create()`.
 *
 * \return PT_STATUS_SUCCESS for successful initiation of the client shutdown.
 *         Other error codes for failure.
 */
pt_status_t pt_client_shutdown(pt_client_t *client);

/**
 * @}
 * Close EDGE_PT_API_V2 addtogroup
 */

#endif
