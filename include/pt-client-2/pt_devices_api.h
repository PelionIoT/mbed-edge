/*
 * ----------------------------------------------------------------------------
 * Copyright 2018 ARM Ltd.
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

#ifndef PT_DEVICES_API_H
#define PT_DEVICES_API_H

#include "pt-client-2/pt_common_api.h"

/**
 * \addtogroup EDGE_PT_API_V2
 * @{
 */

/**
 * \file pt-client-2/pt_devices_api.h
 * \brief Contains the interface to manage multiple devices.
 */

/**
 * \brief A function prototype for calling the client code when devices operation (for example: write, register or
 * unregister) is done.
 *
 * The callbacks are run on the same thread as the event loop of the protocol translator client.
 * If the related functionality of the callback is running a long process, you need to move it to a worker thread.
 * If the process runs directly in the callback, it blocks the event loop, and thus the whole protocol translator.
 *
 * \param[in] connection_id The connection ID of the protocol translator client connection.
 * \param[in] userdata The user supplied data to pass back when the handler is called.
 */
typedef void (*pt_devices_cb)(connection_id_t connection_id, void *userdata);

/**
 * \brief registers the devices that haven't been registered yet.
 *
 * The callback is run on the same thread as the event loop of the protocol translator client.
 * If the related functionality of the callback does some long processing the processing
 * must be moved to worker thread. If the processing is run directly in the callback it
 * will block the event loop and therefore it will block the whole protocol translator.
 *
 * \param[in] connection_id The connection ID of the protocol translator client connection.
 * \param[in] devices_registration_success The function to call if all the devices registered successfully.
 * \param[in] devices_registration_failure The function to call if some of the devices couldn't be registered.
 * \param[in] userdata Pointer to user's data. This will be passed back in the callback functions.
 * \return PT_STATUS_SUCCESS in case there is no error. Other error codes when it fails.
 *         See ::pt_status_t for possible error codes.
 */
pt_status_t pt_devices_register_devices(const connection_id_t connection_id,
                                        pt_devices_cb devices_registration_success,
                                        pt_devices_cb devices_registration_failure,
                                        void *userdata);

/**
 * \brief Unregisters all the registered devices.
 *
 * The callback is run on the same thread as the event loop of the protocol translator client.
 * If the related functionality of the callback does some long processing the processing
 * must be moved to worker thread. If the processing is run directly in the callback it
 * will block the event loop and therefore it will block the whole protocol translator.
 *
 * If unregistration succeeds, it deletes the device instances from memory. If unregistration fails
 * the device instances remain in memory to allow retrying to unregister the devices.
 *
 * \param[in] connection_id The connection ID of the protocol translator client connection.
 * \param[in] devices_unregistration_success The function to call if all the devices unregistered successfully.
 * \param[in] devices_unregistration_failure The function to call if some of the devices couldn't be unregistered.
 * \param[in] userdata Pointer to user's data. This will be passed back in the callback functions.
 * \return PT_STATUS_SUCCESS in case there is no error. Other error codes when it fails.
 *         See ::pt_status_t for possible error codes.
 */
pt_status_t pt_devices_unregister_devices(const connection_id_t connection_id,
                                          pt_devices_cb devices_unregistration_success,
                                          pt_devices_cb devices_unregistration_failure,
                                          void *userdata);

/**
 * \brief Updates the changed object structure from the endpoint device to Edge Core.
 *
 * The callback is run on the same thread as the event loop of the protocol translator client.
 * If the related functionality of the callback does some long processing the processing
 * must be moved to worker thread. If the processing is run directly in the callback it
 * will block the event loop and therefore it will block the whole protocol translator.
 *
 * \param[in] connection_id The connection ID.
 * \param[in] success_handler A function pointer to be called when the object structure was updated successfully.
 * \param[in] failure_handler A function pointer to be called when the the object structure update failed.
 * \param[in] userdata The user-supplied context given as an argument to the success and failure handler
 *                     functions.
 * \return The status of the write value operation.\n
 *         `PT_STATUS_SUCCESS` on successful write.\n
 *         See ::pt_status_t for possible error codes.
 */
pt_status_t pt_devices_update(const connection_id_t connection_id,
                              pt_devices_cb success_handler,
                              pt_devices_cb failure_handler,
                              void *userdata);

/**
 * @}
 * Close EDGE_PT_API_V2 addtogroup
 */

#endif
