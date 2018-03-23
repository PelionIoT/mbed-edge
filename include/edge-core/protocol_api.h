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

#ifndef PROTOCOL_API_H
#define PROTOCOL_API_H

#include "jsonrpc/jsonrpc.h"
#include "common/pt_api_error_codes.h"

/**
 * \ingroup EDGE_SERVER Mbed Edge functionality and RPC API.
 * @{
 */

/** \file protocol_api.h
 * \brief Mbed Edge RPC API
 *
 * Definition of Mbed Edge RPC API.
 *
 * RPC API provides functions to:
 * * register and unregister the protocol translator.
 * * register and unregister endpoint devices.
 * * update the endpoint device state.
 * * write the endpoint device value changes.
 */

/**
 * \brief Initialize Mbed Edge RPC API.
 */
void init_protocol();

/**
 * \brief Register the protocol translator to Mbed Edge.
 * \param json_params The parameter portion of the jsonrpc request.
 * \param result The jsonrpc result object to fill.
 * \param userdata The user-supplied context data pointer.
 * \return 0 - Protocol translator registration succeeded
 *         1 - Some error occurred. Details are in the result parameter.
 *
 */
int protocol_translator_register(json_t *json_params, json_t **result, void *userdata);

/**
 * \brief Register an endpoint device to Mbed Edge.
 * \param json_params The parameter portion of the jsonrpc request.
 * \param result The jsonrpc result object to fill.
 * \param userdata The user-supplied context data pointer.
 * \return 0 - Device registration succeeded.
 *         1 - Some error occurred. Details are in the result parameter.
 */
int device_register(json_t *json_params, json_t **result, void *userdata);

/**
 * \brief Unregister an endpoint device from Mbed Edge.
 * \param json_params The parameter portion of the jsonrpc request.
 * \param result The jsonrpc result object to fill.
 * \param userdata The user-supplied context data pointer.
 * \return 0 - Device unregistration succeeded.
 *         1 - Some error occurred. Details are in the result parameter.
 */
int device_unregister(json_t *json_params, json_t **result, void *userdata);

/**
 * \brief Write endpoint device values.
 * \param json_params The parameter portion of the jsonrpc request.
 * \param result The jsonrpc result object to fill.
 * \param userdata The user-supplied context data pointer.
 * \return 0 - Write value succeeded.
 *         1 - Some error occurred. Details are in the result parameter.
 */
int write_value(json_t *json_params, json_t **result, void *userdata);

/**
 * \brief The edgeclient request context data.
 */
typedef struct edgeclient_request_context edgeclient_request_context_t;


/**
 * \brief Writes the updated values to protocol translator
 *
 * \param ctx The user supplied write context.
 * \param userdata The user supplied data.
 *
 * \return 0 if values were written successfully
 *         1 if the values couldn't be written.
 */
int write_to_pt(edgeclient_request_context_t *ctx, void *userdata);

/**
 * @}
 * Close EDGE_SERVER Doxygen group definition
 */

#endif /* PROTOCOL_API_H */
