/*
 * ----------------------------------------------------------------------------
 * Copyright 2020 ARM Ltd.
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

#ifndef GRM_API_INTERNAL_H
#define GRM_API_INTERNAL_H

#include "edge-rpc/rpc.h"
#include "client_type.h"
#include "edge-core/server.h"

/**
 * \ingroup EDGE_SERVER Edge functionality and RPC API.
 * @{
 */

/** \file grm_api_internal.h
 * \brief Edge RPC API
 *
 * Definition of the Edge RPC API.
 *
 * RPC API provides functions to:
 * - register the gateway resource manager.
 * - add gateway resources.
 * - update the resource states/values.
 * - write the resource changes to gateway resource manager.
 */

/**
 * \brief The edgeclient request context data.
 */
typedef struct edgeclient_request_context edgeclient_request_context_t;

/**
 * \brief The gateway resource manager api method table.
 */
extern struct jsonrpc_method_entry_t grm_method_table[];

/**
 * \brief Register the gateway resource manager to Edge.
 *
 * \param request The jsonrpc request.
 * \param json_params The parameter portion of the jsonrpc request.
 * \param result The jsonrpc result object to fill.
 * \param userdata The user-supplied context data pointer.
 * \return 0 if the gateway resource manager registration succeeded.\n
 *         1 if an error occurred. Details are in the result parameter.
 */
int gw_resource_manager_register(json_t *request, json_t *json_params, json_t **result, void *userdata);

/**
 * \brief Register an endpoint device to Edge.
 *
 * \param request The jsonrpc request.
 * \param json_params The parameter portion of the jsonrpc request.
 * \param result The jsonrpc result object to fill.
 * \param userdata The user-supplied context data pointer.
 * \return 0 if the resource registration succeeded.\n
 *         1 if an error occurred. Details are in the result parameter.
 */
int add_resource(json_t *request, json_t *json_params, json_t **result, void *userdata);

/**
 * \brief Write gateway resource values.
 *
 * \param request The jsonrpc request.
 * \param json_params The parameter portion of the jsonrpc request.
 * \param result The jsonrpc result object to fill.
 * \param userdata The user-supplied context data pointer.
 * \return 0 if the write value succeeded.\n
 *         1 if an error occurred. Details are in the result parameter.
 */
int write_resource_value(json_t *request, json_t *json_params, json_t **result, void *userdata);

/**
 * \brief Writes the updated values to the gateway resource manager.
 *
 * \param ctx The user-supplied write context.
 * \return 0 if values were written successfully.\n
 *         1 if the values couldn't be written.
 */
int write_to_grm(edgeclient_request_context_t *request_ctx);

/**
 * @}
 * Close EDGE_SERVER Doxygen group definition
 */

#endif // GRM_API_INTERNAL_H
