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

#ifndef PROTOCOL_CRYPTO_API_H
#define PROTOCOL_CRYPTO_API_H

#include "jsonrpc/jsonrpc.h"
#include "common/pt_api_error_codes.h"
#include "edge-core/server.h"

/**
 * \ingroup EDGE_SERVER RPC API for crypto operations.
 * @{
 */

/** \file protocol_crypto_api.h
 * \brief Edge RPC API for crypto operations
 *
 * Definition of the Edge RPC API for crypto operations.
 *
 * RPC API provides functions to:
 * - get a certificate from edge crypto service.
 */

/**
 * \brief Initialize the crypto API protocol.
 */
void crypto_api_protocol_init();

/**
 * \brief Destroy the crypto API protocol.
 */
void crypto_api_protocol_destroy();

/**
 * \brief Retrieve a certificate from the Edge crypto service.
 *
 * \param request The jsonrpc request.
 * \param json_params The parameter portion of the jsonrpc request.
 * \param result The jsonrpc result object to fill.
 * \param userdata The user-supplied context data pointer.
 * \return 0 if the certificate retrieval succeeded.\n
 *         1 if an error occurred. Details are in the result parameter.
 *         -1 if the response will be provided later.
 */
int crypto_api_get_certificate(json_t *request, json_t *json_params, json_t **result, void *userdata);

/**
 * \brief Retrieve a public key from the Edge crypto service.
 *
 * \param request The jsonrpc request.
 * \param json_params The parameter portion of the jsonrpc request.
 * \param result The jsonrpc result object to fill.
 * \param userdata The user-supplied context data pointer.
 * \return 0 if the certificate retrieval succeeded.\n
 *         1 if an error occurred. Details are in the result parameter.
 *         -1 if the response will be provided later.
 */
int crypto_api_get_public_key(json_t *request, json_t *json_params, json_t **result, void *userdata);

/**
 * @}
 * Close EDGE_SERVER Doxygen group definition
 */

#endif /* PROTOCOL_CRYPTO_API_H */
