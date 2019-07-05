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
#include "edge-core/server.h"
#include "est_defs.h"
#include "certificate-enrollment-client/ce_status.h"
#include "certificate-enrollment-client/ce_defs.h"

/**
 * \ingroup EDGE_SERVER Edge functionality and RPC API.
 * @{
 */

/** \file protocol_api.h
 * \brief Edge RPC API
 *
 * Definition of the Edge RPC API.
 *
 * RPC API provides functions to:
 * - register and unregister the protocol translator.
 * - register and unregister endpoint devices.
 * - update the endpoint device state.
 * - write the endpoint device value changes.
 */

/**
 * \brief Initialize Edge RPC API.
 */
void init_protocol();

/**
 * \brief Register the protocol translator to Edge.
 *
 * \param request The jsonrpc request.
 * \param json_params The parameter portion of the jsonrpc request.
 * \param result The jsonrpc result object to fill.
 * \param userdata The user-supplied context data pointer.
 * \return 0 if the protocol translator registration succeeded.\n
 *         1 if an error occurred. Details are in the result parameter.
 */
int protocol_translator_register(json_t *request, json_t *json_params, json_t **result, void *userdata);

/**
 * \brief Register an endpoint device to Edge.
 *
 * \param request The jsonrpc request.
 * \param json_params The parameter portion of the jsonrpc request.
 * \param result The jsonrpc result object to fill.
 * \param userdata The user-supplied context data pointer.
 * \return 0 if the device registration succeeded.\n
 *         1 if an error occurred. Details are in the result parameter.
 */
int device_register(json_t *request, json_t *json_params, json_t **result, void *userdata);

/**
 * \brief Unregister an endpoint device from Edge.
 *
 * \param request The jsonrpc request.
 * \param json_params The parameter portion of the jsonrpc request.
 * \param result The jsonrpc result object to fill.
 * \param userdata The user-supplied context data pointer.
 * \return 0 if the device unregistration succeeded.\n
 *         1 if an error occurred.\n
 *         Details are in the result parameter of the function call.
 */
int device_unregister(json_t *request, json_t *json_params, json_t **result, void *userdata);

/**
 * \brief Write endpoint device values.
 *
 * \param request The jsonrpc request.
 * \param json_params The parameter portion of the jsonrpc request.
 * \param result The jsonrpc result object to fill.
 * \param userdata The user-supplied context data pointer.
 * \return 0 if the write value succeeded.\n
 *         1 if an error occurred. Details are in the result parameter.
 */
int write_value(json_t *request, json_t *json_params, json_t **result, void *userdata);

/**
 * \brief Set list of certificates to receive renewal status updates for.
 *
 * \param request The jsonrpc request.
 * \param json_params The parameter portion of the jsonrpc request.
 * \param result The jsonrpc result object to fill.
 * \param userdata The user-supplied context data pointer.
 * \return 0 if setting the list succeeded.\n
 *         1 if an error occurred. Details are in the result parameter.
 */
int certificate_renewal_list_set(json_t *request, json_t *json_params, json_t **result, void *userdata);

/**
 * \brief Initiate certificate renewal operation for a certificate.
 *
 * \param request The jsonrpc request.
 * \param json_params The parameter portion of the jsonrpc request.
 * \param result The jsonrpc result object to fill.
 * \param userdata The user-supplied context data pointer.
 * \return 0 if the renewal operation started successfully.\n
 *         1 if an error occurred. Details are in the result parameter.
 */
int renew_certificate(json_t *request, json_t *json_params, json_t **result, void *userdata);

/**
 * \brief Requests an EST enrollment for a certificate.
 *
 * \param request The jsonrpc request.
 * \param json_params The parameter portion of the jsonrpc request.
 * \param result The jsonrpc result object to fill.
 * \return 0 if the EST enrollment operation started successfully.\n
 *         1 if an error occurred. Details are in the result parameter.
 */
int est_request_enrollment(json_t *request, json_t *json_params, json_t **result, void *userdata);

/**
 * \brief The edgeclient request context data.
 */
typedef struct edgeclient_request_context edgeclient_request_context_t;


/**
 * \brief Writes the updated values to the protocol translator.
 *
 * \param ctx The user-supplied write context.
 * \param userdata The user-supplied data.
 * \return 0 if values were written successfully.\n
 *         1 if the values couldn't be written.
 */
int write_to_pt(edgeclient_request_context_t *ctx, void *userdata);

/**
 * \brief Writes the certificate renewal status to the protocol translator.
 *
 * \param certificate_name Name of certificate whose renewal process finished.
 * \param status Status of the finished renewal process.
 * \param initiator Initiator of the renewal process.\n
 *                  0 for PT initiated renew
 *                  1 for cloud initiated renew
 * \param ctx Context pointer passed from server when initializing the client.
 * \return 0 if status was written successfully.\n
 *         1 if the status couldn't be written.
 */
int certificate_renewal_notifier(const char *certificate_name, ce_status_e status, ce_initiator_e initiator, void *ctx);

/**
 * \brief Sends the EST enrollment result to the protocol translator.
 *
 * \param result Result of the finished EST enrollment process.
 * \param cert_chain Structure containing the enrolled certificate or certificates.
 * \param ctx Context pointer passed from server when initializing the client.
 * \return 0 if status was written successfully.\n
 *         1 if the status couldn't be written.
 */
int est_enrollment_result_notifier(est_enrollment_result_e result, struct cert_chain_context_s *cert_chain, void *ctx);

/**
 * @}
 * Close EDGE_SERVER Doxygen group definition
 */

#endif /* PROTOCOL_API_H */
