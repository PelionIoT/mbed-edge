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

#ifndef GATEWAY_RESOURCE_H
#define GATEWAY_RESOURCE_H

#include "m2mresourcebase.h"
#include <stdlib.h>

/**
 * \ingroup GATEWAY_RESOURCE Gateway resource API
 * @{
 */

/**
 * \file gateway_resource.h
 * \brief Definition Gateway Resource Edge internal API (internal).
 */


/**
 * \brief This function is called when a write operation for gateway resource is received from Device Management.
 * \param connection The connection pointer which is stored to the resource object.
 * \param resource_base Pointer to the resource.
 * \param value The incoming value.
 * \param value_length The length of the incoming value.
 * \param token The asynchronous request token.
 * \param token_length length The length of the token.
 * \param[out] rc_status Returned status value for request context allocation.
 */
bool edgeclient_grm_set_handler(const M2MResourceBase *resource_base,
                                           void *connection,
                                           uint8_t *value,
                                           const uint32_t value_length,
                                           uint8_t *token,
                                           uint8_t token_len,
                                           edge_rc_status_e *rc_status);

/**
 * \brief This function is called when an execute operation for gateway resource is received from Device Management.
 * \param connection The connection pointer which is stored to the resource object.
 * \param resource_base Pointer to the resource.
 * \param value The incoming value.
 * \param value_length The length of the incoming value.
 * \param token The asynchronous request token.
 * \param token_length length The length of the token.
 * \param[out] rc_status Returned status value for request context allocation.
 */
bool edgeclient_grm_execute_handler(const M2MResourceBase *resource_base,
                                               void *endpoint_context,
                                               uint8_t *value,
                                               const uint32_t value_length,
                                               uint8_t *token,
                                               uint8_t token_len,
                                               edge_rc_status_e *rc_status);

/**
 * @}
 * Close GATEWAY_RESOURCE Doxygen group definition
 */
#endif
