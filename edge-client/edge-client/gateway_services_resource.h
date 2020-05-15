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

#ifndef GATEWAY_SERVICES_RESOURCE_H
#define GATEWAY_SERVICES_RESOURCE_H

#include "edge-client/edge_client.h"
#include "edge-core/edge_servicemgmt_object.h"
#include <event2/event.h>
#include <pthread.h>

/**
 * \ingroup GATEWAY_SERVICES_RESOURCE Gateway services API
 * @{
 */

/**
 * \file gateway_services_resource.h
 * \brief Definition Gateway Services Resource Edge internal API (internal).
 */

/**
 * \brief Adds the Gateway Services resource.
 */
void gsr_add_gateway_services_resource();

/**
 * \brief Called when gateway service resource update request comes from Device Management.
 * \param request_ctx Data and state information about the gateway service resource request.
 * \see edgeclient_request_context_t
 */

void gsr_resource_requested(edgeclient_request_context_t *request_ctx);

/**
 * @}
 * Close GATEWAY_SERVICES_RESOURCE Doxygen group definition
 */
#endif
