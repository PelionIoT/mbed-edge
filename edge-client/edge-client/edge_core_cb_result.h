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

#ifndef EDGE_CORE_CB_RESULT_H
#define EDGE_CORE_CB_RESULT_H

#include "edge-client/edge_client.h"

/**
 * \ingroup EDGE_CORE_CB_RESULT Edge Core Callback Result API
 * @{
 */

/**
 * \file edge_core_cb_result.h
 * \brief Definition of the Edge Core Callback Result API (internal).
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Called when the asynchronous request succeeded.
 *        This currently only traces information about the request.
 * \param ctx Data and state relating to the execute request.
 */
void edgecore_async_cb_success(edgeclient_request_context_t *ctx);

/**
 * \brief Called when the asynchronous request failed.
 *        This currently only traces information about the request.
 * \param ctx Data and state relating to the execute request.
 */
void edgecore_async_cb_failure(edgeclient_request_context_t *ctx);

#ifdef __cplusplus
}
#endif

/**
 * @}
 * Close EDGE_CORE_CB_RESULT Doxygen group definition
 */

#endif
