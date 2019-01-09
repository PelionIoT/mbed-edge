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

#ifndef EDGE_SERVER_CUSTOMER_CODE_H

#include "edge-client/edge_client.h"

/**
 * \defgroup EDGE_SERVER_CUSTOMER_CODE Edge Server Customer Code
 * \ingroup EDGE_SERVER_CUSTOMER_CODE
 * @{
 */

/** \file edge_server_customer_code.h
 * \brief Edge server customer code
 *
 * This file contains hooks for a customer implementation. For example, when factory reset is called from Device Management,
 * `edgeserver_execute_rfs_customer_code` is called.\n
 * The customers may implement their own implementation for reset factory settings.\n
 * This function should always return within a reasonable time, ideally within a few seconds.\n
 * If the settings are reset successfully the Edge server will gracefully shutdown to be restarted.
 */

/**
 * \brief Called when reset factory settings is requested from Cloud.
 *
 * \param request_ctx Information about this request.
 * \return True if reset factory settings was successful.\n
 *         False if reset failed.
 */
bool edgeserver_execute_rfs_customer_code(edgeclient_request_context_t *request_ctx);

/**
 * @}
 * Close EDGE_SERVER_CUSTOMER_CODE Doxygen group definition
 */

#endif
