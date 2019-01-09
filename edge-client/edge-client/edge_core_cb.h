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

#ifndef EDGE_CORE_CB_H
#define EDGE_CORE_CB_H

#include <stdint.h>
#include "edge-client/edge_client.h"
#include "m2mresource.h"
#include "edge-client/execute_cb_params_base.h"

/**
 * \ingroup EDGE_CORE_CB_PARAMS Edge Core Callback Parameters.
 * @{
 */

/**
 * \file edge_core_cb.h
 * \brief Definition of the EdgeCoreCallbackParams class (internal)
 */

/**
 * \brief Called when a resource execute request is received from Device Management.
 * \param request_ctx State and parameters relating to this execute request.
 */
void edgeserver_execute_resource(edgeclient_request_context_t *request_ctx);

/**
 * \brief Edge Client creates an instance of EdgeCoreCallbackParams class for Edge Core resources that have
 *        OPERATION_EXECUTE set for allowed operations.
 *
 */
class EdgeCoreCallbackParams : public ExecuteCallbackParamsBase
{
public:
    /**
     * \brief Constructor for the EdgeCoreCallbackParams class.
     */
    EdgeCoreCallbackParams();

    /**
     * \brief Used to store the URI of the resources with OPERATION_EXECUTE set.
     *        This URI will be used in the execute method.
     */
    bool set_uri(uint16_t object_id, uint16_t object_instance_id, uint16_t resource_id);

    /**
     * \brief destructor for the EdgeCoreCallbackParams class.
     *        It frees the allocated resources.
     */
    ~EdgeCoreCallbackParams();

    /**
     * \brief Called when execute operation is requested from Device Management.
     * \param params The M2MResource::M2MExecuteParameter parameters for the execute operation.
     */ void
    execute(void *params);

private:
    char *uri;
};

/**
 * @}
 * Close EDGE_CORE_CB_PARAMS Doxygen group definition
 */

#endif
