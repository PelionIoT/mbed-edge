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

#ifndef EXECUTE_CB_PARAMS_H
#define EXECUTE_CB_PARAMS_H

/**
 * \ingroup EXECUTE_CB_PARAMS Execute Callback Parameters Base Class.
 * @{
 */

/**
 * \file execute_cb_params.h
 * \brief Definition of the ExecuteCallbackParams class (internal)
 */

#include <stdint.h>
#include "edge-client/execute_cb_params_base.h"

/**
 * \brief Edge Client creates an instance of ExecuteCallbackParams class for endpoint resources that have
 *        OPERATION_EXECUTE set for allowed operations.
 *
 */
class ExecuteCallbackParams : public ExecuteCallbackParamsBase
{
public:
    /**
     * \brief Constructor for the ExecuteCallbackParams class.
     * \param endpoint_context pointer to context data for the endpoint.
     */
    ExecuteCallbackParams(void *endpoint_context);

    /**
     * \brief destructor for the ExecuteCallbackParams class.
     *        It frees the allocated resources.
     */
    ~ExecuteCallbackParams();

    /**
     * \brief Used to store the URI of the resources with OPERATION_EXECUTE set.
     *        This URI will be given to the client when the execute method is called.
     */
    bool set_uri(const char *device_name, uint16_t object_id, uint16_t object_instance_id, uint16_t resource_id);

    /**
     * \brief Called when execute operation is requested from Device Management.
     * \param params The M2MResource::M2MExecuteParameter parameters for the execute operation.
     */
    void execute(void *params);

private:
    char *uri;
    void *ctx;
};

/**
 * @}
 * Close EXECUTE_CB_PARAMS Doxygen group definition
 */

#endif
