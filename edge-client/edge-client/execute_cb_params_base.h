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

#ifndef EXECUTE_CB_PARAMS_BASE_H
#define EXECUTE_CB_PARAMS_BASE_H

#include <stdint.h>

/**
 * \ingroup EXECUTE_CB_PARAMS_BASE Execute Callback Parameters Base Class.
 * @{
 */

/**
 * \file execute_cb_params_base.h
 * \brief Definition of the ExecuteCallbackParamsBase class (internal)
 *
 * Edge Client creates an instance of ExecuteCallbackParamsBase class for resources that have OPERATION_EXECUTE set
 * for allowed operations.
 * The execute method of this class implements what will be done when the execute operation is requested from the
 * Device Management for a resource.
 *
 */
class ExecuteCallbackParamsBase
{
  public:
    /**
     * \brief Destructor for the ExecuteCallbackParamsBase class.
     *        The body of this method may be inherited to free allocated resources.
     */
    virtual ~ExecuteCallbackParamsBase()
    {
    }

    /**
     * \brief Called when execute operation is requested from Device Management.
     * \param params The M2MResource::M2MExecuteParameter parameters for the execute operation.
     */
    virtual void execute(void *params) = 0;
};

/**
 * @}
 * Close EXECUTE_CB_PARAMS_BASE Doxygen group definition
 */

#endif
