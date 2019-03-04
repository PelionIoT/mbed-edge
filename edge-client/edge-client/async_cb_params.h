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

#ifndef ASYNC_CB_PARAMS_H
#define ASYNC_CB_PARAMS_H

/**
 * \ingroup ASYNC_CB_PARAMS Async Callback Parameters Base Class.
 * @{
 */

/**
 * \file async_cb_params.h
 * \brief Definition of the AsyncCallbackParams class (internal)
 */

#include <stdint.h>
#include "edge-client/async_cb_params_base.h"

/**
 * \brief Edge Client creates an instance of AsyncCallbackParams class for endpoint resources that have
 *        OPERATION_WRITE or OPERATION_EXECUTE set for allowed operations.
 *
 */
class AsyncCallbackParams : public AsyncCallbackParamsBase
{
public:
    /**
     * \brief Constructor for the AsyncCallbackParams class.
     * \param endpoint_context pointer to context data for the endpoint.
     */
    AsyncCallbackParams(void *endpoint_context);

    /**
     * \brief destructor for the AsyncCallbackParams class.
     *        It frees the allocated resources.
     */
    ~AsyncCallbackParams();

    /**
     * \brief Used to store the URI of the resource with OPERATION_WRITE or OPERATION_EXECUTE set.
     *        This URI will be given to the client when the execute method is called.
     */
    bool set_uri(const char *device_name, uint16_t object_id, uint16_t object_instance_id, uint16_t resource_id);

    /**
     * \brief Called when a write or execute operation is requested from Device Management.
     * \param resource The resource for which this operation is applied.
     * \param operation The operation (write or execute).
     * \param buffer The asynchronous request buffer. Needs to be deallocated by Edge.
     * \param length The length or the size of the buffer.
     * \param token The asynchronous request token sent by the cloud client.
     *              This is an allocated memory and ownership is transferred.
     * \param token_length length The length of the token.
     * \param[out] rc_status Returned status value for request context allocation.
     * \return true if the request was successfully handled
     *         false if the request could not be handled
     */
    bool async_request(M2MResource *resource,
                       M2MBase::Operation operation,
                       uint8_t *buffer,
                       size_t length,
                       uint8_t *token,
                       uint8_t token_len,
                       edge_rc_status_e *rc_status);

private:
    char *uri;
    void *ctx;
};

/**
 * @}
 * Close ASYNC_CB_PARAMS Doxygen group definition
 */

#endif
