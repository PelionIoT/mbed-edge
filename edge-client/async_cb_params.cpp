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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#define TRACE_GROUP "execcbparams"

extern "C" {
#include <stdint.h>
#include "common/integer_length.h"
#include <stdio.h>
#include <stdlib.h>
#include "mbed-trace/mbed_trace.h"
#include <common/test_support.h>
#include <assert.h>
}
#include "edge-client/edge_client.h"
#include "m2mresource.h"
#include "edge-client/async_cb_params.h"
#include "edge-client/edge_client_cpp.h"

AsyncCallbackParams::AsyncCallbackParams(void *endpoint_context) : ctx(endpoint_context)
{
    tr_debug("Create AsyncCallbackParams %p", this);
    uri = NULL;
}

bool AsyncCallbackParams::set_uri(const char *device_name,
                                  uint16_t object_id,
                                  uint16_t object_instance_id,
                                  uint16_t resource_id)
{
    if (uri) {
        // CppCheck finding, this might leak memory. Could free() but it was
        // decided to go with log & assert route instead
        tr_error("\"Not supposed to happen\"-branch of code just happened");
        assert(0);
    }
    if (-1 == asprintf(&uri, "d/%s/%d/%d/%d", device_name, object_id, object_instance_id, resource_id)) {
        tr_error("AsyncCallbackParams could not allocate uri");
        return false;
    }
    return true;
}

AsyncCallbackParams::~AsyncCallbackParams()
{
    if (uri)
        free(uri);
}

bool AsyncCallbackParams::async_request(M2MResource *resource,
                                        M2MBase::Operation operation,
                                        uint8_t *buffer,
                                        size_t length,
                                        uint8_t *token,
                                        uint8_t token_len,
                                        edge_rc_status_e *rc_status)
{
    if (!uri) {
        tr_err("Cannot execute on NULL uri");
        return false;
    }

    if (operation == M2MBase::POST_ALLOWED) {
        return edgeclient_endpoint_value_execute_handler(resource,
                                                         ctx,
                                                         (uint8_t *) buffer,
                                                         length,
                                                         token,
                                                         token_len,
                                                         rc_status);
    } else if (operation == M2MBase::PUT_ALLOWED) {
        return edgeclient_endpoint_value_set_handler(resource,
                                                     ctx,
                                                     (uint8_t *) buffer,
                                                     length,
                                                     token,
                                                     token_len,
                                                     rc_status);
    } else {
        tr_err("Unexpected operation in async_request %d", operation);
    }
    return false;
}
