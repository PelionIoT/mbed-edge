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
#include "edge-client/execute_cb_params.h"

EDGE_LOCAL void edgeclient_execute_success(edgeclient_request_context_t *ctx)
{
    tr_info("Execute successful to protocol translator for path 'd/%s/%d/%d/%d'.",
            ctx->device_id, ctx->object_id, ctx->object_instance_id,
            ctx->resource_id);
    edgeclient_deallocate_request_context(ctx);
}

EDGE_LOCAL void edgeclient_execute_failure(edgeclient_request_context_t *ctx)
{
    tr_info("Execute failed to protocol translator for path 'd/%s/%d/%d/%d'.",
            ctx->device_id, ctx->object_id, ctx->object_instance_id,
            ctx->resource_id);
    edgeclient_deallocate_request_context(ctx);
}

ExecuteCallbackParams::ExecuteCallbackParams(void *endpoint_context) : ctx(endpoint_context)
{
    tr_debug("Create ExecuteCallbackParams %p", this);
    uri = NULL;
}

bool ExecuteCallbackParams::set_uri(const char *device_name, uint16_t object_id,
                          uint16_t object_instance_id, uint16_t resource_id)
{
    if (uri) {
        // CppCheck finding, this might leak memory. Could free() but it was 
        // decided to go with log & assert route instead
        tr_error("\"Not supposed to happen\"-branch of code just happened");
        assert(0);
    }

    uri = (char *) calloc(2 + strlen(device_name) + 1 + edge_int_length(object_id) + 1 +
                                  edge_int_length(object_instance_id) + 1 + edge_int_length(resource_id) + 1,
                          1);
    if (!uri) {
        tr_error("ExecuteCallbackParams could not allocate uri");
        return false;
    }
    else {
        sprintf(uri, "d/%s/%d/%d/%d", device_name, object_id, object_instance_id, resource_id);
    }
    return true;
}

ExecuteCallbackParams::~ExecuteCallbackParams()
{
    if (uri)
        free(uri);
}

void ExecuteCallbackParams::execute(void *params)
{
    if (!uri) {
        tr_err("Cannot execute on NULL uri");
        return;
    }

    M2MResource::M2MExecuteParameter* parameters = static_cast<M2MResource::M2MExecuteParameter*>(params);

    const uint8_t* buffer = parameters->get_argument_value();
    uint16_t length = parameters->get_argument_value_length();
    uint8_t *copy_buffer = (uint8_t *) malloc(length);
    memcpy(copy_buffer, buffer, length);

    tr_info("resource executed: url=%s, data length=%d", uri, length);

    edgeclient_request_context_t *request_ctx = edgeclient_allocate_request_context(uri,
                                                                                    copy_buffer,
                                                                                    length,
                                                                                    EDGECLIENT_VALUE_IN_BINARY,
                                                                                    OPERATION_EXECUTE,
                                                                                    LWM2M_OPAQUE,
                                                                                    edgeclient_execute_success,
                                                                                    edgeclient_execute_failure,
                                                                                    ctx);

    if (request_ctx) {
        edgeclient_write_to_pt_cb(request_ctx, ctx);
    } else {
        tr_err("Could not write execution to protocol translator.");
    }
}
