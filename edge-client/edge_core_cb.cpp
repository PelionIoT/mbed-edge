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

#define TRACE_GROUP "edgecorecb"
extern "C" {
#include <stdint.h>
#include "common/integer_length.h"
#include <stdio.h>
#include <stdlib.h>
#include <common/test_support.h>
#include "edge-core/edge_device_object.h"
#include "edge-client/reset_factory_settings.h"
}
#include "edge-client/edge_client.h"
#include "edge-client/request_context.h"
#include "m2mresource.h"
#include "mbed-trace/mbed_trace.h"
#include "edge-client/edge_core_cb.h"
#include "edge-client/edge_core_cb_result.h"

void edgeserver_execute_resource(edgeclient_request_context_t *request_ctx)
{
    tr_debug("edgeserver_execute_resource %d/%d/%d operation %d",
             request_ctx->object_id,
             request_ctx->object_instance_id,
             request_ctx->resource_id,
             request_ctx->operation);
    if (request_ctx->object_id == EDGE_DEVICE_OBJECT_ID && request_ctx->object_instance_id == 0 &&
        request_ctx->resource_id == EDGE_FACTORY_RESET_RESOURCE_ID && request_ctx->operation == OPERATION_EXECUTE) {
        rfs_reset_factory_settings_requested(request_ctx);
    } else {
        tr_warn("Unexpected edge_server_resource parameters");
        edgeclient_deallocate_request_context(request_ctx);
    }
}

void edgecore_execute_success(edgeclient_request_context_t *ctx)
{
    tr_info("Execute successful to for path '%d/%d/%d'.", ctx->object_id, ctx->object_instance_id, ctx->resource_id);
    edgeclient_deallocate_request_context(ctx);
}

void edgecore_execute_failure(edgeclient_request_context_t *ctx)
{
    tr_info("Execute failed to for path '%d/%d/%d'.", ctx->object_id, ctx->object_instance_id, ctx->resource_id);
    edgeclient_deallocate_request_context(ctx);
}

EdgeCoreCallbackParams::EdgeCoreCallbackParams()
{
    tr_debug("Create EdgeCoreCallbackParams %p", this);
    uri = NULL;
}

bool EdgeCoreCallbackParams::set_uri(uint16_t object_id, uint16_t object_instance_id, uint16_t resource_id)
{
    int32_t uri_length =
            edge_int_length(object_id) + 1 + edge_int_length(object_instance_id) + 1 + edge_int_length(resource_id) + 1;
    uri = (char *) calloc(uri_length, 1);
    if (!uri) {
        tr_error("EdgeCoreCallbackParams could not allocate uri");
        return false;
    } else {
        sprintf(uri, "%d/%d/%d", object_id, object_instance_id, resource_id);
    }
    return true;
}

EdgeCoreCallbackParams::~EdgeCoreCallbackParams()
{
    if (uri) {
        free(uri);
    }
}

void EdgeCoreCallbackParams::execute(void *params)
{
    if (!uri) {
        tr_err("Cannot execute on NULL uri");
        return;
    }

    M2MResource::M2MExecuteParameter* parameters = static_cast<M2MResource::M2MExecuteParameter*>(params);

    const uint8_t* buffer = parameters->get_argument_value();
    uint16_t length = parameters->get_argument_value_length();

    tr_info("resource executed: url=%s, data length=%d", uri, length);
    edgeclient_request_context_t *request_ctx = edgeclient_allocate_request_context(uri,
                                                                                    buffer,
                                                                                    length,
                                                                                    EDGECLIENT_VALUE_IN_BINARY,
                                                                                    OPERATION_EXECUTE,
                                                                                    LWM2M_OPAQUE,
                                                                                    edgecore_execute_success,
                                                                                    edgecore_execute_failure,
                                                                                    NULL);
    if (request_ctx) {
        // direct the callback to Edge Core:
        edgeserver_execute_resource(request_ctx);
    } else {
        tr_err("Could not write execution to protocol translator.");
    }
}

