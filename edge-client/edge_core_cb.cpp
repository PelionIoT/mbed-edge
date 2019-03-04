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
#include "edge-client/edge_client.h"

bool edgeserver_resource_async_request(edgeclient_request_context_t *request_ctx)
{
    tr_debug("edgeserver_resource_async_request %d/%d/%d operation %d",
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
        return false;
    }
    return true;
}

void edgecore_async_cb_success(edgeclient_request_context_t *ctx)
{
    tr_info("Edge Core asynchronous request successful to for path '%d/%d/%d'.",
            ctx->object_id,
            ctx->object_instance_id,
            ctx->resource_id);
    pt_api_result_code_e status = edgeclient_send_asynchronous_response(NULL,
                                                                        EDGE_DEVICE_OBJECT_ID,
                                                                        ctx->object_instance_id,
                                                                        ctx->resource_id,
                                                                        ctx->token,
                                                                        ctx->token_len,
                                                                        COAP_RESPONSE_CHANGED);
    if (PT_API_SUCCESS != status) {
        tr_err("Failed to send a successful asynchronous request response for '%d/%d/%d' ! Code: %d",
               ctx->object_id,
               ctx->object_instance_id,
               ctx->resource_id,
               status);
    }
    edgeclient_deallocate_request_context(ctx);
}

void edgecore_async_cb_failure(edgeclient_request_context_t *ctx)
{
    tr_warn("Edge Core asynchronous request failed to for path '%d/%d/%d'.",
            ctx->object_id,
            ctx->object_instance_id,
            ctx->resource_id);
    pt_api_result_code_e status = edgeclient_send_asynchronous_response(NULL,
                                                                        EDGE_DEVICE_OBJECT_ID,
                                                                        ctx->object_instance_id,
                                                                        ctx->resource_id,
                                                                        ctx->token,
                                                                        ctx->token_len,
                                                                        COAP_RESPONSE_INTERNAL_SERVER_ERROR);
    if (PT_API_SUCCESS != status) {
        tr_err("edgeclient_send_asynchronous_response failed for '%d/%d/%d' ! returned status: %d",
               ctx->object_id,
               ctx->object_instance_id,
               ctx->resource_id,
               status);
    }
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

bool EdgeCoreCallbackParams::async_request(M2MResource *resource,
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

    tr_info("resource executed: url=%s, data length=%d", uri, (int32_t) length);
    edgeclient_request_context_t *request_ctx = edgeclient_allocate_request_context(uri,
                                                                                    buffer,
                                                                                    length,
                                                                                    token,
                                                                                    token_len,
                                                                                    EDGECLIENT_VALUE_IN_BINARY,
                                                                                    (uint8_t) operation,
                                                                                    LWM2M_OPAQUE,
                                                                                    edgecore_async_cb_success,
                                                                                    edgecore_async_cb_failure,
                                                                                    rc_status,
                                                                                    NULL);
    if (request_ctx) {
        // direct the callback to Edge Core:
        return edgeserver_resource_async_request(request_ctx);
    } else {
        free(buffer);
        tr_err("Could not call Edge Core resource execute for uri '%s'.", uri);
    }
    return false;
}

