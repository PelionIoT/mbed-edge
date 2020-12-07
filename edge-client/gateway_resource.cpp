/*
 * ----------------------------------------------------------------------------
 * Copyright 2020 ARM Ltd.
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

#define TRACE_GROUP "edgegrm"
#include "edge-client/edge_client.h"
#include "mbed-trace/mbed_trace.h"
#include "edge-client/gateway_resource.h"

Lwm2mResourceType m2mresource_type(M2MResourceBase::ResourceType resourceType)
{
    switch (resourceType) {
    case M2MResourceBase::STRING:
        return LWM2M_STRING;
    case M2MResourceBase::INTEGER:
        return LWM2M_INTEGER;
    case M2MResourceBase::FLOAT:
        return LWM2M_FLOAT;
    case M2MResourceBase::BOOLEAN:
        return LWM2M_BOOLEAN;
    case M2MResourceBase::OPAQUE:
        return LWM2M_OPAQUE;
    case M2MResourceBase::TIME:
        return LWM2M_TIME;
    case M2MResourceBase::OBJLINK:
        return LWM2M_OBJLINK;
    }
    return static_cast<Lwm2mResourceType>(-1);
}

coap_response_code_e generate_coap_error(int16_t jsonrpc_error_code)
{
    coap_response_code_e resp;
    switch (jsonrpc_error_code) {
        case PT_API_REQUEST_TIMEOUT:
            resp = COAP_RESPONSE_GATEWAY_TIMEOUT;
            break;
        case PT_API_REMOTE_DISCONNECTED:
            resp = COAP_RESPONSE_NOT_FOUND;
            break;
        default:
            resp = COAP_RESPONSE_INTERNAL_SERVER_ERROR;
            break;
    }
    return resp;
}

void edgeclient_grm_execute_success(edgeclient_request_context_t *ctx)
{
    tr_info("Execute successful to gateway resource manager for path '/%d/%d/%d'.",
            ctx->object_id,
            ctx->object_instance_id,
            ctx->resource_id);
    pt_api_result_code_e status = edgeclient_send_asynchronous_response(NULL,
                                          ctx->object_id,
                                          ctx->object_instance_id,
                                          ctx->resource_id,
                                          ctx->token,
                                          ctx->token_len,
                                          COAP_RESPONSE_CHANGED);
    if (PT_API_SUCCESS != status) {
        tr_err("Failed to send asynchronous response for '%d/%d/%d' execution success! returned status: %d",
               ctx->object_id,
               ctx->object_instance_id,
               ctx->resource_id,
               status);
    }
    edgeclient_deallocate_request_context(ctx);
}

void edgeclient_grm_execute_failure(edgeclient_request_context_t *ctx)
{
    tr_info("Execute failed to gateway resource manager for path '/%d/%d/%d'.",
            ctx->object_id,
            ctx->object_instance_id,
            ctx->resource_id);
    coap_response_code_e coap_response_code = generate_coap_error(ctx->jsonrpc_error_code);
    pt_api_result_code_e status = edgeclient_send_asynchronous_response(NULL,
                                          ctx->object_id,
                                          ctx->object_instance_id,
                                          ctx->resource_id,
                                          ctx->token,
                                          ctx->token_len,
                                          coap_response_code);
    if (PT_API_SUCCESS != status) {
        tr_err("Failed to send asynchronous response for '%d/%d/%d' execution failure! returned status: %d",
               ctx->object_id,
               ctx->object_instance_id,
               ctx->resource_id,
               status);
    }
    edgeclient_deallocate_request_context(ctx);
}

void edgeclient_grm_write_success(edgeclient_request_context_t *ctx)
{
    tr_info("Write successful to gateway resource manager for path '/%d/%d/%d'.",
            ctx->object_id,
            ctx->object_instance_id,
            ctx->resource_id);

    coap_response_code_e coap_response = COAP_RESPONSE_CHANGED;
    pt_api_result_code_e status = edgeclient_update_resource_value(NULL,
                                                                   ctx->object_id,
                                                                   ctx->object_instance_id,
                                                                   ctx->resource_id,
                                                                   ctx->value,
                                                                   ctx->value_len);
    if (PT_API_SUCCESS != status) {
        tr_err("edgeclient_grm_write_success: updating written value failed with code %d", status);
        switch (status) {
            case PT_API_RESOURCE_NOT_FOUND: {
                coap_response = COAP_RESPONSE_NOT_FOUND;
            } break;
            case PT_API_ILLEGAL_VALUE: {
                coap_response = COAP_RESPONSE_UNSUPPORTED_CONTENT_FORMAT;
            } break;
            default: {
                coap_response = COAP_RESPONSE_INTERNAL_SERVER_ERROR;
            } break;
        }
    }

    status = edgeclient_send_asynchronous_response(NULL,
                                          ctx->object_id,
                                          ctx->object_instance_id,
                                          ctx->resource_id,
                                          ctx->token,
                                          ctx->token_len,
                                          coap_response);
    if (PT_API_SUCCESS != status) {
        tr_err("Failed to send asynchronous response for '%d/%d/%d' write success! returned status: %d",
               ctx->object_id,
               ctx->object_instance_id,
               ctx->resource_id,
               status);
    }
    edgeclient_deallocate_request_context(ctx);
}

void edgeclient_grm_write_failure(edgeclient_request_context_t *ctx)
{
    tr_warn("Write failed to gateway resource manager for path '/%d/%d/%d'.",
            ctx->object_id,
            ctx->object_instance_id,
            ctx->resource_id);
    coap_response_code_e coap_response_code = generate_coap_error(ctx->jsonrpc_error_code);
    pt_api_result_code_e status = edgeclient_send_asynchronous_response(NULL,
                                          ctx->object_id,
                                          ctx->object_instance_id,
                                          ctx->resource_id,
                                          ctx->token,
                                          ctx->token_len,
                                          coap_response_code);
    if (PT_API_SUCCESS != status) {
        tr_err("Failed to send asynchronous response for '%d/%d/%d' write failure! returned status: %d",
               ctx->object_id,
               ctx->object_instance_id,
               ctx->resource_id,
               status);
    }
    edgeclient_deallocate_request_context(ctx);
}

bool edgeclient_grm_execute_handler(const M2MResourceBase *resource_base,
                                               void *connection,
                                               uint8_t *buffer,
                                               const uint32_t length,
                                               uint8_t *token,
                                               uint8_t token_len,
                                               edge_rc_status_e *rc_status)
{
    const char *uri = resource_base->uri_path();
    Lwm2mResourceType resource_type = m2mresource_type(resource_base->resource_instance_type());
    uint8_t operation = OPERATION_EXECUTE;
    tr_info("Resource execute initiated to gateway resource manager for %s, data length=%d", uri, (int32_t) length);

    edgeclient_request_context_t *request_ctx = edgeclient_allocate_request_context(uri,
                                                                                    buffer,
                                                                                    length,
                                                                                    token,
                                                                                    token_len,
                                                                                    EDGECLIENT_VALUE_IN_BINARY,
                                                                                    (uint8_t) operation,
                                                                                    resource_type,
                                                                                    edgeclient_grm_execute_success,
                                                                                    edgeclient_grm_execute_failure,
                                                                                    rc_status,
                                                                                    connection);

    if (request_ctx) {
        if (PT_API_SUCCESS == edgeclient_write_to_grm_cb(request_ctx)) {
            return true;
        } else {
            tr_err("Executing to gateway resource manager failed. Freeing the request context.");
            edgeclient_deallocate_request_context(request_ctx);
        }
    } else {
        tr_err("Could not allocate request context for writing to protocol translator.");
        free(buffer);
    }
    return false;
}

bool edgeclient_grm_set_handler(const M2MResourceBase *resource_base,
                                           void *connection,
                                           uint8_t *value,
                                           const uint32_t value_length,
                                           uint8_t *token,
                                           uint8_t token_len,
                                           edge_rc_status_e *rc_status)
{
    const char *uri_path = resource_base->uri_path();
    Lwm2mResourceType resource_type = m2mresource_type(resource_base->resource_instance_type());

    edgeclient_request_context_t *request_ctx = edgeclient_allocate_request_context(uri_path,
                                                                                    value,
                                                                                    value_length,
                                                                                    token,
                                                                                    token_len,
                                                                                    EDGECLIENT_VALUE_IN_TEXT,
                                                                                    OPERATION_WRITE,
                                                                                    resource_type,
                                                                                    edgeclient_grm_write_success,
                                                                                    edgeclient_grm_write_failure,
                                                                                    rc_status,
                                                                                    connection);
    if (request_ctx) {
        tr_info("Value write initiated to gateway resource manager for %s with size %u", uri_path, value_length);
        if (PT_API_SUCCESS == edgeclient_write_to_grm_cb(request_ctx)) {
          return true;
        } else {
            tr_err("Write to gateway resource manager failed. Freeing the request context.");
            edgeclient_deallocate_request_context(request_ctx);
        }
    } else {
        tr_err("Could not allocate request context. Write not propagated to resource manager.");
        free(value);
    }
    return false;
}
