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

#define TRACE_GROUP "edgecc"

#include <stdlib.h>
#include <string.h>

extern "C" {
#include "common/integer_length.h"
#include "edge-client/edge_client_format_values.h"
}
#include "edge-client/request_context.h"
#include "mbed-trace/mbed_trace.h"

void edgeclient_deallocate_request_context(edgeclient_request_context *request_context)
{
    if (request_context != NULL) {
        if (request_context->value != NULL) {
            free(request_context->value);
        }
        free(request_context->device_id);
        free(request_context->token);
        free(request_context);
    }
}

edgeclient_request_context_t *edgeclient_allocate_request_context(const char *original_uri,
                                                                  uint8_t *value,
                                                                  uint32_t value_len,
                                                                  uint8_t *token,
                                                                  uint8_t token_len,
                                                                  edgeclient_value_format_e value_format,
                                                                  uint8_t operation,
                                                                  Lwm2mResourceType resource_type,
                                                                  edgeclient_response_handler success_handler,
                                                                  edgeclient_response_handler failure_handler,
                                                                  edge_rc_status_e *rc_status,
                                                                  void *connection)
{
    uint8_t *value_bytes_buf = NULL;
    size_t value_bytes_len = 0;
    char* uri = NULL;
    char *saveptr;
    char *device_id = NULL;
    char* str_object_id = NULL;
    char* str_object_instance_id = NULL;
    char* str_resource_id = NULL;
    edgeclient_request_context_t *ctx;
    int rc = 0;

    if (!rc_status) {
        return NULL;
    }

    *rc_status = EDGE_RC_STATUS_SUCCESS;
    if (!original_uri || strlen(original_uri) == 0) {
        tr_err("NULL or empty uri passed to write context allocation.");
        *rc_status = EDGE_RC_STATUS_INVALID_PARAMETERS;
        return NULL;
    }

    ctx = (edgeclient_request_context_t *) calloc(1, sizeof(edgeclient_request_context_t));
    if (!ctx) {
        tr_err("Could not allocate request context structure.");
        *rc_status = EDGE_RC_STATUS_CANNOT_ALLOCATE_MEMORY;
        return NULL;
    }
    ctx->token = token;
    ctx->token_len = token_len;
    // Our code is expecting that the buffer is null terminated. So let's add a null termination!
    uint8_t *copied_value = NULL;
    if (value) {
        copied_value = (uint8_t *) malloc(value_len + 1);
        if (!copied_value) {
            tr_err("edgeclient_allocate_request_context - cannot duplicate value to null terminate it!");
            free(ctx);
            *rc_status = EDGE_RC_STATUS_CANNOT_ALLOCATE_MEMORY;
            return NULL;
        }
        memcpy(copied_value, value, value_len);
        copied_value[value_len] = '\0';
    }

    /*
     * Decode the text format value from cloud client into bytebuffer in correct
     * data type for protocol translator
     */
    if (EDGECLIENT_VALUE_IN_TEXT == value_format) {
        value_bytes_len = text_format_to_value(resource_type, copied_value, value_len, &value_bytes_buf);
        if (value_bytes_buf == NULL) {
            tr_err("Could not decode resource value to correct type");
            *rc_status = EDGE_RC_STATUS_INVALID_VALUE_FORMAT;
            goto cleanup;
        }
    }

    /*
     * Must copy the original uri to new buffer, the strok function will modify the data
     */
    uri = strndup(original_uri, strlen(original_uri));
    if (uri == NULL) {
        tr_err("Could not allocate copy of original uri for request context.");
        *rc_status = EDGE_RC_STATUS_CANNOT_ALLOCATE_MEMORY;
        goto cleanup;
    }
    /*
     * Split the URI to ids
     * 1) For URIs starting with `d/` , the `uri + 2` skips the starting `d/` from translated endpoint uris,
     *    Example: `d/device_name/5432/0/0`.
     * 2) For URIs that don't start with `d/` assume the device id is NULL.
     *    Example: 3/0/5
     */
    if (strncmp(uri, "d/", 2) == 0) {
        char* tokenized = strtok_r(uri + 2, "/", &saveptr);
        if (tokenized) {
            device_id = strdup(tokenized);
            if (device_id == NULL) {
                tr_err("Could not duplicate device id string");
                *rc_status = EDGE_RC_STATUS_CANNOT_PARSE_URI;
                goto cleanup;
            }
        }
        else {
            tr_err("Could not tokenize the URI string");
            *rc_status = EDGE_RC_STATUS_CANNOT_PARSE_URI;
            goto cleanup;
        }
    } else {
        saveptr = uri;
    }
    str_object_id = strtok_r(NULL, "/", &saveptr);
    str_object_instance_id = strtok_r(NULL, "/", &saveptr);
    str_resource_id = strtok_r(NULL, "/", &saveptr);

    uint16_t object_id;
    uint16_t object_instance_id;
    uint16_t resource_id;
    rc = edge_str_to_uint16_t(str_object_id, &object_id);
    rc = rc | edge_str_to_uint16_t(str_object_instance_id, &object_instance_id);
    rc = rc | edge_str_to_uint16_t(str_resource_id, &resource_id);

    if (rc == 1) {
        *rc_status = EDGE_RC_STATUS_CANNOT_PARSE_URI;
        tr_err("Could not parse valid url for resource.");
        goto cleanup;
    }

    ctx->device_id = device_id;
    ctx->object_id = object_id;
    ctx->object_instance_id = object_instance_id;
    ctx->resource_id = resource_id;
    if (EDGECLIENT_VALUE_IN_TEXT == value_format) {
        ctx->value = value_bytes_buf;
        ctx->value_len = value_bytes_len;
        // Free copied value, it is copied to value_bytes_buf as binary content.
        free(copied_value);
        copied_value = NULL;
    } else {
        ctx->value = copied_value;
        ctx->value_len = value_len;
    }
    ctx->resource_type = resource_type;
    ctx->operation = operation;
    ctx->success_handler = success_handler;
    ctx->failure_handler = failure_handler;
    ctx->connection = connection;

    free(uri);
    free(value);
    return ctx;

cleanup:
    free(token);
    free(copied_value);
    free(device_id);
    free(uri);
    free(value_bytes_buf);
    free(ctx);

    return NULL;
}
