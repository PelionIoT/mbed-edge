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

#include <stdio.h>
#include "jansson.h"
#include "jsonrpc/jsonrpc.h"

#include "mbed-trace/mbed_trace.h"
#include "edge-client/edge_client_mgmt.h"
#include "edge-client/edge_client.h"
#include "common/integer_length.h"
#include "common/apr_base64.h"
#include "edge-client/edge_client_format_values.h"
#include "edge-core/protocol_api.h"
#include "edge-core/protocol_api_internal.h"
#include "edge-rpc/rpc.h"

#include <assert.h>
#include <string.h>
#define TRACE_GROUP "mgmt_api"

typedef struct mgmt_api_request_context_s {
    char *request_id;
    struct connection *connection;
} mgmt_api_request_context_t;

// This table may be used to map Lwm2mResourceType to string
static const char *resource_type_string_table[] =
{"string", "integer", "float", "boolean", "opaque", "time", "objlink"};

int devices(json_t *request, json_t *json_params, json_t **result, void *userdata)
{
    (void) json_params;
    (void) request;
    (void) userdata;
    edge_device_list_t *devices = edgeclient_devices();
    if (!devices) {
        *result = jsonrpc_error_object_predefined(
            JSONRPC_INTERNAL_ERROR, json_string("Device list request failed."));
        return 1;
    }

    *result = json_object();
    json_t *data = json_array();
    json_object_set_new(*result, "data", data);

    ns_list_foreach_safe(edge_device_entry_t, entry, devices) {
        json_t *device_json = json_object();
        json_t *resource_arr = json_array();

        json_object_set_new(device_json, "endpointName", json_string(entry->name));
        json_object_set_new(device_json, "resources", resource_arr);

        ns_list_foreach_safe(edge_device_resource_entry_t, resource_entry, entry->resources) {
            json_t *resource = json_object();
            json_object_set_new(resource, "uri", json_string(resource_entry->uri));
            const char *resource_type_string = resource_type_string_table[resource_entry->type];
            json_object_set_new(resource, "type", json_string(resource_type_string));
            json_object_set_new(resource, "operation", json_integer(resource_entry->operation));
            json_array_append_new(resource_arr, resource);
            ns_list_remove(entry->resources, resource_entry);
            free(resource_entry->uri);
            free(resource_entry);
        }
        free(entry->resources);

        json_array_append_new(data, device_json);

        // Free the allocated memory.
        ns_list_remove(devices, entry);
        free(entry->name);
        free(entry);

    }

    // Free the allocated list structure
    free(devices);

    return 0;
}

static int parse_endpoint_name_and_uri_tokens(json_t *json_params,
                                              json_t **result,
                                              const char **endpoint_name,
                                              uint16_t *uri_tokens,
                                              const char **uri)
{
    json_t *endpoint_name_obj = json_object_get(json_params, "endpointName");
    if (NULL == endpoint_name_obj) {
        *result = jsonrpc_error_object_predefined(JSONRPC_INVALID_PARAMS, json_string("Key 'endpointName' missing"));
        return 1;
    }
    *endpoint_name = json_string_value(endpoint_name_obj);
    if (!(*endpoint_name) || 0 == strnlen(*endpoint_name, 10)) {
        *result = jsonrpc_error_object_predefined(JSONRPC_INVALID_PARAMS,
                                                  json_string("Value for key 'endpointName' missing or empty"));
        return 1;
    }
    json_t *uri_obj = json_object_get(json_params, "uri");
    if (NULL == uri_obj) {
        *result = jsonrpc_error_object_predefined(JSONRPC_INVALID_PARAMS, json_string("Key 'uri' missing"));
        return 1;
    }
    *uri = json_string_value(uri_obj);
    if (!(*uri) || 0 == strnlen(*uri, 10)) {
        *result = jsonrpc_error_object_predefined(JSONRPC_INVALID_PARAMS,
                                                  json_string("Value for key 'uri' missing or empty"));
        return 1;
    }
    char *tokenized_uri = (char *) strdup(*uri);
    if (!tokenized_uri) {
        tr_err("Cannot allocate tokenized_uri!");
        goto error_exit;
    }
    char *token;
    char *state;
    int32_t counter = 0;
    bool error = false;
    if (strncmp("/", tokenized_uri, 1) != 0) {
        tr_err("Uri does not start with '/'");
        error = true;
    } else if (!strncmp("/", tokenized_uri + strlen(tokenized_uri) - 1, 1)) {
        tr_err("Uri should not end with '/'");
        error = true;
    } else {
        for (token = strtok_r(tokenized_uri + 1, "/", &state); token != NULL; token = strtok_r(NULL, "/", &state)) {
            if (counter >= 3) {
                error = true;
                break;
            }
            int ret = edge_str_to_uint16_t(token, &uri_tokens[counter]);
            if (ret) {
                error = true;
                break;
            }
            counter++;
        }
    }
    if (error || counter != 3) {
        *result = jsonrpc_error_object_predefined(JSONRPC_INVALID_PARAMS,
                                                  json_string("Value for key 'uri' is malformed"));
        goto error_exit;
    }
    free(tokenized_uri);
    return 0;
error_exit:
    free(tokenized_uri);
    return 1;
}

int read_resource(json_t *request, json_t *json_params, json_t **result, void *userdata)
{
    (void) userdata;
    (void) request;
    const char *endpoint_name;
    uint32_t value_length;
    edgeclient_resource_attributes_t attributes;
    uint16_t uri_tokens[3];
    uint8_t *value = NULL;
    const char *uri;

    if (0 != parse_endpoint_name_and_uri_tokens(json_params, result, &endpoint_name, uri_tokens, &uri)) {
        return 1;
    }

    bool found = edgeclient_get_resource_value_and_attributes(endpoint_name,
                                                              uri_tokens[0],
                                                              uri_tokens[1],
                                                              uri_tokens[2],
                                                              &value,
                                                              &value_length,
                                                              &attributes);
    if (!found) {
        *result = jsonrpc_error_object(PT_API_RESOURCE_NOT_FOUND,
                                       pt_api_get_error_message(PT_API_RESOURCE_NOT_FOUND),
                                       json_string("Cannot read resource value"));
        goto error_exit;
    }

    if (!(attributes.operations_allowed & OPERATION_READ)) {
        *result = jsonrpc_error_object(PT_API_RESOURCE_NOT_READABLE,
                                       pt_api_get_error_message(PT_API_RESOURCE_NOT_READABLE),
                                       json_string("Cannot read resource value"));
        goto error_exit;
    }

    *result = json_object();
    json_t *json_string_value = NULL;

    // LWM2M_OPAQUE and LWM2M_OBJLINK cannot be represented as string.
    // FIXME: LWM2M_TIME is not converted to string, because format is not yet specified.
    if (attributes.type != LWM2M_OPAQUE && attributes.type != LWM2M_OBJLINK && attributes.type != LWM2M_TIME) {
        json_string_value = json_string((char *) value);
    }
    json_t *json_type = json_string(resource_type_string_table[attributes.type]);
    uint8_t *binary_value = NULL;
    uint32_t binary_value_length = text_format_to_value(attributes.type, value, value_length, &binary_value);
    if (0 < binary_value_length) {
        int encoded_length = apr_base64_encode_len(binary_value_length);
        char *encoded_value = (char *) malloc(encoded_length);
        if (!encoded_value) {
            tr_err("Cannot allocate encoded_value");
            goto error_exit;
        }
        int encoded_length2 = apr_base64_encode_binary(encoded_value,
                                                       (const uint8_t *) (binary_value),
                                                       binary_value_length);
        assert(encoded_length == encoded_length2);

        json_t *json_binary_value = json_string(encoded_value);
        json_object_set_new(*result, "base64Value", json_binary_value);
        free(binary_value);
        free(encoded_value);
    }
    if (json_string_value != NULL) {
        json_object_set_new(*result, "stringValue", json_string_value);
    }
    json_object_set_new(*result, "type", json_type);
    free(value);
    return 0;
error_exit:
    free(value);
    return 1;
}

static bool parse_value(json_t *json_params, json_t **result, uint8_t **parsed_value, uint32_t *parsed_value_length)
{
    json_t *base64_value_obj = json_object_get(json_params, "base64Value");
    if (NULL == base64_value_obj) {
        *result = jsonrpc_error_object_predefined(JSONRPC_INVALID_PARAMS, json_string("Key 'base64Value' missing"));
        return false;
    }

    const char *base64_value = json_string_value(base64_value_obj);
    if (NULL == base64_value) {
        *result = jsonrpc_error_object_predefined(JSONRPC_INVALID_PARAMS,
                                                  json_string("Value for key 'base64Value' missing"));
        return false;
    }

    uint32_t decoded_len = apr_base64_decode_len(base64_value);
    uint8_t *decoded_value = malloc(decoded_len);
    if (NULL == decoded_value) {
        return false;
    }
    *parsed_value_length = apr_base64_decode_binary(decoded_value, base64_value);
    assert(decoded_len >= *parsed_value_length);
    *parsed_value = decoded_value;
    return true;
}

static void set_write_resource_error_result(json_t **result, pt_api_result_code_e code)
{
    *result = jsonrpc_error_object(code, pt_api_get_error_message(code), json_string("Cannot write resource value"));
}

static void mgmt_write_free_func(rpc_request_context_t *userdata)
{
    mgmt_api_request_context_t *mgmt_context = (mgmt_api_request_context_t *) (userdata);
    tr_debug("Handling write to management client free operations.");
    free(mgmt_context->request_id);
    free(mgmt_context);
}

static void mgmt_send_response_common(mgmt_api_request_context_t *mgmt_context, json_t *response)
{
    int ret_code = rpc_construct_and_send_response(mgmt_context->connection,
                                                   response,
                                                   mgmt_write_free_func,
                                                   (rpc_request_context_t *) mgmt_context, // context
                                                   mgmt_context->connection->transport_connection->write_function);
    if (0 != ret_code) {
        tr_err("mgmt_api_write_success: can't send message. Return code: %d", ret_code);
    }
}

EDGE_LOCAL void mgmt_api_write_success(edgeclient_request_context_t *ctx)
{
    tr_debug("write success for device '%s' | path: '%d/%d/%d'.",
             ctx->device_id,
             ctx->object_id,
             ctx->object_instance_id,
             ctx->resource_id);
    mgmt_api_request_context_t *mgmt_context = (mgmt_api_request_context_t *) (ctx->connection);
    pt_api_result_code_e result_code = edgeclient_update_resource_value(ctx->device_id,
                                                                        ctx->object_id,
                                                                        ctx->object_instance_id,
                                                                        ctx->resource_id,
                                                                        ctx->value,
                                                                        ctx->value_len);

    json_t *response = pt_api_allocate_response_common(mgmt_context->request_id);
    if (PT_API_SUCCESS == result_code) {
        json_object_set_new(response, "result", json_string("ok"));
    } else {
        json_t *result = NULL;
        set_write_resource_error_result(&result, result_code);
        json_object_set_new(response, "error", result);
    }
    mgmt_send_response_common(mgmt_context, response);
    edgeclient_deallocate_request_context(ctx);
}

EDGE_LOCAL void mgmt_api_write_failure(edgeclient_request_context_t *ctx)
{
    tr_warn("Writing to protocol translator failed");
    mgmt_api_request_context_t *mgmt_context = (mgmt_api_request_context_t *) (ctx->connection);
    tr_debug("write failure for device '%s' | path: '%d/%d/%d'.",
             ctx->device_id,
             ctx->object_id,
             ctx->object_instance_id,
             ctx->resource_id);
    json_t *response = pt_api_allocate_response_common(mgmt_context->request_id);
    json_t *result = NULL;
    set_write_resource_error_result(&result, PT_API_WRITE_TO_PROTOCOL_TRANSLATOR_FAILED);
    json_object_set_new(response, "error", result);
    mgmt_send_response_common(mgmt_context, response);
    edgeclient_deallocate_request_context(ctx);
}

int write_resource(json_t *request, json_t *json_params, json_t **result, void *userdata)
{
    const char *endpoint_name;
    uint16_t uri_tokens[3];
    uint8_t *parsed_value = NULL;
    uint32_t parsed_value_length;
    char *uri_with_device = NULL;
    edgeclient_request_context_t *request_ctx = NULL;
    mgmt_api_request_context_t *mgmt_ctx = NULL;
    const char *uri;

    if (0 != parse_endpoint_name_and_uri_tokens(json_params, result, &endpoint_name, uri_tokens, &uri)) {
        return 1;
    }
    // After success of this call we have the `parsed_value` containing the value in raw binary format
    if (!parse_value(json_params, result, &parsed_value, &parsed_value_length)) {
        goto error_exit;
    }
    struct connection *endpoint_connection;
    bool endpoint_found = edgeclient_get_endpoint_context(endpoint_name, (void **) &endpoint_connection);
    if (!endpoint_found) {
        tr_err("Endpoint was not found");
        set_write_resource_error_result(result, PT_API_RESOURCE_NOT_FOUND);
        goto error_exit;
    }
    edgeclient_resource_attributes_t attributes;
    bool resource_found = edgeclient_get_resource_attributes(endpoint_name,
                                                             uri_tokens[0],
                                                             uri_tokens[1],
                                                             uri_tokens[2],
                                                             &attributes);

    if (!resource_found) {
        set_write_resource_error_result(result, PT_API_RESOURCE_NOT_FOUND);
        goto error_exit;
    }

    if (!(attributes.operations_allowed & OPERATION_WRITE)) {
        set_write_resource_error_result(result, PT_API_RESOURCE_NOT_WRITABLE);
        goto error_exit;
    }

    bool value_ok = edgeclient_verify_value(parsed_value, parsed_value_length, attributes.type);
    if (!value_ok) {
        tr_debug("write_resource: value verification failed.");
        set_write_resource_error_result(result, PT_API_ILLEGAL_VALUE);
        goto error_exit;
    }
    mgmt_ctx = malloc(sizeof(mgmt_api_request_context_t));

    if (!mgmt_ctx) {
        tr_debug("write_resource: management api request context malloc failure.");
        goto error_exit;
    }
    mgmt_ctx->request_id = json_dumps(json_object_get(request, "id"), JSON_COMPACT|JSON_ENCODE_ANY);
    mgmt_ctx->connection = ((struct json_message_t *) userdata)->connection;
    if (-1 == asprintf(&uri_with_device, "d/%s%s", endpoint_name, uri)) {
        goto error_exit;
    }
    edge_rc_status_e rc_status;
    request_ctx = edgeclient_allocate_request_context(uri_with_device,
                                                      parsed_value,
                                                      parsed_value_length,
                                                      NULL, /* No token needed */
                                                      0,    /* token_len*/
                                                      EDGECLIENT_VALUE_IN_BINARY,
                                                      OPERATION_WRITE,
                                                      attributes.type,
                                                      mgmt_api_write_success,
                                                      mgmt_api_write_failure,
                                                      &rc_status,
                                                      (void *) mgmt_ctx);
    if (request_ctx) {
        tr_debug("write_resource: edgeclient request_context allocated.");
        if (write_to_pt(request_ctx, (void *) endpoint_connection) != 0) {
            tr_warn("Was not able to prepare or send message to protocol translator.");
            set_write_resource_error_result(result, PT_API_ILLEGAL_VALUE);
            /*
             * The edge and management api contexts must be freed here, the failure callback is not
             * called and should not be called here. If it would be called two responses would be written
             * back to client application.
             */
            edgeclient_deallocate_request_context(request_ctx);
            free(mgmt_ctx->request_id);
            free(mgmt_ctx);
            free(uri_with_device);
            return 1; // error occured.
        }
    } else {
        tr_debug("write_resource: edgeclient request context is NULL. Failing.");
        // Most probably memory ran out. Just return quickly.
        goto error_exit;
    }
    free(uri_with_device);
    return -1; // OK so far, but the response is provided later.
error_exit:
    free(parsed_value);
    free(uri_with_device);
    edgeclient_deallocate_request_context(request_ctx);
    if (mgmt_ctx) {
        free(mgmt_ctx->request_id);
        free(mgmt_ctx);
    }
    return 1; // error occured.
}

struct jsonrpc_method_entry_t mgmt_api_method_table[] = {{"devices", devices, "o"},
                                                         {"read_resource", read_resource, "o"},
                                                         {"write_resource", write_resource, "o"},
                                                         {NULL, NULL, "o"}};

