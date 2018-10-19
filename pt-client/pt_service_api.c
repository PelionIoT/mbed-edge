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

#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "jsonrpc/jsonrpc.h"
#include "edge-rpc/rpc.h"
#include "common/apr_base64.h"
#include "common/pt_api_error_codes.h"
#include "pt-client/pt_api_internal.h"
#include "ns_list.h"
#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP "clnt"

struct jsonrpc_method_entry_t pt_service_method_table[] = {
  { "write", pt_receive_write_value, "o" },
  { NULL, NULL, "o" }
};

static bool check_request_id(struct json_message_t *jt, json_t **result)
{
    json_error_t error;
    json_t *full_request = json_loadb(jt->data, jt->len, 0, &error);
    json_t *id_obj = json_object_get(full_request, "id");
    json_decref(full_request);

    if (id_obj == NULL) {
        tr_err("No id_obj on protocol translator registration request: \"%s\"", jt->data);
        *result = jsonrpc_error_object(JSONRPC_INVALID_PARAMS,
                                       "Invalid params. Missing 'id'-field from request.",
                                       NULL);
        return false;
    }
    return true;
}

json_t* get_handle(json_t* parent, json_t **result, const char* field_name)
{
    json_t* handle = json_object_get(parent, field_name);
    if (!handle) {
        char *err_msg = (char *) malloc(strlen(field_name) +
                                        /* error msg template */
                                        strlen("Invalid params. Missing ''-field.") + 1);
        sprintf(err_msg, "Invalid params. Missing '%s'-field.", field_name);
        *result = jsonrpc_error_object(JSONRPC_INVALID_PARAMS,
                                       err_msg,
                                       NULL);
        free(err_msg);
        tr_error("No '%s' element", field_name);
    }
    return handle;
}

int update_device_values_from_json(struct connection *connection,
                                   json_t *params, json_t **result)
{
    if (!params) {
        *result = jsonrpc_error_object(JSONRPC_INVALID_PARAMS,
                                       "Invalid params. Missing 'params'-field from request.",
                                       NULL);
        tr_error("No parameters element");
        return 1;
    }

    json_t *uri_handle = get_handle(params, result, "uri");
    if (!uri_handle && *result) {
        return 1;
    }

    // Get the device id
    json_t *device_id_handle = get_handle(uri_handle, result, "deviceId");
    if (!device_id_handle && *result) {
        return 1;
    }

    // Get the object id
    json_t *object_id_handle = get_handle(uri_handle, result, "objectId");
    if (!object_id_handle && *result) {
        return 1;
    }

    // Get the object instance id
    json_t *object_instance_id_handle = get_handle(uri_handle, result, "objectInstanceId");
    if (!object_instance_id_handle && *result) {
        return 1;
    }

    // Get the resource id
    json_t *resource_id_handle = get_handle(uri_handle, result, "resourceId");
    if (!resource_id_handle && *result) {
        return 1;
    }

    json_t *resource_value_handle = get_handle(params, result, "value");
    if (!resource_value_handle && *result) {
        return 1;
    }

    json_t *operation_handle = get_handle(params, result, "operation");
    if (!operation_handle && *result) {
        return 1;
    }

    const char* device_id = json_string_value(device_id_handle);
    if (device_id == NULL) {
        tr_err("Could not allocate device id copy");
        return 1;
    }

    /* Create an object and add it to device */
    uint16_t object_id = json_integer_value(object_id_handle);

    /* Create an object instance and add it to object */
    uint16_t object_instance_id = json_integer_value(object_instance_id_handle);

    /* Create a resource and add it to object instance */
    uint16_t resource_id = json_integer_value(resource_id_handle);
    const char *encoded_value = json_string_value(resource_value_handle);
    if (encoded_value == NULL) {
        return 1;
    }
    uint32_t decoded_len = apr_base64_decode_len(encoded_value);
    uint8_t *resource_value = malloc(decoded_len);
    if (NULL == resource_value) {
        return 1;
    }
    uint32_t decoded_len2 = apr_base64_decode_binary(resource_value, encoded_value);
    assert(decoded_len >= decoded_len2);

    uint8_t operation = json_integer_value(operation_handle);

    /* Ready to call write handler with received write data */
    tr_debug("Write resource /d/%s/%d/%d/%d (value_size=%d operation=%d)",
             device_id, object_id, object_instance_id,
             resource_id, decoded_len2, operation);

    int success = connection->protocol_translator_callbacks->received_write_cb(
        connection, device_id, object_id, object_instance_id,
        resource_id, operation, resource_value,
        decoded_len2, connection->userdata);
    if (success != 0) {
        *result = jsonrpc_error_object(PT_API_PROTOCOL_TRANSLATOR_CLIENT_WRITE_ERROR,
                                       pt_api_get_error_message(PT_API_PROTOCOL_TRANSLATOR_CLIENT_WRITE_ERROR),
                                       json_string("Error in client write."));
    }

    free(resource_value);
    return success;
}

int pt_receive_write_value(json_t *request, json_t *json_params, json_t **result, void *userdata)
{
    struct json_message_t *jt = (struct json_message_t*) userdata;
    tr_debug("Write value to protocol translator.");

    if (!check_request_id(jt, result) != 0) {
        return 1;
    }

    if (update_device_values_from_json(jt->connection, json_params, result) != 0) {
        return 1;
    }

    *result = json_string("ok");
    return 0;
}

