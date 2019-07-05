/*
 * ----------------------------------------------------------------------------
 * Copyright 2019 ARM Ltd.
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
#include "pt-client-2/pt_api_internal.h"
#include "ns_list.h"
#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP "clnt"

EDGE_LOCAL int pt_receive_write_value(json_t *request, json_t *json_params, json_t **result, void *userdata);
EDGE_LOCAL int pt_receive_certificate_renewal_result(json_t *request, json_t *json_params, json_t **result, void *userdata);

struct jsonrpc_method_entry_t pt_service_method_table[] = {
  { "write", pt_receive_write_value, "o" },
  { "certificate_renewal_result", pt_receive_certificate_renewal_result, "o" },
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

pt_status_t pt_devices_call_resource_callback(connection_id_t connection_id,
                                              const char *device_id,
                                              const uint16_t object_id,
                                              const uint16_t instance_id,
                                              const uint16_t resource_id,
                                              const unsigned int operation,
                                              const uint8_t *value,
                                              const uint32_t value_size)
{
    tr_info("Device Management Edge write to protocol translator.");

    connection_t *connection = find_connection(connection_id);
    if (NULL == connection || NULL == connection->client->devices || NULL == device_id) {
        return PT_STATUS_INVALID_PARAMETERS;
    }
    pt_device_t *device = pt_devices_find_device(connection->client->devices, device_id);
    if (device) {
        pt_object_t *object = pt_device_find_object(device, object_id);
        pt_object_instance_t *instance = pt_object_find_object_instance(object, instance_id);
        const pt_resource_t *resource = pt_object_instance_find_resource(instance, resource_id);

        if (!object || !instance || !resource) {
            tr_warn("No match for device \"%s/%d/%d/%d\" on write action.",
                    device_id,
                    object_id,
                    instance_id,
                    resource_id);
            return PT_STATUS_NOT_FOUND;
        }

        /* Check if resource supports operation */
        if (!(resource->operations & operation)) {
            tr_warn("Operation %d tried on resource \"%s/%d/%d/%d\" which does not support it.",
                    operation,
                    device_id,
                    object_id,
                    instance_id,
                    resource_id);
            return PT_STATUS_ERROR;
        }

        if (resource->callback) {
            tr_info("Execute resource callback for \"%s/%d/%d/%d\".",
                    device_id,
                    object_id,
                    instance_id,
                    resource_id);
            void *userdata = NULL;
            if (resource->userdata && resource->userdata->data) {
                userdata = resource->userdata->data;
            }
            return resource->callback(connection_id,
                                      device_id,
                                      object_id,
                                      instance_id,
                                      resource_id,
                                      operation,
                                      value,
                                      value_size,
                                      userdata);
        }
    } else {
        return PT_STATUS_NOT_FOUND;
    }
    return PT_STATUS_SUCCESS;
}

int update_device_values_from_json(struct connection *connection,
                                   json_t *params,
                                   json_t **result)
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

    int success = pt_devices_call_resource_callback(get_connection_id(connection),
                                                    device_id,
                                                    object_id,
                                                    object_instance_id,
                                                    resource_id,
                                                    operation,
                                                    resource_value,
                                                    decoded_len2);
    if (success != 0) {
        *result = jsonrpc_error_object(PT_API_PROTOCOL_TRANSLATOR_CLIENT_WRITE_ERROR,
                                       pt_api_get_error_message(PT_API_PROTOCOL_TRANSLATOR_CLIENT_WRITE_ERROR),
                                       json_string("Error in client write."));
    }

    free(resource_value);
    return success;
}

EDGE_LOCAL int pt_receive_write_value(json_t *request, json_t *json_params, json_t **result, void *userdata)
{
    (void) request;
    struct json_message_t *jt = (struct json_message_t*) userdata;
    tr_debug("Write value to protocol translator.");
    int status = 0;

    if (!check_request_id(jt, result) != 0) {
        return JSONRPC_RETURN_CODE_ERROR;
    }

    // Prepare response params context
    response_params_t *params = (response_params_t *) calloc(1, sizeof(response_params_t));
    json_t *response = json_object();
    if (params == NULL || response == NULL) {
        free(params);
        json_decref(response);
        return JSONRPC_RETURN_CODE_ERROR;
    }
    params->response = response;
    connection_t *connection = jt->connection;
    params->connection_id = connection->id;
    json_object_set_new(response, "id", json_copy(json_object_get(request, "id")));
    json_object_set_new(response, "jsonrpc", json_string("2.0"));

    status = update_device_values_from_json(jt->connection, json_params, result);
    if (status != 0) {
        // Write failed, prepare error response and push to eventloop
        if (*result == NULL) {
            *result = jsonrpc_error_object(JSONRPC_INVALID_PARAMS,
                                           "Invalid params.",
                                           NULL);
        }
        json_object_set_new(response, "error", *result);
    }
    else {
        // Write was success, prepare response and push it into eventloop
        json_object_set_new(response, "result", json_string("ok"));
    }

    if (pt_api_send_to_event_loop(connection->id, params, event_loop_send_response_callback) != PT_STATUS_SUCCESS) {
        return JSONRPC_RETURN_CODE_ERROR;
    }

    return JSONRPC_RETURN_CODE_NO_RESPONSE;
}

EDGE_LOCAL int pt_receive_certificate_renewal_result(json_t *request, json_t *json_params, json_t **result, void *userdata)
{
    (void) request;
    struct json_message_t *jt = (struct json_message_t*) userdata;
    tr_debug("Received certificate renewal result.");

    if (!check_request_id(jt, result) != 0) {
        return JSONRPC_RETURN_CODE_ERROR;
    }

    json_t *cert_handle = json_object_get(json_params, "certificate");
    json_t *initiator_handle = json_object_get(json_params, "initiator");
    json_t *status_handle = json_object_get(json_params, "status");
    json_t *description_handle = json_object_get(json_params, "description");
    if (cert_handle == NULL || initiator_handle == NULL || status_handle == NULL || description_handle == NULL) {
        tr_warning("Certificate renewal result missing fields.");
        *result = jsonrpc_error_object(
                JSONRPC_INVALID_PARAMS,
                "Invalid params. Missing 'params', 'initiator', 'status' or 'description' field from request.",
                NULL);
        return JSONRPC_RETURN_CODE_ERROR;
    }

    const char *cert_name = json_string_value(cert_handle);
    int initiator = json_integer_value(initiator_handle);
    int status = json_integer_value(status_handle);
    const char *description = json_string_value(description_handle);

    tr_debug("Certificate renewal result, (certificate '%s', initiator '%d', status '%d', description '%s')",
             cert_name,
             initiator,
             status,
             description);

    connection_t *connection = jt->connection;
    pt_client_t *client = connection->client;
    if (client->protocol_translator_callbacks->certificate_renewal_notifier_cb) {
        client->protocol_translator_callbacks->certificate_renewal_notifier_cb(connection->id,
                                                                               cert_name,
                                                                               initiator,
                                                                               status,
                                                                               description,
                                                                               client->userdata);
    } else {
        tr_err("Cannot notify certificate renewal result!");
    }
    *result = json_string("ok");
    return JSONRPC_RETURN_CODE_SUCCESS;
}
