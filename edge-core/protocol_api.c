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

#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <jansson.h>
#include <assert.h>

#include "edge-core/protocol_api.h"

#include "jsonrpc/jsonrpc.h"
#include "edge-rpc/rpc.h"
#include "edge-client/edge_client.h"
#include "common/apr_base64.h"
#include "common/default_message_id_generator.h"
#include "edge-core/server.h"
#include "edge-core/edge_server.h"
#include "common/edge_common.h"
#include "mbedtls/base64.h"

#include "ns_list.h"
#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP "serv"


struct jsonrpc_method_entry_t method_table[] = {
  { "protocol_translator_register", protocol_translator_register, "o" },
  { "device_register", device_register, "o" },
  { "device_unregister", device_unregister, "o" },
  { "write", write_value, "o" },
  { NULL, NULL, "o" }
};

static bool check_service_availability(json_t **result);

typedef enum {
    PT_TRANSLATOR_ALREADY_REGISTERED,
    PT_TRANSLATOR_NOT_REGISTERED
} pt_translator_registration_status_e;

typedef enum {
    PT_MODE_PRETEND,
    PT_MODE_REAL
} pt_mode_e;

typedef enum {
    PT_UPDATE_FLAGS_NONE = 0x00,
    PT_UPDATE_FLAGS_FAIL_IF_DEVICE_EXISTS = 0x01 // Abort hte operation if the devices already exists
} pt_update_device_values_flags_e;

static int update_device_values_from_json(json_t *structure,
                                          struct connection *connection,
                                          const char **error_detail,
                                          pt_update_device_values_flags_e flags);

void init_protocol()
{
    rpc_set_generate_msg_id(edge_default_generate_msg_id);
    rpc_init(method_table);
}

static pt_translator_registration_status_e get_protocol_translator_registration_status(struct connection *connection)
{
    tr_debug("get_protocol_translator_registration_status");

    if (connection->protocol_translator->registered) {
        return PT_TRANSLATOR_ALREADY_REGISTERED;
    }
    return PT_TRANSLATOR_NOT_REGISTERED;
}

static bool is_protocol_translator_registered(const char* name_val, const struct ctx_data *ctx_data)
{
    ns_list_foreach(const struct connection_list_elem, cur, &ctx_data->registered_translators) {
        if (strcmp(cur->conn->protocol_translator->name, name_val) == 0) {
            return true;
        }
    }
    return false;
}

static bool check_request_id(struct json_message_t *jt)
/**
 * \brief Checks if the request id is in the JSON request.
 * \return true  - request id is found
 *         false - request id is missing
 */
{
    json_error_t error;
    json_t *full_request = json_loadb(jt->data, jt->len, 0, &error);
    json_t *id_obj = json_object_get(full_request, "id");
    json_decref(full_request);

    if (id_obj == NULL) {
        return false;
    }
    return true;
}

static void initialize_pt_resources(char *name, int pt_id){
    // Set pt name
    uint32_t length = strlen(name);
    edgeclient_set_resource_value(NULL, PROTOCOL_TRANSLATOR_OBJECT_ID, pt_id,
                                  PROTOCOL_TRANSLATOR_OBJECT_NAME_RESOURCE_ID, (uint8_t*) name, length,
                                  LWM2M_OPAQUE, OPERATION_READ /*GET_ALLOWED*/, /* userdata */ NULL);

    //Set device counter to zero, the API expects values in network byte-order.
    uint16_t zero = htons(0);
    edgeclient_set_resource_value(NULL, PROTOCOL_TRANSLATOR_OBJECT_ID, pt_id,
                                  PROTOCOL_TRANSLATOR_OBJECT_COUNT_RESOURCE_ID, (uint8_t*) &zero, sizeof(uint16_t),
                                  LWM2M_INTEGER, OPERATION_READ /*GET_ALLOWED*/, /* userdata */ NULL);
}

void protocol_api_free_pt_resources(protocol_translator_t *protocol_translator)
{
    int pt_id = protocol_translator->id;
    if (pt_id != -1) {
        edgeclient_remove_object_instance(NULL, PROTOCOL_TRANSLATOR_OBJECT_ID, pt_id);
    }
}

static bool check_service_availability(json_t **result)
/**
 * \return true  if service is available.
 *         false if service is unavailable
 */
{
    if (edgeclient_is_shutting_down()) {
        *result = jsonrpc_error_object(PT_API_INTERNAL_ERROR,
                                       "Error",
                                       json_string("Service unavailable, because the server is shutting down"));
        return false;
    }
    return true;
}

int protocol_translator_register(json_t *json_params, json_t **result, void *userdata)
/** \return 0 - success
 *          1 - failure
 */
{
    struct json_message_t *jt = (struct json_message_t*) userdata;
    struct connection *connection = jt->connection;
    struct ctx_data *ctx_data = connection->ctx->ctx_data;

    if (!check_service_availability(result)) {
        return 1;
    }

    if (!check_request_id(jt)) {
        tr_err("No id_obj on protocol translator registration request: \"%s\"", jt->data);
        // FIXME: write back an error response and close the connection.
        *result = jsonrpc_error_object_predefined(
                JSONRPC_INVALID_PARAMS, json_string("Protocol translator registration failed. Request id missing."));
        return 1;
    }
    pt_translator_registration_status_e status = get_protocol_translator_registration_status(connection);
    if (status == PT_TRANSLATOR_NOT_REGISTERED) {
        tr_info("Registering protocol translator.");
        json_t *name_obj = json_object_get(json_params, "name");
        const char *name_val = json_string_value(name_obj);

        if (!name_obj) {
            tr_err("protocol_translator_register 'name' key not found");
            *result = jsonrpc_error_object_predefined(JSONRPC_INVALID_PARAMS,
                                                      json_string("Key 'name' missing"));
            return 1;
        }
        else if (!name_val || strnlen(name_val, 10) == 0) {
            tr_err("protocol_translator_unregister: No value for key 'name'");
            *result = jsonrpc_error_object_predefined(
                    JSONRPC_INVALID_PARAMS, json_string("Value for key 'name' missing or empty"));
            return 1;
        } else if (!is_protocol_translator_registered(name_val, ctx_data)) {
            char *name = malloc(sizeof(char) * strlen(name_val) + 1);
            int new_pt_id = 0;

            strncpy(name, name_val, strlen(name_val) + 1);
            connection->protocol_translator->name = name;
            connection->protocol_translator->registered = true;
            if (ns_list_count(&ctx_data->registered_translators) > 0) {
                struct connection_list_elem *last_pt = ns_list_get_last(&ctx_data->registered_translators);
                int last_pt_id = last_pt->conn->protocol_translator->id;
                new_pt_id = last_pt_id + 1;
            }
            connection->protocol_translator->id = new_pt_id;
            initialize_pt_resources(name, new_pt_id);

            struct connection_list_elem *new_translator = calloc(1, sizeof(struct connection_list_elem));
            new_translator->conn = connection;
            ns_list_add_to_end(&ctx_data->registered_translators, new_translator);
            tr_info("Registered protocol translator '%s'", name);
            *result = json_string("ok");
            edgeclient_update_register_conditional(EDGECLIENT_LOCK_MUTEX);
            return 0;
        } else {
            tr_warn("Protocol translator name already reserved.");

            struct connection_list_elem *not_accepted_translator = calloc(1, sizeof(struct connection_list_elem));
            not_accepted_translator->conn = connection;
            ns_list_add_to_end(&ctx_data->not_accepted_translators, not_accepted_translator);

            *result = jsonrpc_error_object(PT_API_PROTOCOL_TRANSLATOR_NAME_RESERVED,
                                           pt_api_get_error_message(PT_API_PROTOCOL_TRANSLATOR_NAME_RESERVED),
                                           json_string("Cannot register the protocol translator."));
            return 1;
        }
    }
    /* PT_API_PROTOCOL_TRANSLATOR_ALREADY_REGISTERED */
    tr_warn("Protocol translator already registered.");
    *result = jsonrpc_error_object(PT_API_PROTOCOL_TRANSLATOR_ALREADY_REGISTERED,
                                   pt_api_get_error_message(PT_API_PROTOCOL_TRANSLATOR_ALREADY_REGISTERED),
                                   json_string("Already registered."));
    return 1;
}

static void update_device_amount_resource_by_delta(struct connection* connection, int16_t delta_amount)
{
    // Update the device amount in protocol translator by delta amount
    int16_t pt_device_amount = 0; // 65535 devices should be more than enough
    char* pt_device_amount_text_format = NULL;
    uint32_t value_len = 0;

    if (edgeclient_get_resource_value(NULL,
                                      PROTOCOL_TRANSLATOR_OBJECT_ID,
                                      connection->protocol_translator->id,
                                      PROTOCOL_TRANSLATOR_OBJECT_COUNT_RESOURCE_ID,
                                      (uint8_t**) &pt_device_amount_text_format,
                                      &value_len)) {
        pt_device_amount = atoi(pt_device_amount_text_format);
        pt_device_amount += delta_amount;
        /* Change the amount to network byte order */
        pt_device_amount = htons(pt_device_amount);
        pt_api_result_code_e ret =  edgeclient_set_resource_value(
            NULL, PROTOCOL_TRANSLATOR_OBJECT_ID,
            connection->protocol_translator->id,
            PROTOCOL_TRANSLATOR_OBJECT_COUNT_RESOURCE_ID,
            (uint8_t*) &pt_device_amount, sizeof(int16_t),
            LWM2M_INTEGER,
            /* operations = allow read */ OPERATION_READ,
            connection);
        if (PT_API_SUCCESS == ret) {
            tr_debug("Updated the device amount for %s to %d", connection->protocol_translator->name, ntohs(pt_device_amount));
        } else {
            tr_warn("Could not update device amount for protocol translator");
        }
        free(pt_device_amount_text_format);
    }
    else {
        tr_warn("Could not get device amount for protocol translator");
    }
}

const char* check_device_id(json_t *json_params, json_t **result)
{
    json_t *device_id_obj = json_object_get(json_params, "device-id");
    if (device_id_obj == NULL) {
        *result = jsonrpc_error_object(JSONRPC_INVALID_PARAMS,
                                       "Error",
                                       json_string("Missing `device-id` field."));
        return NULL;
    }
    const char* device_id = json_string_value(device_id_obj);
    if (!device_id || strlen(device_id) == 0) {
        *result = jsonrpc_error_object(JSONRPC_INVALID_PARAMS,
                                       "Error",
                                       json_string("Invalid `device-id` field value."));
        return NULL;
    }
    return device_id;
}

static json_t *create_detailed_error_object(pt_api_result_code_e error_id, const char *base_error, const char *error_detail)
{
    char *error_description = (char *) base_error;
    char *alloced_description = NULL;

    if (error_detail) {
        const char *reason = " Reason: ";
        size_t reason_len = strnlen(reason, 100);
        size_t base_len = strnlen(base_error, 100);
        size_t offset = 0;
        size_t detail_len = strnlen(error_detail, 100);
        alloced_description = (char *) calloc(1, detail_len + reason_len + base_len + 1);

        if (alloced_description) {
            strncpy(alloced_description, base_error, base_len);
            offset += base_len;
            strncpy(alloced_description + offset, reason, reason_len);
            offset += reason_len;
            strncpy(alloced_description + offset, error_detail, detail_len);
            error_description = alloced_description;
            }
    }
    json_t *result = jsonrpc_error_object(error_id, pt_api_get_error_message(error_id), json_string(error_description));
    free(alloced_description);
    return result;
}

int device_register(json_t *json_params, json_t **result, void *userdata)
/** \return 0 - success
 *          1 - failure
 */
{
    struct json_message_t *jt = (struct json_message_t*) userdata;
    struct connection* connection = jt->connection;
    tr_debug("Device register.");

    if (!check_request_id(jt)) {
        tr_warn("Device registration failed. No request id was given");
        *result = jsonrpc_error_object_predefined(JSONRPC_INVALID_PARAMS,
                                                  json_string("Device registration failed. No request id was given."));
        return 1;
    }

    if (edgeserver_get_number_registered_endpoints_count() >= edgeserver_get_number_registered_endpoints_limit()) {
        tr_warn("Device registration failed. The maximum number of registered endpoints is already in use.");
        *result = jsonrpc_error_object(PT_API_REGISTERED_ENDPOINT_LIMIT_REACHED,
                                       pt_api_get_error_message(PT_API_REGISTERED_ENDPOINT_LIMIT_REACHED),
                                       json_string("Failed to register device."));
        return 1;
    }

    if (!check_service_availability(result)) {
        return 1;
    }
    // Not registered
    if (get_protocol_translator_registration_status(connection) !=
            PT_TRANSLATOR_ALREADY_REGISTERED) {
        *result = jsonrpc_error_object(PT_API_PROTOCOL_TRANSLATOR_NOT_REGISTERED,
                                       pt_api_get_error_message(PT_API_PROTOCOL_TRANSLATOR_NOT_REGISTERED),
                                       json_string("Failed to register device."));
        return 1;
    }
    const char* device_id = check_device_id(json_params, result);
    if(!device_id) {
        tr_error("Device register failed. Field 'device-id' was missing or value was either null or empty string");
        return 1;
    }
    const char *error_detail = NULL;
    pt_api_result_code_e result_code = update_device_values_from_json(json_params,
                                                                      connection,
                                                                      &error_detail,
                                                                      PT_UPDATE_FLAGS_FAIL_IF_DEVICE_EXISTS);
    if (result_code != 0) {
        tr_error("Device register failed: '%s'.", device_id);
        *result = create_detailed_error_object(result_code, "Failed to register device.", error_detail);
        return 1;
    }
    *result = json_string("ok");
    update_device_amount_resource_by_delta(connection, +1);
    edgeserver_change_number_registered_endpoints_by_delta(+1);
    tr_info("Device registered successfully: '%s'.", device_id);
    edgeclient_update_register_conditional(EDGECLIENT_LOCK_MUTEX);
    return 0;
}

/**
 * \brief device unregister jsonrpc endpoint
 *  \return 0 - success
 *          1 - failure
 */
int device_unregister(json_t *json_params, json_t **result, void *userdata)
{
    struct json_message_t *jt = (struct json_message_t*) userdata;
    struct connection* connection = jt->connection;
    tr_debug("Device unregister.");

    if (!check_request_id(jt)) {
        tr_warn("Device unregistration failed. No request id was given");
        *result = jsonrpc_error_object_predefined(JSONRPC_INVALID_PARAMS,
                                                  json_string("Device unregistration failed. No request id was given."));
        return 1;
    }

    if (!check_service_availability(result)) {
        return 1;
    }
    // Not registered
    if (get_protocol_translator_registration_status(connection) != PT_TRANSLATOR_ALREADY_REGISTERED) {
        *result = jsonrpc_error_object(PT_API_PROTOCOL_TRANSLATOR_NOT_REGISTERED,
                                       pt_api_get_error_message(PT_API_PROTOCOL_TRANSLATOR_NOT_REGISTERED),
                                       json_string("Failed to unregister device."));
        return 1;
    }
    const char* device_id = check_device_id(json_params, result);
    if(!device_id){
        tr_error("Device unregister failed. Field 'device-id' was missing or value was either null or empty string");
        return 1;
    }
    if (!edgeclient_remove_endpoint(device_id)) {
        tr_error("Device unregister failed: '%s'.", device_id);
        *result = jsonrpc_error_object(PT_API_INTERNAL_ERROR,
                                       pt_api_get_error_message(PT_API_INTERNAL_ERROR),
                                       json_string("Failed to unregister device."));
        return 1;
    }
    update_device_amount_resource_by_delta(connection, -1);
    edgeserver_change_number_registered_endpoints_by_delta(-1);
    *result = json_string("ok");
    tr_info("Device unregistered successfully: '%s'.", device_id);
    edgeclient_update_register_conditional(EDGECLIENT_LOCK_MUTEX);
    return 0;
}

int write_value(json_t *json_params, json_t **result, void *userdata)
/** \return 0 - success
 *          1 - failure
 */
{
    struct json_message_t *jt = (struct json_message_t*) userdata;
    struct connection *connection = jt->connection;
    tr_debug("Write value.");
    if (!check_service_availability(result)) {
        return 1;
    }
    if (get_protocol_translator_registration_status(connection) != PT_TRANSLATOR_ALREADY_REGISTERED) {
        tr_warn("Write value failed. Protocol translator not registered");
        *result = jsonrpc_error_object(PT_API_PROTOCOL_TRANSLATOR_NOT_REGISTERED,
                                       pt_api_get_error_message(PT_API_PROTOCOL_TRANSLATOR_NOT_REGISTERED),
                                       json_string("Write value failed. Protocol translator not registered."));
        return 1;
    }
    if (!check_request_id(jt)) {
        tr_warn("Write value failed. No request id was given");
        *result = jsonrpc_error_object_predefined(JSONRPC_INVALID_PARAMS,
                                                  json_string("Write value failed. No request id was given."));
        return 1;
    }
    const char* device_id = check_device_id(json_params, result);
    if(!device_id) {
        tr_warn("Write value failed.  Field 'device-id' was missing or value was either null or empty string");

        return 1;
    }
    const char *error_detail = NULL;
    pt_api_result_code_e ret = update_device_values_from_json(json_params,
                                                              connection,
                                                              &error_detail,
                                                              PT_UPDATE_FLAGS_NONE);
    if (ret != PT_API_SUCCESS) {
        tr_warn("Write value failed. Failed to update device values from json.");
        *result = create_detailed_error_object(
                ret, "Write value failed. Failed to update device values from json.", error_detail);
        return 1;
    }
    tr_info("Write value succeeded");
    *result = json_string("ok");
    /* NOTE edgeclient_update_register_conditional not required here since
    * we don't call anything else than update_device_values_from_json
    */
    return 0;
}

static Lwm2mResourceType resource_type_from_json_handle(json_t *resource_dict_handle)
{
    const char *string_str = "string";
    const char *int_str = "int";
    const char *float_str = "float";
    const char *bool_str = "bool";
    const char *time_str = "time";
    const char *objlink_str = "objlink";

    Lwm2mResourceType resource_type = LWM2M_OPAQUE; // OPAQUE default
    json_t *resource_type_obj = json_object_get(resource_dict_handle, "type");
    if (resource_type_obj != NULL) {
        const char *resource_type_s = json_string_value(resource_type_obj);
        if (resource_type_s != NULL) {
            if (strncmp(resource_type_s, string_str, strlen(string_str)) == 0) {
                resource_type = LWM2M_STRING;
            } else if (strncmp(resource_type_s, int_str, strlen(int_str)) == 0) {
                resource_type = LWM2M_INTEGER;
            } else if (strncmp(resource_type_s, float_str, strlen(float_str)) == 0) {
                resource_type = LWM2M_FLOAT;
            } else if (strncmp(resource_type_s, bool_str, strlen(bool_str)) == 0) {
                resource_type = LWM2M_BOOLEAN;
            } else if (strncmp(resource_type_s, time_str, strlen(time_str)) == 0) {
                resource_type = LWM2M_TIME;
            } else if (strncmp(resource_type_s, objlink_str, strlen(objlink_str)) == 0) {
                resource_type = LWM2M_OBJLINK;
            }
        }
    }
    return resource_type;
}

pt_api_result_code_e update_json_device_objects(json_t *json_structure,
                                                pt_mode_e mode,
                                                struct connection *connection,
                                                const char *device_id_val,
                                                const char **error_detail)
{
    uint8_t *resource_value = NULL;
    int object_id;
    int object_instance_id;
    int resource_id;

    pt_api_result_code_e ret = PT_API_SUCCESS;
    // Get handle to objects array
    json_t *object_array_handle = json_object_get(json_structure, "objects");

    // This code support to create devices without the objects key and the objects array can be empty too.
    size_t object_count = json_array_size(object_array_handle);
    tr_debug("JSON parsed object count = %lu\r\n", object_count);
    for (size_t object_index = 0; object_index < object_count; object_index++) {
        if (ret != PT_API_SUCCESS) {
            break;
        }
        // Get handle to object
        json_t *object_dict_handle = json_array_get(object_array_handle, object_index);
        // And get object-id
        json_t *object_id_handle = json_object_get(object_dict_handle, "object-id");
        if (!object_id_handle) {
            ret = PT_API_INVALID_JSON_STRUCTURE;
            *error_detail = "Invalid or missing object-id key.";
            tr_error("%s", *error_detail);
            break;
        }
        object_id = json_integer_value(object_id_handle);
        tr_debug("JSON parsed object, id = %d\r\n", object_id);
        // Get handle to object-instance array
        json_t *object_instance_array_handle = json_object_get(object_dict_handle, "object-instances");
        size_t object_instance_count = json_array_size(object_instance_array_handle);
        tr_debug("JSON parsed object instance count = %lu\r\n", object_instance_count);
        for (size_t object_instance_index = 0; object_instance_index < object_instance_count; object_instance_index++) {
            if (ret != PT_API_SUCCESS) {
                break;
            }
            // Get handle to object instance
            json_t *instance_dict_handle = json_array_get(object_instance_array_handle, object_instance_index);
            // And get object-instance-id
            json_t *instance_id_handle = json_object_get(instance_dict_handle, "object-instance-id");
            if (!instance_id_handle) {
                *error_detail = "Invalid or missing object-instance-id key.";
                tr_error("%s", *error_detail);
                ret = PT_API_INVALID_JSON_STRUCTURE;
                break;
            }
            object_instance_id = json_integer_value(instance_id_handle);

            tr_debug("JSON parsed object instance, id = %d\r\n", object_instance_id);
            // Get handle to resource array
            json_t *resource_array_handle = json_object_get(instance_dict_handle, "resources");
            size_t resource_count = json_array_size(resource_array_handle);
            tr_debug("JSON parsed resource count = %lu\r\n", resource_count);
            for (size_t resource_index = 0; resource_index < resource_count; resource_index++) {
                // Get handle to object instance
                json_t *resource_dict_handle = json_array_get(resource_array_handle, resource_index);
                // And get object-instance-id
                json_t *resource_id_handle = json_object_get(resource_dict_handle, "item-id");
                if (!resource_id_handle) {
                    *error_detail = "Invalid or missing resource item-id key.";
                    tr_error("%s", *error_detail);
                    ret = PT_API_INVALID_JSON_STRUCTURE;
                    break;
                }
                resource_id = json_integer_value(resource_id_handle);

                tr_debug("JSON parsed resource, id = %d\r\n", resource_id);
                json_t *resource_value_handle = json_object_get(resource_dict_handle, "value");
                uint32_t decoded_len = 0;
                if (resource_value_handle) {
                    const char *resource_value_encoded = json_string_value(resource_value_handle);

                    uint32_t decoded_len_max = apr_base64_decode_len(resource_value_encoded);
                    resource_value = (uint8_t *) malloc(decoded_len_max);
                    decoded_len = apr_base64_decode_binary((unsigned char *) resource_value, resource_value_encoded);
                    assert(decoded_len_max >= decoded_len);
                }
                Lwm2mResourceType resource_type = resource_type_from_json_handle(resource_dict_handle);
                int opr = json_integer_value(json_object_get(resource_dict_handle, "operations"));
                if (mode == PT_MODE_PRETEND) {
                    bool value_ok = edgeclient_verify_value(resource_value, decoded_len, resource_type);
                    if (!value_ok) {
                        ret = PT_API_ILLEGAL_VALUE;
                        break;
                    }
                } else {
                    pt_api_result_code_e set_resource_status = edgeclient_set_resource_value(device_id_val,
                                                                                            object_id,
                                                                                            object_instance_id,
                                                                                            resource_id,
                                                                                            resource_value,
                                                                                            decoded_len,
                                                                                            resource_type,
                                                                                            opr,
                                                                                            connection);
                    if (set_resource_status == PT_API_SUCCESS) {
                        tr_info("set_resource_value /d/%s/%d/%d/%d (type=%ud, operation=%d)",
                                device_id_val,
                                object_id,
                                object_instance_id,
                                resource_id,
                                resource_type,
                                opr);
                    } else {
                        tr_error("Could not set resource value /d/%s/%d/%d/%d (type=%ud, operation=%d)",
                                device_id_val, object_id, object_instance_id,
                            resource_id, resource_type, opr);
                            ret = set_resource_status;
                            break;
                    }
                }
                free(resource_value);
                resource_value = NULL;
            }
        }
    }
    if (resource_value) {
        free(resource_value);
    }
    return ret;
}

static pt_api_result_code_e update_device_values_from_json(json_t *json_structure,
                                                           struct connection *connection,
                                                           const char **error_detail,
                                                           pt_update_device_values_flags_e flags)
/** \return PT_API_SUCCESS - success
 *          something else - error
 */
{
    pt_api_result_code_e ret = PT_API_SUCCESS; // return value of the function
    // Get the device id
    json_t *device_id_handle = json_object_get(json_structure, "device-id");
    if (!device_id_handle) {
        tr_error("Invalid device-id field");
        return JSONRPC_INVALID_PARAMS;
    }
    const char *device_id_val = json_string_value(device_id_handle);

    tr_debug("JSON parsed endpoint, name = %s\r\n", device_id_val);
    if (!edgeclient_endpoint_exists(device_id_val)) {
        tr_debug("Endpoint doesn't exist, lets create it...");
        if (!edgeclient_add_endpoint(device_id_val, connection)) {
            tr_error("Could not create endpoint.");
            return PT_API_INTERNAL_ERROR;
        }
        else {
            tr_debug("Endpoint created.");
        }
    }
    else {
        tr_debug("Endpoint already existed.");
        if (flags & PT_UPDATE_FLAGS_FAIL_IF_DEVICE_EXISTS) {
            *error_detail = "The endpoint was already registered.";
            tr_error("%s", *error_detail);
            return PT_API_ENDPOINT_ALREADY_REGISTERED;
        }
    }

    // First pass is done to verify that values are valid.
    ret = update_json_device_objects(json_structure, PT_MODE_PRETEND, connection, device_id_val, error_detail);
    if (ret == PT_API_SUCCESS) {
        // The 2nd pass is done to actually write the values.
        ret = update_json_device_objects(json_structure, PT_MODE_REAL, connection, device_id_val, error_detail);
        edgeclient_update_register_conditional(EDGECLIENT_LOCK_MUTEX);
    }
    return ret;
}

static void handle_write_to_pt_success(json_t *response, void *userdata)
{
    tr_debug("Handling write to protocol translator success");
    edgeclient_request_context_t *ctx = (edgeclient_request_context_t*) userdata;
    ctx->success_handler(ctx);
}

static void handle_write_to_pt_failure(json_t *response, void* userdata)
{
    tr_debug("Handling write to protocol translator failure");
    edgeclient_request_context_t *ctx = (edgeclient_request_context_t*) userdata;
    ctx->failure_handler(ctx);
}

/*
 * This is called after either handle_write_to_pt_success or
 * handle_write_to_pt_failure callback is called. See write_to_pt.
 */
static void pt_write_free_func(void* userdata)
{
    tr_debug("Handling write to protocol translator free operations. Nothing to do.");
}

/*
 * The below function handles writing messages to protocol translator
 */
int write_to_pt(edgeclient_request_context_t *request_ctx, void *userdata)
{
    if (!request_ctx) {
        tr_error("Request context was NULL.");
        return 1;
    }

    if (request_ctx->device_id == NULL) {
        tr_error("No device id set for write context");
        return 1;
    }

    tr_debug("uri is '%s/%d/%d/%d'",
             request_ctx->device_id,
             request_ctx->object_id,
             request_ctx->object_instance_id,
             request_ctx->resource_id);

    if (request_ctx->operation & OPERATION_WRITE) {
        if (request_ctx->value == NULL) {
            tr_debug("Operation is WRITE and value to update is NULL. Abort value write.");
            return 1;
        }

        if (request_ctx->value_len == 0) {
            tr_debug("Operation is WRITE and value length is 0. Abort value write.");
            return 1;
        }
    }

    /*
     * Connection must be passed in the userdata to know which protocol translator is the
     * correct one to send the message.
     */
    struct connection *connection = (struct connection*) userdata;

    json_t *request = allocate_base_request("write");
    json_t *params = json_object_get(request, "params");

    json_t *uri_obj = json_object();
    json_object_set_new(uri_obj, "device-id", json_string(request_ctx->device_id));
    json_object_set_new(uri_obj, "object-id", json_integer(request_ctx->object_id));
    json_object_set_new(uri_obj, "object-instance-id", json_integer(request_ctx->object_instance_id));
    json_object_set_new(uri_obj, "resource-id", json_integer(request_ctx->resource_id));
    json_object_set(params, "uri", uri_obj);
    json_decref(uri_obj);

    json_object_set_new(params, "operation", json_integer(request_ctx->operation));

    tr_debug("write_to_pt - base64 encoding the value to json object");
    size_t out_size = 0;
    int32_t ret_val = mbedtls_base64_encode(NULL, 0, &out_size, request_ctx->value, request_ctx->value_len);
    if (0 != ret_val && MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL != ret_val) {
        tr_error("cannot estimate the size of encoded value - %d", ret_val);
        return 1;
    }
    unsigned char *json_value = NULL;
    if (out_size == 0) {
        // Allocate just an empty string. This signifies no data.
        json_value = (unsigned char *) calloc(1, 1);
    } else {
        json_value = (unsigned char *) calloc(1, out_size);
    }
    if (!json_value) {
        tr_error("allocating value base64 buffer failed");
        return 1;
    }
    if (out_size != 0) {
        if (0 != mbedtls_base64_encode(json_value, out_size, &out_size, request_ctx->value, request_ctx->value_len)) {
            ret_val = 1;
            goto write_to_pt_cleanup;
        }
    }
    if (json_object_set_new(params, "value", json_string((const char *) json_value))) {
        tr_error("Could not write value to json object");
        ret_val = 1;
        goto write_to_pt_cleanup;
    }

    ret_val = edge_common_construct_and_send_message(connection,
                                                     request,
                                                     handle_write_to_pt_success,
                                                     handle_write_to_pt_failure,
                                                     pt_write_free_func,
                                                     request_ctx);

write_to_pt_cleanup:
    // json_string makes a copy of json_value above.
    free(json_value);

    return ret_val;
}
