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

#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <jansson.h>
#include <assert.h>

#include "edge-core/grm_api_internal.h"

#include "jsonrpc/jsonrpc.h"
#include "edge-rpc/rpc.h"
#include "edge-client/edge_client.h"
#include "common/apr_base64.h"
#include "common/default_message_id_generator.h"
#include "edge-core/server.h"
#include "edge-core/edge_server.h"
#include "edge-core/srv_comm.h"
#include "lib/ssl-platform/ssl_platform.h"
#include "common/pt_api_error_parser.h"

#include "ns_list.h"
#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP "grm"

struct jsonrpc_method_entry_t grm_method_table[] = {
    { "gw_resource_manager_register", gw_resource_manager_register, "o" },
    { "add_resource", add_resource, "o" },
    { "write_resource_value", write_resource_value, "o" },
    { NULL, NULL, "o" }
};

typedef enum {
    GRM_ALREADY_REGISTERED,
    GRM_NOT_REGISTERED
} grm_registration_status_e;

typedef enum {
    GRM_MODE_ADD,
    GRM_MODE_UPDATE
} grm_mode_e;

static int update_json_gateway_objects(json_t *structure,
                                          grm_mode_e mode,
                                          struct connection *connection,
                                          const char **error_detail);

int write_to_grm(edgeclient_request_context_t *request_ctx);

extern const char *pt_api_get_error_message(pt_api_result_code_e code);

static grm_registration_status_e get_grm_registration_status(struct connection *connection)
{
    tr_debug("get_grm_registration_status");

    if (connection->client_data->registered) {
        return GRM_ALREADY_REGISTERED;
    }
    return GRM_NOT_REGISTERED;
}

static bool is_grm_registered(const char* name_val, const struct ctx_data *ctx_data)
{
    ns_list_foreach(const struct connection_list_elem, cur, &ctx_data->registered_translators) {
        if (strcmp(cur->conn->client_data->name, name_val) == 0) {
            return true;
        }
    }
    return false;
}

/**
 * \brief Checks if the request id is in the JSON request.
 * \return true  - request id is found
 *         false - request id is missing
 */
bool grm_api_check_request_id(struct json_message_t *jt)
{
    json_error_t error;
    json_t *full_request = json_loadb(jt->data, jt->len, 0, &error);
    json_t *id_obj = json_object_get(full_request, "id");
    json_decref(full_request);

    bool id_found = true;
    if (id_obj == NULL) {
        id_found = false;
    }
    json_decref(id_obj);

    return id_found;
}

/**
 * \brief Checks if service edge core is available or shutting down.
 *
 * \param result The jsonrpc result object to fill.
 * \return true  if service is available.
 *         false if service is unavailable
 */
bool grm_api_check_service_availability(json_t **result)
{
    if (edgeclient_is_shutting_down()) {
        *result = jsonrpc_error_object(PT_API_EDGE_CORE_SHUTTING_DOWN,
                                       pt_api_get_error_message(PT_API_EDGE_CORE_SHUTTING_DOWN),
                                       json_string("Service unavailable, because the server is shutting down"));
        return false;
    }
    return true;
}

/** \return 0 - success
 *          1 - failure
 */
int gw_resource_manager_register(json_t *request, json_t *json_params, json_t **result, void *userdata)
{
    struct json_message_t *jt = (struct json_message_t*) userdata;
    struct connection *connection = jt->connection;
    struct ctx_data *ctx_data = connection->ctx->ctx_data;

    if (!grm_api_check_service_availability(result)) {
        return 1;
    }

    if (!grm_api_check_request_id(jt)) {
        tr_err("No id_obj on gw resource manager registration request: \"%s\"", jt->data);
        *result = jsonrpc_error_object_predefined(
                JSONRPC_INVALID_PARAMS, json_string("gw resource manager registration failed. Request id missing."));
        connection->connected = false;
        return 1;
    }
    grm_registration_status_e status = get_grm_registration_status(connection);
    if (status == GRM_NOT_REGISTERED) {
        tr_info("Registering gw resource manager.");
        json_t *name_obj = json_object_get(json_params, "name");
        const char *name_val = json_string_value(name_obj);

        if (!name_obj) {
            tr_err("gw_resource_manager_register 'name' key not found");
            *result = jsonrpc_error_object_predefined(JSONRPC_INVALID_PARAMS,
                                                      json_string("Key 'name' missing"));
            connection->connected = false;
            return 1;
        }
        else if (!name_val || strnlen(name_val, 10) == 0) {
            tr_err("gw_resource_manager_register: No value for key 'name'");
            *result = jsonrpc_error_object_predefined(
                    JSONRPC_INVALID_PARAMS, json_string("Value for key 'name' missing or empty"));
            connection->connected = false;
            return 1;
        } else if (!is_grm_registered(name_val, ctx_data)) {
            char *name = malloc(sizeof(char) * strlen(name_val) + 1);
            int new_grm_id = 0;

            strncpy(name, name_val, strlen(name_val) + 1);
            connection->client_data->name = name;
            connection->client_data->registered = true;
            if (ns_list_count(&ctx_data->registered_translators) > 0) {
                struct connection_list_elem *last_grm = ns_list_get_last(&ctx_data->registered_translators);
                int last_grm_id = last_grm->conn->client_data->id;
                new_grm_id = last_grm_id + 1;
            }
            connection->client_data->id = new_grm_id;

            struct connection_list_elem *new_translator = calloc(1, sizeof(struct connection_list_elem));
            new_translator->conn = connection;
            ns_list_add_to_end(&ctx_data->registered_translators, new_translator);
            tr_info("Registered gw resource manager '%s'", name);

            *result = json_string("ok");
            return 0;
        } else {
            tr_warn("gw resource manager name already reserved.");

            struct connection_list_elem *not_accepted_translator = calloc(1, sizeof(struct connection_list_elem));
            not_accepted_translator->conn = connection;
            ns_list_add_to_end(&ctx_data->not_accepted_translators, not_accepted_translator);

            *result = jsonrpc_error_object(GRM_API_RESOURCE_MANAGER_NAME_RESERVED,
                                           pt_api_get_error_message(GRM_API_RESOURCE_MANAGER_NAME_RESERVED),
                                           json_string("Cannot register the gw resource manager."));
            connection->connected = false;
            return 1;
        }
    }
    /* GRM_API_RESOURCE_MANAGER_ALREADY_REGISTERED */
    tr_warn("gw resource manager already registered.");
    *result = jsonrpc_error_object(GRM_API_RESOURCE_MANAGER_ALREADY_REGISTERED,
                                   pt_api_get_error_message(GRM_API_RESOURCE_MANAGER_ALREADY_REGISTERED),
                                   json_string("Already registered."));
    connection->connected = false;
    return 1;
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

/** \return 0 - success
 *          1 - failure
 */
int add_resource(json_t *request, json_t *json_params, json_t **result, void *userdata)
{
    struct json_message_t *jt = (struct json_message_t*) userdata;
    struct connection* connection = jt->connection;
    tr_debug("Add gateway resource.");

    if (!grm_api_check_service_availability(result)) {
        return 1;
    }

    if (!grm_api_check_request_id(jt)) {
        tr_warn("Adding gateway resource failed. No request id was given");
        *result = jsonrpc_error_object_predefined(JSONRPC_INVALID_PARAMS,
                                                  json_string("Adding gateway resource failed. No request id was given."));
        return 1;
    }

    // Not registered
    if (get_grm_registration_status(connection) !=
            GRM_ALREADY_REGISTERED) {
        *result = jsonrpc_error_object(GRM_API_RESOURCE_MANAGER_NOT_REGISTERED,
                                       pt_api_get_error_message(GRM_API_RESOURCE_MANAGER_NOT_REGISTERED),
                                       json_string("Failed to add gateway resource."));
        return 1;
    }

    const char *error_detail = NULL;
    pt_api_result_code_e result_code = update_json_gateway_objects(json_params,
                                                                      GRM_MODE_ADD,
                                                                      connection,
                                                                      &error_detail);

    if (result_code != PT_API_SUCCESS) {
        tr_error("Adding gateway resource failed.");
        *result = create_detailed_error_object(result_code, "Failed to add gateway resource.", error_detail);
        return 1;
    }
    *result = json_string("ok");
    tr_info("Added gateway resource successfully.");
    edgeclient_update_register_conditional();
    return 0;
}

/** \return 0 - success
 *          1 - failure
 */
int write_resource_value(json_t *request, json_t *json_params, json_t **result, void *userdata)
{
    struct json_message_t *jt = (struct json_message_t*) userdata;
    struct connection *connection = jt->connection;
    tr_debug("Write resource value.");
    if (!grm_api_check_service_availability(result)) {
        return 1;
    }
    if (get_grm_registration_status(connection) != GRM_ALREADY_REGISTERED) {
        tr_warn("Write value failed. gw resource manager not registered");
        *result = jsonrpc_error_object(GRM_API_RESOURCE_MANAGER_NOT_REGISTERED,
                                       pt_api_get_error_message(GRM_API_RESOURCE_MANAGER_NOT_REGISTERED),
                                       json_string("Write value failed. gw resource manager not registered."));
        return 1;
    }
    if (!grm_api_check_request_id(jt)) {
        tr_warn("Write value failed. No request id was given");
        *result = jsonrpc_error_object_predefined(JSONRPC_INVALID_PARAMS,
                                                  json_string("Write value failed. No request id was given."));
        return 1;
    }
    const char *error_detail = NULL;
    pt_api_result_code_e ret = update_json_gateway_objects(json_params,
                                                              GRM_MODE_UPDATE,
                                                              connection,
                                                              &error_detail);
    if (ret != PT_API_SUCCESS) {
        tr_warn("Write value failed. Failed to update device values from json.");
        *result = create_detailed_error_object(
                ret, "Write gsr value failed. Failed to update device values from json.", error_detail);
        return 1;
    }
    tr_info("Write value succeeded");
    *result = json_string("ok");
    /* NOTE edgeclient_update_register_conditional not required here since
    * we don't call anything else than update_json_gateway_objects
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

static pt_api_result_code_e update_json_gateway_objects(json_t *json_structure,
                                                grm_mode_e mode,
                                                struct connection *connection,
                                                const char **error_detail)
{
    uint8_t *resource_value = NULL;
    int object_id;
    int object_instance_id;
    int resource_id;

    pt_api_result_code_e ret = PT_API_SUCCESS;
    // Get handle to objects array
    json_t *object_array_handle = json_object_get(json_structure, "objects");
    if (!object_array_handle) {
        ret = PT_API_INVALID_JSON_STRUCTURE;
        *error_detail = "Missing objects key.";
        tr_error("%s", *error_detail);
        return ret;
    }

    // This code support to create devices without the objects key and the objects array can be empty too.
    size_t object_count = json_array_size(object_array_handle);
    tr_debug("JSON parsed object count = %zu", object_count);
    if(object_count == 0) {
        ret = PT_API_INVALID_JSON_STRUCTURE;
        *error_detail = "Invalid objects key value.";
        tr_error("%s", *error_detail);
        return ret;
    }

    for (size_t object_index = 0; object_index < object_count; object_index++) {
        if (ret != PT_API_SUCCESS) {
            break;
        }
        // Get handle to object
        json_t *object_dict_handle = json_array_get(object_array_handle, object_index);
        // And get objectId
        json_t *object_id_handle = json_object_get(object_dict_handle, "objectId");
        if (!object_id_handle) {
            ret = PT_API_INVALID_JSON_STRUCTURE;
            *error_detail = "Invalid or missing objectId key.";
            tr_error("%s", *error_detail);
            break;
        }
        object_id = json_integer_value(object_id_handle);
        tr_debug("JSON parsed object, id = %d", object_id);

        // All default/reserved objects in edge-core should not be overwritten.
        if (object_id == 1
            || object_id == 3
            || object_id == 14
            || object_id == 10252
            || object_id == 10255
            || object_id == 26241
            || object_id == 35011) {
            ret = GRM_API_OBJECT_RESERVED;
            *error_detail = "Invalid objectId key, reserved.";
            tr_error("%s", *error_detail);
            break;
        }
        // Get handle to objectInstance array
        json_t *object_instance_array_handle = json_object_get(object_dict_handle, "objectInstances");
        if (!object_instance_array_handle) {
            ret = PT_API_INVALID_JSON_STRUCTURE;
            *error_detail = "Missing objectInstances key.";
            tr_error("%s", *error_detail);
            return ret;
        }

        size_t object_instance_count = json_array_size(object_instance_array_handle);
        tr_debug("JSON parsed object instance count = %zu", object_instance_count);
        if(object_instance_count == 0) {
            ret = PT_API_INVALID_JSON_STRUCTURE;
            *error_detail = "Invalid objectInstances key value.";
            tr_error("%s", *error_detail);
            return ret;
        }

        for (size_t object_instance_index = 0; object_instance_index < object_instance_count; object_instance_index++) {
            if (ret != PT_API_SUCCESS) {
                break;
            }
            // Get handle to object instance
            json_t *instance_dict_handle = json_array_get(object_instance_array_handle, object_instance_index);
            // And get objectInstanceId
            json_t *instance_id_handle = json_object_get(instance_dict_handle, "objectInstanceId");
            if (!instance_id_handle) {
                *error_detail = "Invalid or missing objectInstanceId key.";
                tr_error("%s", *error_detail);
                ret = PT_API_INVALID_JSON_STRUCTURE;
                break;
            }
            object_instance_id = json_integer_value(instance_id_handle);

            tr_debug("JSON parsed object instance, id = %d", object_instance_id);
            // Get handle to resource array
            json_t *resource_array_handle = json_object_get(instance_dict_handle, "resources");
            if (!resource_array_handle) {
                ret = PT_API_INVALID_JSON_STRUCTURE;
                *error_detail = "Missing resources key.";
                tr_error("%s", *error_detail);
                return ret;
            }

            size_t resource_count = json_array_size(resource_array_handle);
            tr_debug("JSON parsed resource count = %zu", resource_count);
            if(resource_count == 0) {
                ret = PT_API_INVALID_JSON_STRUCTURE;
                *error_detail = "Invalid resources key value.";
                tr_error("%s", *error_detail);
                return ret;
            }

            for (size_t resource_index = 0; resource_index < resource_count; resource_index++) {
                // Get handle to resource
                json_t *resource_dict_handle = json_array_get(resource_array_handle, resource_index);
                // And get resourceId
                json_t *resource_id_handle = json_object_get(resource_dict_handle, "resourceId");
                if (!resource_id_handle) {
                    *error_detail = "Invalid or missing resource resourceId key.";
                    tr_error("%s", *error_detail);
                    ret = PT_API_INVALID_JSON_STRUCTURE;
                    break;
                }
                resource_id = json_integer_value(resource_id_handle);

                tr_debug("JSON parsed resource, id = %d", resource_id);

                // Get resourceName
                json_t *resource_name_handle = json_object_get(resource_dict_handle, "resourceName");
                const char *resource_name = json_string_value(resource_name_handle);
                if (resource_name) {
                    tr_debug("JSON parsed resource, name = %s", resource_name);
                }

                json_t *resource_value_handle = json_object_get(resource_dict_handle, "value");
                uint32_t decoded_len = 0;
                if (resource_value_handle) {
                    const char *resource_value_encoded = json_string_value(resource_value_handle);
                    if (resource_value_encoded == NULL) {
                        *error_detail = "Message value is not a string.";
                        tr_error("%s", *error_detail);
                        ret = PT_API_ILLEGAL_VALUE;
                        break;
                    }

                    uint32_t decoded_len_max = apr_base64_decode_len(resource_value_encoded);
                    resource_value = (uint8_t *) malloc(decoded_len_max);
                    decoded_len = apr_base64_decode_binary((unsigned char *) resource_value, resource_value_encoded);
                    assert(decoded_len_max >= decoded_len);
                }
                if(mode == GRM_MODE_ADD) {
                    if(edgeclient_resource_exists(NULL, object_id, object_instance_id, resource_id)) {
                        tr_debug("Resource already existed.");
                        *error_detail = "The resource already exists.";
                        tr_error("%s", *error_detail);
                        return GRM_API_RESOURCE_AlREADY_EXISTS;
                    }
                }

                Lwm2mResourceType resource_type = resource_type_from_json_handle(resource_dict_handle);
                int opr = json_integer_value(json_object_get(resource_dict_handle, "operations"));
                bool value_ok = edgeclient_verify_value(resource_value, decoded_len, resource_type);
                if (!value_ok) {
                    ret = PT_API_ILLEGAL_VALUE;
                    break;
                } else {
                    pt_api_result_code_e set_resource_status = edgeclient_set_resource_value(NULL,
                                                                                            object_id,
                                                                                            object_instance_id,
                                                                                            resource_id,
                                                                                            resource_name,
                                                                                            resource_value,
                                                                                            decoded_len,
                                                                                            resource_type,
                                                                                            opr,
                                                                                            connection);
                    if (set_resource_status == PT_API_SUCCESS) {
                        tr_info("set_resource_value /%d/%d/%d (type=%ud, operation=%d)",
                                object_id,
                                object_instance_id,
                                resource_id,
                                resource_type,
                                opr);
                    } else {
                        tr_error("Could not set resource value /%d/%d/%d (type=%ud, operation=%d)",
                            object_id, object_instance_id,
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

static void handle_write_value_to_grm_success(json_t *response, void *userdata)
{
    tr_debug("Handling write value to grm success");
    edgeclient_request_context_t *ctx = (edgeclient_request_context_t*) userdata;
    ctx->success_handler(ctx);
}

static void handle_write_value_to_grm_failure(json_t *response, void* userdata)
{
    tr_debug("Handling write value to grm failure");
    edgeclient_request_context_t *ctx = (edgeclient_request_context_t*) userdata;
    pt_api_error_parser_parse_error_response(response, ctx);
    ctx->failure_handler(ctx);
}

/*
 * This is called after either handle_write_value_to_grm_success or
 * handle_write_value_to_grm_failure callback is called. See write_value_to_grm.
 */
static void write_to_grm_free_func(rpc_request_context_t *userdata)
{
    (void) userdata;
    tr_debug("Handling write to grm free operations. Nothing to do.");
}

/*
 * The below function handles writing messages to gw resource manager
 */
int write_to_grm(edgeclient_request_context_t *request_ctx)
{
    if (!request_ctx) {
        tr_error("Request context was NULL.");
        return 1;
    }

    tr_debug("uri is '%d/%d/%d'",
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
     * Connection must be passed in the userdata to know which gw resource manager is the
     * correct one to send the message.
     */
    struct connection *connection = (struct connection*) request_ctx->connection;

    json_t *request = allocate_base_request("write");
    json_t *params = json_object_get(request, "params");

    json_t *uri_obj = json_object();
    json_object_set_new(uri_obj, "objectId", json_integer(request_ctx->object_id));
    json_object_set_new(uri_obj, "objectInstanceId", json_integer(request_ctx->object_instance_id));
    json_object_set_new(uri_obj, "resourceId", json_integer(request_ctx->resource_id));
    json_object_set(params, "uri", uri_obj);
    json_decref(uri_obj);

    json_object_set_new(params, "operation", json_integer(request_ctx->operation));

    tr_debug("write_value_to_grm - base64 encoding the value to json object");
    size_t out_size = 0;
    int32_t ret_val = ssl_platform_base64_encode(NULL, 0, &out_size, request_ctx->value, request_ctx->value_len);
    if (0 != ret_val && SSL_PLATFORM_ERROR_BUFFER_TOO_SMALL != ret_val) {
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
        if (0 != ssl_platform_base64_encode(json_value, out_size, &out_size, request_ctx->value, request_ctx->value_len)) {
            tr_error("Could not encode value to base64.");
            ret_val = 1;
            goto write_value_to_grm_cleanup;
        }
    }
    if (json_object_set_new(params, "value", json_string((const char *) json_value))) {
        tr_error("Could not write value to json object");
        ret_val = 1;
        goto write_value_to_grm_cleanup;
    }

    ret_val = rpc_construct_and_send_message(connection,
                                             request,
                                             handle_write_value_to_grm_success,
                                             handle_write_value_to_grm_failure,
                                             write_to_grm_free_func,
                                             (rpc_request_context_t *) request_ctx,
                                             connection->transport_connection->write_function);

write_value_to_grm_cleanup:
    // json_string makes a copy of json_value above.
    free(json_value);

    return ret_val;
}
