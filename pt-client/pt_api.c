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
#define _GNU_SOURCE 1 // needed for strndup
#endif
#include <event2/bufferevent.h>
#include <jansson.h>
#include <string.h>
#include <assert.h>

#include "pt-client/pt_api.h"

#include "edge-rpc/rpc.h"
#include "common/test_support.h"
#include "pt-client/pt_api_internal.h"
#include "common/apr_base64.h"

#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP "clnt"

struct pt_customer_callback *allocate_customer_callback(connection_t *connection,
                                                        pt_response_handler success_handler,
                                                        pt_response_handler failure_handler,
                                                        void *userdata)
{
    struct pt_customer_callback *customer_callback =
        (struct pt_customer_callback *)malloc(sizeof(struct pt_customer_callback));
    if (customer_callback == NULL) {
        tr_err("Error could not allocate pt_customer_callback struct.");
        return NULL;
    }
    customer_callback->connection = connection;
    customer_callback->success_handler = success_handler;
    customer_callback->failure_handler = failure_handler;
    customer_callback->userdata = userdata;
    return customer_callback;
}

EDGE_LOCAL struct pt_device_customer_callback *allocate_device_customer_callback(
        connection_t *connection,
        pt_device_response_handler success_handler,
        pt_device_response_handler failure_handler,
        const char *device_id,
        void *userdata)
{
    struct pt_device_customer_callback *customer_callback =
        (struct pt_device_customer_callback *)malloc(sizeof(struct pt_device_customer_callback));
    if (customer_callback == NULL) {
        tr_err("Error could not allocate pt_device_customer_callback struct.");
        return NULL;
    }
    customer_callback->connection = connection;
    customer_callback->success_handler = success_handler;
    customer_callback->failure_handler = failure_handler;
    customer_callback->userdata = userdata;
    customer_callback->device_id = NULL;
    if(success_handler && failure_handler) {
        customer_callback->device_id = strndup(device_id, strlen(device_id));
    }
    return customer_callback;
}

void customer_callback_free(struct pt_customer_callback *customer_callback)
{
    free(customer_callback);
}

void device_customer_callback_free(struct pt_device_customer_callback *customer_callback)
{
    if(customer_callback->device_id) {
        free(customer_callback->device_id);
    }
    free(customer_callback);
}

EDGE_LOCAL void customer_callback_free_func(rpc_request_context_t *callback_data)
{
    struct pt_customer_callback *customer_callback = (struct pt_customer_callback*) callback_data;
    customer_callback_free(customer_callback);
}

EDGE_LOCAL void device_customer_callback_free_func(rpc_request_context_t *callback_data)
{
    struct pt_device_customer_callback *customer_callback = (struct pt_device_customer_callback *) callback_data;
    device_customer_callback_free(customer_callback);
}

EDGE_LOCAL void pt_handle_pt_register_success(json_t *response, void *callback_data)
{
    tr_debug("Handling register success.");
    struct pt_device_customer_callback *customer_callback = (struct pt_device_customer_callback *) callback_data;
    connection_t *connection = customer_callback->connection;
    connection->client_data->registered = true;

    if (callback_data) {
        struct pt_customer_callback *customer_callback = (struct pt_customer_callback*) callback_data;
        customer_callback->success_handler(customer_callback->userdata);
    }
}

EDGE_LOCAL void pt_handle_pt_register_failure(json_t *response, void *callback_data)
{
    tr_debug("Handling register failure.");
    struct pt_device_customer_callback *customer_callback = (struct pt_device_customer_callback *) callback_data;
    connection_t *connection = customer_callback->connection;
    connection->client_data->registered = false;
    // FIXME: handle registration failure connection close gracefully elsewhere
    //edge_common_write_stop_frame(connection);

    if (callback_data) {
        struct pt_customer_callback *customer_callback = (struct pt_customer_callback*) callback_data;
        customer_callback->failure_handler(customer_callback->userdata);
    }
}

EDGE_LOCAL void pt_handle_device_register_success(json_t *response, void *callback_data)
{
    tr_debug("Handling device register success.");
    if (callback_data) {
        struct pt_device_customer_callback *customer_callback = (struct pt_device_customer_callback*) callback_data;
        customer_callback->success_handler(customer_callback->device_id, customer_callback->userdata);
    }
}

EDGE_LOCAL void pt_handle_device_register_failure(json_t *response, void *callback_data)
{
    tr_debug("Handling device register failure.");
    if (callback_data) {
        struct pt_device_customer_callback *customer_callback = (struct pt_device_customer_callback*) callback_data;
        customer_callback->failure_handler(customer_callback->device_id, customer_callback->userdata);
    }
}

EDGE_LOCAL void pt_handle_device_unregister_success(json_t *response, void *callback_data)
{
    tr_debug("Handling device unregister success.");
    if (callback_data) {
        struct pt_device_customer_callback *customer_callback = (struct pt_device_customer_callback*) callback_data;
        customer_callback->success_handler(customer_callback->device_id, customer_callback->userdata);
    }
}

EDGE_LOCAL void pt_handle_device_unregister_failure(json_t *response, void *callback_data)
{
    tr_debug("Handling device unregister failure.");
    if (callback_data) {
        struct pt_device_customer_callback *customer_callback = (struct pt_device_customer_callback*) callback_data;
        customer_callback->failure_handler(customer_callback->device_id, customer_callback->userdata);
    }
}

EDGE_LOCAL pt_status_t write_data_frame(json_t *message,
                                        rpc_response_handler success_handler,
                                        rpc_response_handler failure_handler,
                                        rpc_free_func free_func,
                                        void *callback_data)
{
    struct pt_device_customer_callback *customer_callback = (struct pt_device_customer_callback*) callback_data;
    connection_t *connection = customer_callback->connection;

    if (!customer_callback->connection->connected) {
        tr_warn("Not connected, discarding write.");
        json_decref(message);
        return PT_STATUS_NOT_CONNECTED;
    }

    int32_t ret_val = rpc_construct_and_send_message(connection,
                                                     message,
                                                     success_handler,
                                                     failure_handler,
                                                     free_func,
                                                     (rpc_request_context_t *) customer_callback,
                                                     connection->transport_connection->write_function);

    if (ret_val == -1) {
        return PT_STATUS_ALLOCATION_FAIL;
    }
    else if (ret_val != 0) {
        return PT_STATUS_ERROR;
    }
    return PT_STATUS_SUCCESS;
}

pt_status_t pt_register_protocol_translator(connection_t *connection,
                                            pt_response_handler success_handler,
                                            pt_response_handler failure_handler,
                                            void *userdata)
{
    if (connection == NULL || connection->client_data == NULL) {
        tr_warn("No connection or protocol translator instantiated.");
        return PT_STATUS_ERROR;
    }
    if (!connection->client_data->name || strlen(connection->client_data->name) == 0) {
        tr_warn("No protocol translator name set.");
        return PT_STATUS_ERROR;
    }

    if (connection->client_data->registered) {
        tr_warn("Already registered, not able to do duplicate registration.");
        return PT_STATUS_ERROR;
    }
    tr_info("Registering protocol translator '%s' in pt_api.", connection->client_data->name);
    json_t *register_msg = allocate_base_request("protocol_translator_register");
    json_t *params = json_object_get(register_msg, "params");
    json_t *name = json_string(connection->client_data->name);
    struct pt_customer_callback *customer_callback =
        allocate_customer_callback(connection, success_handler, failure_handler, userdata);
    if (register_msg == NULL || params == NULL || name == NULL || customer_callback == NULL) {
        json_decref(register_msg);
        json_decref(name);
        customer_callback_free(customer_callback);
        return PT_STATUS_ALLOCATION_FAIL;
    }

    json_object_set_new(params, "name", name);

    return write_data_frame(register_msg,
                           pt_handle_pt_register_success,
                           pt_handle_pt_register_failure,
                           customer_callback_free_func,
                           customer_callback);
}

static char* convert_resource_type_to_str(Lwm2mResourceType resource_type)
{
    switch(resource_type) {
        case LWM2M_STRING:
            return "string";
        case LWM2M_INTEGER:
            return "int";
        case LWM2M_FLOAT:
            return "float";
        case LWM2M_BOOLEAN:
            return "bool";
        case LWM2M_TIME:
            return "time";
        case LWM2M_OBJLINK:
            return "objlink";
        default:
            return "opaque";
    }
}

static void parse_objects(pt_object_list_t *objects, json_t *j_objects)
{
    ns_list_foreach(pt_object_t, current_object, objects)
    {
        json_t *j_object = json_object();
        json_t *j_object_instances = json_array();
        pt_object_instance_list_t *instances = current_object->instances;

        tr_debug("Adding object %d", current_object->id);
        json_array_append_new(j_objects, j_object);
        json_object_set_new(j_object, "objectId", json_integer(current_object->id));
        json_object_set_new(j_object, "objectInstances", j_object_instances);
        ns_list_foreach(pt_object_instance_t, current_instance, instances)
        {
            json_t *j_object_instance = json_object();
            json_t *j_resources = json_array();
            pt_resource_list_t *resources = current_instance->resources;
            tr_debug("Adding object instance %d", current_instance->id);
            json_object_set_new(j_object_instance, "objectInstanceId", json_integer(current_instance->id));
            json_array_append_new(j_object_instances, j_object_instance);
            ns_list_foreach(pt_resource_t, current_resource, resources)
            {
                pt_resource_t *opaque = (pt_resource_t *) current_resource;
                json_t *j_resource = json_object();
                int encoded_length = apr_base64_encode_len(opaque->value_size);
                char *encoded_value = (char*)malloc(encoded_length);
                int encoded_length2 = apr_base64_encode_binary(
                    encoded_value,
                    (const unsigned char *)(opaque->value),
                    opaque->value_size);
                assert(encoded_length == encoded_length2);
                tr_debug("Adding resource %d", opaque->id);
                json_object_set_new(j_resource, "resourceId", json_integer(opaque->id));
                json_object_set_new(j_resource, "operations", json_integer(opaque->operations));
                json_object_set_new(j_resource, "type", json_string(convert_resource_type_to_str(opaque->type)));
                json_object_set_new(j_resource, "value", json_string(encoded_value));
                free(encoded_value);
                json_array_append_new(j_resources, j_resource);
            }
            json_object_set_new(j_object_instance, "resources", j_resources);
        }
    }
}

EDGE_LOCAL pt_status_t check_device_registration_preconditions(connection_t *connection,
                                                               pt_device_t *device, const char *action, const char *message)
{
    if (connection == NULL || connection->client_data == NULL) {
        tr_warn("Device %s - no connection or protocol translator instantiated.", action);
        return PT_STATUS_ERROR;
    }

    if (!connection->client_data->registered) {
        tr_warn("Device %s -  protocol translator not registered, %s", action, message);
        return PT_STATUS_ERROR;
    }

    if (device == NULL) {
        tr_err("Cannot %s null device.", action);
        return PT_STATUS_INVALID_PARAMETERS;
    }
    return PT_STATUS_SUCCESS;
}

EDGE_LOCAL pt_status_t check_registration_data_allocated(json_t *register_msg,
                                                         json_t *params,
                                                         json_t *j_objects,
                                                         json_t *device_lifetime,
                                                         json_t *device_queuemode,
                                                         json_t *device_id,
                                                         struct pt_device_customer_callback *customer_callback)
{
    if (register_msg == NULL || params == NULL || j_objects == NULL || customer_callback == NULL ||
        device_lifetime == NULL || device_queuemode == NULL || device_id == NULL) {
        json_decref(register_msg);
        json_decref(j_objects);
        json_decref(device_lifetime);
        json_decref(device_queuemode);
        json_decref(device_id);
        device_customer_callback_free(customer_callback);
        return PT_STATUS_ALLOCATION_FAIL;
    }
    return PT_STATUS_SUCCESS;
}

pt_status_t pt_register_device(connection_t *connection,
                               pt_device_t *device, pt_device_response_handler success_handler,
                               pt_device_response_handler failure_handler, void *userdata)
{
    pt_status_t status = check_device_registration_preconditions(connection, device,
                                                                 "register", "register before devices.");

    if (PT_STATUS_SUCCESS != status) {
        return status;
    }

    tr_info("Registering device: '%s'", device->device_id);
    json_t *register_msg = allocate_base_request("device_register");
    json_t *params = json_object_get(register_msg, "params");
    json_t *j_objects = json_array();
    json_t *device_lifetime = json_integer(device->lifetime);
    const char* queuemode = device->queuemode == QUEUE ? "Q" : "-";
    json_t *device_queuemode = json_string(queuemode);
    json_t *device_id = json_string(device->device_id);
    struct pt_device_customer_callback *customer_callback =
        allocate_device_customer_callback(connection, success_handler, failure_handler, device->device_id, userdata);

    status = check_registration_data_allocated(
            register_msg, params, j_objects, device_lifetime, device_queuemode, device_id, customer_callback);
    if (PT_STATUS_SUCCESS != status) {
        return status;
    }

    // TODO: Check failures in following block
    json_object_set_new(params, "lifetime", device_lifetime);
    json_object_set_new(params, "queuemode", device_queuemode);
    json_object_set_new(params, "deviceId", device_id);
    json_object_set_new(params, "objects", j_objects);
    parse_objects(device->objects, j_objects);

    return write_data_frame(register_msg,
                           pt_handle_device_register_success,
                           pt_handle_device_register_failure,
                           device_customer_callback_free_func,
                           customer_callback);
}

EDGE_LOCAL pt_status_t check_unregistration_data_allocated(json_t *unregister_msg,
                                                           json_t *params,
                                                           json_t *device_id,
                                                           struct pt_device_customer_callback *customer_callback)
{
    if (unregister_msg == NULL || params == NULL || device_id == NULL || customer_callback == NULL) {
        json_decref(unregister_msg);
        json_decref(device_id);
        device_customer_callback_free(customer_callback);
        return PT_STATUS_ALLOCATION_FAIL;
    }
    return PT_STATUS_SUCCESS;
}

pt_status_t pt_unregister_device(connection_t *connection,
                                 pt_device_t *device,
                                 pt_device_response_handler success_handler,
                                 pt_device_response_handler failure_handler,
                                 void *userdata)
{

    pt_status_t status = check_device_registration_preconditions(connection, device,
                                                                 "unregister", "cannot unregister a device.");

    if (PT_STATUS_SUCCESS != status) {
        return status;
    }

    tr_info("Unregistering device: '%s'", device->device_id);
    json_t *unregister_msg = allocate_base_request("device_unregister");
    json_t *params = json_object_get(unregister_msg, "params");
    json_t *device_id = json_string(device->device_id);
    struct pt_device_customer_callback *customer_callback =
        allocate_device_customer_callback(connection, success_handler, failure_handler, device->device_id, userdata);
    status = check_unregistration_data_allocated(unregister_msg, params, device_id, customer_callback);
    if (PT_STATUS_SUCCESS != status) {
        return status;
    }
    json_object_set_new(params, "deviceId", device_id);

    return write_data_frame(unregister_msg,
                            pt_handle_device_unregister_success,
                            pt_handle_device_unregister_failure,
                            device_customer_callback_free_func,
                            customer_callback);
}

pt_device_userdata_t *pt_api_create_device_userdata(void *data, pt_device_free_userdata_cb_t free_userdata_cb)
{
    pt_device_userdata_t *userdata = malloc(sizeof(pt_device_userdata_t));
    if (NULL == userdata && data && free_userdata_cb) {
        (*free_userdata_cb)(data);
    }
    userdata->data = data;
    userdata->pt_device_free_userdata = free_userdata_cb;
    return userdata;
}

static void call_device_free_userdata_conditional(pt_device_userdata_t *userdata)
{
    if (userdata) {
        if (userdata->pt_device_free_userdata && userdata->data) {
            (*(userdata->pt_device_free_userdata))(userdata->data);
        }
        free(userdata);
    }
}

pt_device_t *pt_create_device_with_userdata(char *device_id,
                                            const uint32_t lifetime,
                                            const queuemode_t queuemode,
                                            pt_status_t *status,
                                            pt_device_userdata_t *userdata)
{
    pt_device_t *device = (pt_device_t*) malloc(sizeof(pt_device_t));
    if (device == NULL) {
        *status = PT_STATUS_ALLOCATION_FAIL;
        return NULL;
    }

    device->device_id = (char *) device_id;
    device->lifetime = lifetime;
    device->queuemode = queuemode;
    device->userdata = userdata;

    pt_object_list_t *objects = (pt_object_list_t *) calloc(1, sizeof(pt_object_list_t));
    if (objects == NULL) {
        *status = PT_STATUS_ALLOCATION_FAIL;
        call_device_free_userdata_conditional(device->userdata);
        free(device);
        return NULL;
    }
    ns_list_init(objects);
    device->objects = objects;
    *status = PT_STATUS_SUCCESS;
    return device;
}

pt_device_t *pt_create_device(char* device_id, const uint32_t lifetime, const queuemode_t queuemode, pt_status_t *status)
{
    return pt_create_device_with_userdata(device_id, lifetime, queuemode, status, NULL);
}

void pt_device_free(pt_device_t *device)
{
    if (device) {
        ns_list_foreach_safe(pt_object_t, current_object, device->objects)
        {
            pt_object_instance_list_t *instances  = current_object->instances;
            ns_list_foreach_safe(pt_object_instance_t, current_instance, instances)
            {
                pt_resource_list_t *resources = current_instance->resources;
                ns_list_foreach_safe(pt_resource_t, current_resource, resources)
                {
                    pt_resource_t *opaque = (pt_resource_t *) current_resource;
                    free(opaque->value);
                    ns_list_remove(resources, current_resource);
                    free(current_resource);
                }
                free(resources);
                ns_list_remove(instances, current_instance);
                free(current_instance);
            }
            free(instances);
            ns_list_remove(device->objects, current_object);
            free(current_object);
        }
        free(device->objects);
        free(device->device_id);
        call_device_free_userdata_conditional(device->userdata);
        free(device);
    }
}

pt_object_t *pt_device_add_object(pt_device_t *device, uint16_t id, pt_status_t *status)
{
    if (device == NULL) {
        *status = PT_STATUS_INVALID_PARAMETERS;
        return NULL;
    }

    if (pt_device_find_object(device, id)) {
        *status = PT_STATUS_ITEM_EXISTS;
        return NULL;
    }

    pt_object_t *object = (pt_object_t *)calloc(1, sizeof(pt_object_t));
    if (object == NULL) {
        *status = PT_STATUS_ALLOCATION_FAIL;
        return NULL;
    }
    object->id = id;
    pt_object_instance_list_t *instances = (pt_object_instance_list_t*) calloc(1, sizeof(pt_object_instance_list_t));
    if (instances == NULL) {
        free(object);
        *status = PT_STATUS_ALLOCATION_FAIL;
        return NULL;
    }
    ns_list_init(instances);
    object->instances = instances;
    object->parent = device;
    ns_list_add_to_end(device->objects, object);

    *status = PT_STATUS_SUCCESS;
    return object;
}

pt_object_t *pt_device_find_object(pt_device_t *device, uint16_t id)
{
    if (device == NULL || !device->objects) {
        return NULL;
    }

    ns_list_foreach(pt_object_t, cur, device->objects) {
        if (cur->id == id) {
            return (pt_object_t *) cur;
        }
    }
    return NULL;
}

pt_object_instance_t *pt_object_add_object_instance(pt_object_t *object, uint16_t id, pt_status_t *status)
{
    if (object == NULL || status == NULL) {
        *status = PT_STATUS_INVALID_PARAMETERS;
        return NULL;
    }
    if (pt_object_find_object_instance(object, id)) {
        *status = PT_STATUS_ITEM_EXISTS;
        return NULL;
    }
    *status = PT_STATUS_SUCCESS;

    struct pt_object_instance *instance =
            (struct pt_object_instance *)calloc(1, sizeof(pt_object_instance_t));
    if (instance == NULL) {
        *status = PT_STATUS_ALLOCATION_FAIL;
        return NULL;
    }
    instance->id = id;
    pt_resource_list_t *resources = calloc(1, sizeof(pt_resource_list_t));
    if (resources == NULL) {
        *status = PT_STATUS_ALLOCATION_FAIL;
        free(instance);
        return NULL;
    }
    ns_list_init(resources);
    instance->resources = resources;
    instance->parent = object;
    ns_list_add_to_end(object->instances, instance);
    return instance;
}

pt_object_instance_t *pt_object_find_object_instance(pt_object_t *object, uint16_t id)
{
    if (object == NULL || !object->instances) {
        return NULL;
    }

    ns_list_foreach(pt_object_instance_t, cur, object->instances) {
        if (cur->id == id) {
            return (pt_object_instance_t *) cur;
        }
    }
    return NULL;
}

pt_resource_t *pt_object_instance_add_resource(pt_object_instance_t *object_instance,
                                               uint16_t id,
                                               Lwm2mResourceType type,
                                               uint8_t *value,
                                               uint32_t value_size,
                                               pt_status_t *status)
{
    return pt_object_instance_add_resource_with_callback(object_instance, id, type,
                                                          OPERATION_READ, value, value_size,
                                                          status, NULL);
}

pt_resource_t *pt_object_instance_add_resource_with_callback(pt_object_instance_t *object_instance,
                                                             uint16_t id,
                                                             Lwm2mResourceType type,
                                                             uint8_t operations,
                                                             uint8_t *value,
                                                             uint32_t value_size,
                                                             pt_status_t *status,
                                                             pt_resource_callback callback)
{
    if (object_instance == NULL || status == NULL) {
        *status = PT_STATUS_INVALID_PARAMETERS;
        return NULL;
    }
    if (pt_object_instance_find_resource(object_instance, id)) {
        *status = PT_STATUS_ITEM_EXISTS;
        return NULL;
    }
    if ((operations & OPERATION_WRITE) && (operations & OPERATION_EXECUTE)) {
        *status = PT_STATUS_INVALID_PARAMETERS;
        return NULL;
    }
    if ((operations & OPERATION_WRITE) && !callback) {
        *status = PT_STATUS_INVALID_PARAMETERS;
        return NULL;
    }
    if ((operations & OPERATION_EXECUTE) && !callback) {
        *status = PT_STATUS_INVALID_PARAMETERS;
        return NULL;
    }

    pt_resource_t *resource = (pt_resource_t *) calloc(1, sizeof(pt_resource_t));
    if (resource == NULL) {
        *status = PT_STATUS_ALLOCATION_FAIL;
        return NULL;
    }
    resource->id = id;
    resource->type = type;
    resource->operations = operations;
    resource->value = value;
    resource->value_size = value_size;
    resource->callback = callback;
    resource->parent = object_instance;

    ns_list_add_to_end(object_instance->resources, (pt_resource_t*) resource);

    *status = PT_STATUS_SUCCESS;
    return resource;
}

pt_resource_t *pt_object_instance_find_resource(pt_object_instance_t *instance, uint16_t id)
{
    if (instance == NULL || !instance->resources) {
        return NULL;
    }

    ns_list_foreach(pt_resource_t, cur, instance->resources)
    {
        if (cur->id == id) {
            return (pt_resource_t *) cur;
        }
    }
    return NULL;
}

EDGE_LOCAL void pt_handle_pt_write_value_success(json_t *response, void* userdata)
{
    tr_debug("Handling write value success");
    if (userdata != NULL) {
        struct pt_device_customer_callback *customer_callback = (struct pt_device_customer_callback*) userdata;
        customer_callback->success_handler(customer_callback->device_id, customer_callback->userdata);
    }
}

EDGE_LOCAL void pt_handle_pt_write_value_failure(json_t *response, void* userdata)
{
    tr_debug("Handling write value failure");
    if (userdata != NULL) {
        struct pt_device_customer_callback *customer_callback = (struct pt_device_customer_callback*) userdata;
        customer_callback->failure_handler(customer_callback->device_id, customer_callback->userdata);
    }
}

EDGE_LOCAL pt_status_t check_write_value_data_allocated(json_t *request,
                                                        json_t *params,
                                                        json_t *j_objects,
                                                        json_t *device_id,
                                                        struct pt_device_customer_callback *customer_callback)
{
    if (request == NULL || params == NULL || j_objects == NULL || customer_callback == NULL || device_id == NULL) {
        json_decref(request);
        json_decref(j_objects);
        json_decref(device_id);
        device_customer_callback_free(customer_callback);
        return PT_STATUS_ALLOCATION_FAIL;
    }
    return PT_STATUS_SUCCESS;
}

pt_status_t pt_write_value(connection_t *connection, pt_device_t *device,
                           pt_object_list_t *objects,
                           pt_device_response_handler success_handler,
                           pt_device_response_handler failure_handler,
                           void *userdata)
{
    if (device == NULL || objects == NULL) {
        return PT_STATUS_INVALID_PARAMETERS;
    }
    tr_debug("Writing values to the device '%s'", device->device_id);
    pt_status_t status;
    json_t *request = allocate_base_request("write");
    json_t *params = json_object_get(request, "params");
    json_t *j_objects = json_array();
    json_t *device_id = json_string(device->device_id);
    struct pt_device_customer_callback *customer_callback =
        allocate_device_customer_callback(connection, success_handler, failure_handler, device->device_id, userdata);

    status = check_write_value_data_allocated(request, params, j_objects, device_id, customer_callback);
    if (PT_STATUS_SUCCESS != status) {
        return status;
    }

    // TODO: Check failures in next block
    json_object_set_new(params, "deviceId", device_id);
    json_object_set_new(params, "objects", j_objects);
    parse_objects(objects, j_objects);

    status =  write_data_frame(request,
                               pt_handle_pt_write_value_success,
                               pt_handle_pt_write_value_failure,
                               device_customer_callback_free_func,
                               customer_callback);

    if (PT_STATUS_SUCCESS != status) {
        tr_info("Could not write data to Edge Core, call failure callback.");
        customer_callback->failure_handler(device->device_id, userdata);
        device_customer_callback_free(customer_callback);
        tr_info("Could not write data to Edge Core, deallocate customer callbacks.");
    }

    return status;
}

void pt_client_connection_destroy(connection_t **connection)
{
    if (connection && *connection) {
        if ((*connection)) {
            (*connection)->protocol_translator_callbacks->connection_shutdown_cb(connection, (*connection)->userdata);
        }
    }
}

client_data_t *pt_client_create_protocol_translator(char* name)
{
    client_data_t *client_data = calloc(1, sizeof(client_data_t));
    if (!client_data) {
        tr_err("Could not allocate memory for protocol translator structure.");
        return NULL;
    }
    // Set the id to invalid
    if (NULL != client_data) {
        client_data->id = -1;
    }
    client_data->name = name;
    client_data->registered = false;
    client_data->method_table = pt_service_method_table;
    return client_data;
}

void pt_client_protocol_translator_destroy(client_data_t **client_data)
{
    if (client_data && *client_data) {
        free((*client_data)->name);
        free((*client_data));
        *client_data = NULL;
    }
}
