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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1 // needed for strndup
#endif
#include <event2/bufferevent.h>
#include <jansson.h>
#include <string.h>
#include <assert.h>

#include "pt-client-2/pt_api.h"
#include "pt-client-2/pt_device_api_internal.h"
#include "pt-client-2/pt_object_api_internal.h"
#include "pt-client-2/pt_certificate_api_internal.h"
#include "pt-client-2/pt_object_instance_api_internal.h"
#include "pt-client-2/pt_resource_api_internal.h"

#include "edge-rpc/rpc.h"
#include "common/test_support.h"
#include "pt-client-2/pt_api_internal.h"
#include "common/apr_base64.h"

#include "mbed-trace/mbed_trace.h"
#include "common/edge_mutex.h"
#include "common/msg_api.h"

#define TRACE_GROUP "clnt"

// bad: shouldn't really use static initializer - portability!
// this is basically a recursive mutex but will make e.g. sanitizer squeal
EDGE_LOCAL edge_mutex_t api_mutex = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP; //PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

EDGE_LOCAL void device_list_set_changed(pt_devices_data_t *devices_data, pt_changed_status_e changed_status);
EDGE_LOCAL void device_set_changed(pt_device_t *device, pt_changed_status_e changed_status);
EDGE_LOCAL void object_set_changed(pt_object_t *object, pt_changed_status_e changed_status);
EDGE_LOCAL void object_instance_set_changed(pt_object_instance_t *instance, pt_changed_status_e changed_status);
EDGE_LOCAL void resource_set_changed(pt_resource_t *resource, pt_changed_status_e changed_status);
static device_cb_data_t *alloc_device_cb_data(devices_cb_data_t *devices_data);
static void free_event_loop_send_message(send_message_params_t *message, bool /* customer callback called */);
static void unable_to_send_message(send_message_params_t *message, bool call_failure_cb);
EDGE_LOCAL pt_status_t write_data_frame(send_message_params_t *message);
static void add_message_to_send_messages(send_message_list_t *messages_to_send,
                                         send_message_params_t *send_message,
                                         device_cb_data_t *device_data);
static void free_device_cb_data(device_cb_data_t *data);
static pt_device_t *find_client_device(pt_device_customer_callback_t *cb_data);
EDGE_LOCAL void device_set_changed_recursive(pt_device_t *device, pt_changed_status_e changed_status);
static void free_value(pt_resource_value_free_callback value_free_cb, uint8_t *value);

void api_lock()
{
    uint32_t er = edge_mutex_lock(&api_mutex);
    if (er)
    {
        int break_here = 0; // just for debugger breaking, to be removed
        (void) break_here;
    }
}

void api_unlock()
{
    edge_mutex_unlock(&api_mutex);
}

EDGE_LOCAL void event_loop_send_message_callback(void *arg)
{
    // write_data_frame handles the freeing of the message and parameters
    // Note: it could race with the sending end (send_device_messages), because it could be
    // removing messages from the list at the same time.
    pt_status_t status = write_data_frame((send_message_params_t *) (arg));
    if (PT_STATUS_SUCCESS != status) {
        tr_err("write_data_frame returned error: %d", status);
    }
}

void event_loop_send_response_callback(void *data)
{
    tr_debug("event_loop_send_response_callback");
    response_params_t *params = (response_params_t *) data;
    connection_t *connection = find_connection(params->connection_id);
    if (connection) {
        (void) rpc_construct_and_send_response(connection,
                                               params->response,
                                               (rpc_free_func)free,
                                               NULL,
                                               connection->transport_connection->write_function);
    } else {
        tr_warn("event_loop_send_response_callback: response not send because connection id %d no longer exists",
                params->connection_id);
        json_decref(params->response);
    }
    free(params);
}

pt_status_t pt_api_send_to_event_loop(connection_id_t connection_id,
                                      void *parameter,
                                      event_loop_callback_t callback)
{
    pt_status_t status = PT_STATUS_SUCCESS;
    tr_debug("pt_api_send_to_event_loop");
    api_lock();
    connection_t *connection = find_connection(connection_id);
    if (connection) {
        bool success = msg_api_send_message(connection_get_ev_base(connection), parameter, callback);
        if (!success) {
            status = PT_STATUS_ERROR;
            tr_err("Msg API failed to send the message");
        }
    } else {
        status = PT_STATUS_NOT_CONNECTED;
        tr_err("Cannot find connection any more in pt_api_send_to_event_loop");
    }

    api_unlock();
    return status;
}

pt_status_t send_message_to_event_loop(connection_id_t connection_id, send_message_params_t *message)
{
    pt_status_t status = pt_api_send_to_event_loop(connection_id, message, event_loop_send_message_callback);
    if (status != PT_STATUS_SUCCESS) {
        unable_to_send_message(message, false);
    }
    return status;
}

pt_customer_callback_t *allocate_customer_callback(connection_id_t connection_id,
                                                   pt_response_handler success_handler,
                                                   pt_response_handler failure_handler,
                                                   void *userdata)
{
    if (NULL == success_handler || NULL == failure_handler) {
        tr_err("Trying to allocate customer callback with no success or failure handler");
        return NULL;
    }
    pt_customer_callback_t *customer_callback = (pt_customer_callback_t *) malloc(sizeof(pt_customer_callback_t));
    if (customer_callback == NULL) {
        tr_err("Error could not allocate pt_customer_callback struct.");
        return NULL;
    }
    customer_callback->connection_id = connection_id;
    customer_callback->success_handler = success_handler;
    customer_callback->failure_handler = failure_handler;
    customer_callback->userdata = userdata;
    return customer_callback;
}

EDGE_LOCAL pt_device_customer_callback_t *allocate_device_customer_callback(connection_id_t connection_id,
                                                                            pt_device_response_handler success_handler,
                                                                            pt_device_response_handler failure_handler,
                                                                            const char *device_id,
                                                                            void *userdata)
{
    pt_device_customer_callback_t *customer_callback = (pt_device_customer_callback_t *) malloc(
            sizeof(pt_device_customer_callback_t));
    if (customer_callback == NULL) {
        tr_err("Error could not allocate pt_device_customer_callback struct.");
        return NULL;
    }
    customer_callback->connection_id = connection_id;
    customer_callback->success_handler = success_handler;
    customer_callback->failure_handler = failure_handler;
    customer_callback->userdata = userdata;
    customer_callback->device_id = NULL;
    if(success_handler && failure_handler) {
        customer_callback->device_id = strndup(device_id, strlen(device_id));
    }
    return customer_callback;
}

void customer_callback_free(pt_customer_callback_t *customer_callback)
{
    // Note: this doesn't free the customer's user data.
    // How does customer know whether to free the userdata in error situation?
    free(customer_callback);
}

void device_customer_callback_free(pt_device_customer_callback_t *customer_callback)
{
    if(customer_callback->device_id) {
        free(customer_callback->device_id);
    }
    free(customer_callback);
}

void customer_callback_free_func(rpc_request_context_t *callback_data)
{
    pt_customer_callback_t *customer_callback = (pt_customer_callback_t *) callback_data;
    customer_callback_free(customer_callback);
}

EDGE_LOCAL void device_customer_callback_free_func(rpc_request_context_t *callback_data)
{
    pt_device_customer_callback_t *customer_callback = (pt_device_customer_callback_t *) callback_data;
    device_customer_callback_free(customer_callback);
}

EDGE_LOCAL void pt_handle_pt_register_success(json_t *response, void *callback_data)
{
    (void) response;
    tr_debug("Handling register success.");
    pt_device_customer_callback_t *customer_callback = (pt_device_customer_callback_t *) callback_data;
    connection_id_t connection_id = customer_callback->connection_id;

    api_lock();
    connection_t *connection = find_connection(connection_id);
    if (connection) {
        connection->client->registered = true;
    }
    else {
        tr_warn("Connection no longer found in pt_handle_pt_register_success");
    }
    api_unlock();

    pt_customer_callback_t *pt_customer_callback = (pt_customer_callback_t *) callback_data;
    pt_customer_callback->success_handler(pt_customer_callback->userdata);
}

EDGE_LOCAL void pt_handle_pt_register_failure(json_t *response, void *callback_data)
{
    (void) response;
    tr_debug("Handling register failure.");
    pt_device_customer_callback_t *customer_callback = (pt_device_customer_callback_t *) callback_data;
    connection_id_t connection_id = customer_callback->connection_id;

    api_lock();
    connection_t *connection = find_connection(connection_id);
    if (connection) {
        connection->client->registered = false;
    }
    else {
        tr_warn("Connection no longer found in pt_handle_pt_register_failure");
    }
    api_unlock();

    pt_customer_callback_t *pt_customer_callback = (pt_customer_callback_t *) callback_data;
    pt_customer_callback->failure_handler(pt_customer_callback->userdata);
}

static pt_device_t *find_client_device(pt_device_customer_callback_t *cb_data)
{
    pt_device_t *device = NULL;

    api_lock();
    connection_t *connection = find_connection(cb_data->connection_id);
    if (connection) {
        pt_client_t *client = connection->client;
        device = pt_devices_find_device(client->devices, cb_data->device_id);
    }
    api_unlock();
    return device;
}

EDGE_LOCAL void pt_handle_device_register_success(json_t *response, void *callback_data)
{
    (void) response;
    tr_debug("Handling device register success.");
    pt_device_customer_callback_t *customer_callback = (pt_device_customer_callback_t *) callback_data;
    pt_device_t *device = find_client_device(customer_callback);
    if (device) {
        device->state = PT_STATE_REGISTERED;
        if (device->changed_status == PT_CHANGING) {
            device_set_changed_recursive(device, PT_NOT_CHANGED);
        }
    } else {
        tr_warn("Device '%s' no longer found in pt_handle_device_register_success", customer_callback->device_id);
    }
    customer_callback->success_handler(customer_callback->connection_id,
                                       customer_callback->device_id,
                                       customer_callback->userdata);
}

EDGE_LOCAL void pt_handle_device_register_failure(json_t *response, void *callback_data)
{
    (void) response;
    tr_debug("Handling device register failure.");
    pt_device_customer_callback_t *customer_callback = (pt_device_customer_callback_t *) callback_data;
    pt_device_t *device = find_client_device(customer_callback);
    if (device) {
        device->state = PT_STATE_UNREGISTERED;
    } else {
        tr_warn("Device '%s' no longer found in pt_handle_device_register_failure", customer_callback->device_id);
    }
    customer_callback->failure_handler(customer_callback->connection_id,
                                       customer_callback->device_id,
                                       customer_callback->userdata);
}

EDGE_LOCAL void pt_handle_device_unregister_success(json_t *response, void *callback_data)
{
    (void) response;
    tr_debug("Handling device unregister success.");
    pt_device_customer_callback_t *customer_callback = (pt_device_customer_callback_t *) callback_data;

    api_lock();

    bool success = false;
    connection_t *connection = find_connection(customer_callback->connection_id);
    if (connection) {
        pt_client_t *client = connection->client;
        pt_device_t *device = pt_devices_find_device(client->devices, customer_callback->device_id);
        if (device) {
            pt_devices_remove_and_free_device(client->devices, device);
            success = true;
        }
    }

    if (!success) {
        tr_warn("Device '%s' no longer found in pt_handle_device_unregister_success", customer_callback->device_id);
    }

    api_unlock();
    customer_callback->success_handler(customer_callback->connection_id,
                                       customer_callback->device_id,
                                       customer_callback->userdata);
}

EDGE_LOCAL void pt_handle_device_unregister_failure(json_t *response, void *callback_data)
{
    (void) response;
    tr_warn("Handling device unregister failure.");
    pt_device_customer_callback_t *customer_callback = (pt_device_customer_callback_t *) callback_data;
    pt_device_t *device = find_client_device(customer_callback);
    if (!device) {
        tr_warn("Device '%s' no longer found in pt_handle_device_unregister_failure", customer_callback->device_id);
    }
    customer_callback->failure_handler(customer_callback->connection_id,
                                       customer_callback->device_id,
                                       customer_callback->userdata);
}

send_message_params_t *construct_outgoing_message(json_t *json_message,
                                                  rpc_response_handler success_handler,
                                                  rpc_response_handler failure_handler,
                                                  rpc_free_func free_func,
                                                  send_message_type_e type,
                                                  void *customer_callback_data,
                                                  pt_status_t *status)
{
    *status = PT_STATUS_SUCCESS;
    send_message_params_t *message = calloc(1, sizeof(send_message_params_t));
    if (!message) {
        *status = PT_STATUS_ALLOCATION_FAIL;
        return NULL;
    }
    message->json_message = json_message;
    message->type = type;
    message->success_handler = success_handler;
    message->failure_handler = failure_handler;
    message->free_func = free_func;
    message->customer_callback_data = customer_callback_data;

    return message;
}

static void free_event_loop_send_message(send_message_params_t *message, bool customer_callback_called)
{
    if (message->customer_callback_data) {
        message->free_func((rpc_request_context_t *) (message->customer_callback_data));
    }
    json_decref(message->json_message);
    if (!customer_callback_called) {
        free_device_cb_data(message->device_cb_data_context);
    }
    free(message);
}

static void unable_to_send_message(send_message_params_t *message, bool call_cb)
{
    bool customer_callback_called =false;
    if (call_cb) {
        switch (message->type) {
            case PT_CUSTOMER_CALLBACK_T: {
                pt_customer_callback_t *customer_cb_data = message->customer_callback_data;
                customer_cb_data->failure_handler(customer_cb_data->userdata);
                customer_callback_called = true;
            } break;
            case PT_DEVICE_CUSTOMER_CALLBACK_T: {
                pt_device_customer_callback_t *device_customer_cb_data = message->customer_callback_data;
                device_customer_cb_data->failure_handler(device_customer_cb_data->connection_id,
                                                         device_customer_cb_data->device_id,
                                                         device_customer_cb_data->userdata);
                customer_callback_called = true;
            } break;
            default:
                assert(0);
                break;
        }
    }
    free_event_loop_send_message(message, customer_callback_called);
}

static void call_message_handler(send_message_params_t *message,
                                 rpc_response_handler cb,
                                 json_t *response,
                                 void *userdata)
{
    (void) userdata;
    (*cb)(response, message->customer_callback_data);
}

static void message_success_handler(json_t *response, void *userdata)
{
    send_message_params_t *message = (send_message_params_t *) userdata;
    call_message_handler(message, message->success_handler, response, userdata);
}

static void message_failure_handler(json_t *response, void *userdata)
{
    send_message_params_t *message = (send_message_params_t *) userdata;
    call_message_handler(message, message->failure_handler, response, userdata);
}

static void message_free_func(rpc_request_context_t *data)
{
    send_message_params_t *message = (send_message_params_t *) data;
    message->free_func((rpc_request_context_t *) message->customer_callback_data);
    free(message);
}

EDGE_LOCAL pt_status_t write_data_frame(send_message_params_t *message)
{
    api_lock();
    pt_customer_callback_t *cb_data = NULL;
    cb_data = message->customer_callback_data;
    connection_t *connection = find_connection(cb_data->connection_id);

    if ((!connection) || (!(connection->connected))) {
        tr_warn("Not connected, discarding write.");
        unable_to_send_message(message, true);
        api_unlock();
        return PT_STATUS_NOT_CONNECTED;
    }

    int32_t ret_val = rpc_construct_and_send_message(connection,
                                                     message->json_message,
                                                     message_success_handler,
                                                     message_failure_handler,
                                                     message_free_func,
                                                     (rpc_request_context_t *) (message),
                                                     connection->transport_connection->write_function);

    api_unlock();

    if (ret_val == -1) {
        return PT_STATUS_ALLOCATION_FAIL;
    }
    else if (ret_val != 0) {
        return PT_STATUS_ERROR;
    }
    return PT_STATUS_SUCCESS;
}

pt_status_t construct_and_send_outgoing_message(connection_id_t connection_id,
                                                json_t *json_message,
                                                rpc_response_handler success_handler,
                                                rpc_response_handler failure_handler,
                                                rpc_free_func free_func,
                                                send_message_type_e type,
                                                void *customer_callback_data)
{
    pt_status_t status;
    send_message_params_t *message = construct_outgoing_message(json_message,
                                                                success_handler,
                                                                failure_handler,
                                                                free_func,
                                                                type,
                                                                customer_callback_data,
                                                                &status);
    if (PT_STATUS_SUCCESS == status) {
        status = send_message_to_event_loop(connection_id, message);
    }
    return status;
}

pt_status_t pt_register_protocol_translator(connection_id_t connection_id,
                                            pt_response_handler success_handler,
                                            pt_response_handler failure_handler,
                                            const char *name,
                                            void *userdata)
{
    if (connection_id == PT_API_CONNECTION_ID_INVALID) {
        tr_warn("Connection");
        return PT_STATUS_ERROR;
    }

    if (!name || strlen(name) == 0) {
        tr_warn("No protocol translator name set.");
        return PT_STATUS_INVALID_PARAMETERS;
    }

    /* FIXME: this should be checked where the message is sent
    if (connection->client_data->registered) {
        tr_warn("Already registered, not able to do duplicate registration.");
        return PT_STATUS_ERROR;
    } */
    tr_info("Registering protocol translator '%s' in pt_api.", name);
    json_t *register_msg = allocate_base_request("protocol_translator_register");
    json_t *params = json_object_get(register_msg, "params");
    json_t *json_name = json_string(name);
    pt_customer_callback_t *customer_callback = allocate_customer_callback(connection_id,
                                                                           success_handler,
                                                                           failure_handler,
                                                                           userdata);
    if (register_msg == NULL || params == NULL || json_name == NULL || customer_callback == NULL) {
        json_decref(register_msg);
        json_decref(json_name);
        customer_callback_free(customer_callback);
        return PT_STATUS_ALLOCATION_FAIL;
    }

    json_object_set_new(params, "name", json_name);
    return construct_and_send_outgoing_message(connection_id,
                                               register_msg,
                                               pt_handle_pt_register_success,
                                               pt_handle_pt_register_failure,
                                               customer_callback_free_func,
                                               PT_CUSTOMER_CALLBACK_T,
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

static pt_status_t parse_objects(pt_object_list_t *objects, json_t *j_objects)
{
    pt_status_t status = PT_STATUS_UNNECESSARY;
    ns_list_foreach(pt_object_t, current_object, objects)
    {
        if (current_object->changed_status != PT_NOT_CHANGED) {
            status = PT_STATUS_SUCCESS;
            current_object->changed_status = PT_CHANGING;
            json_t *j_object = json_object();
            json_t *j_object_instances = json_array();
            pt_object_instance_list_t *instances = current_object->instances;

            tr_debug("Adding object %d", current_object->id);
            json_array_append_new(j_objects, j_object);
            json_object_set_new(j_object, "objectId", json_integer(current_object->id));
            json_object_set_new(j_object, "objectInstances", j_object_instances);
            ns_list_foreach(pt_object_instance_t, current_instance, instances)
            {
                if (current_instance->changed_status != PT_NOT_CHANGED) {
                    current_instance->changed_status = PT_CHANGING;
                    json_t *j_object_instance = json_object();
                    json_t *j_resources = json_array();
                    pt_resource_list_t *resources = current_instance->resources;
                    tr_debug("Adding object instance %d", current_instance->id);
                    json_object_set_new(j_object_instance, "objectInstanceId", json_integer(current_instance->id));
                    json_array_append_new(j_object_instances, j_object_instance);
                    ns_list_foreach(pt_resource_t, current_resource, resources)
                    {
                        if (current_resource->changed_status != PT_NOT_CHANGED) {
                            current_resource->changed_status = PT_CHANGING;
                            json_t *j_resource = json_object();
                            int encoded_length = apr_base64_encode_len(current_resource->value_size);
                            char *encoded_value = (char *) malloc(encoded_length);
                            int encoded_length2 = apr_base64_encode_binary(encoded_value,
                                                                           (const unsigned char *) (current_resource
                                                                                                            ->value),
                                                                           current_resource->value_size);
                            assert(encoded_length == encoded_length2);
                            tr_debug("Adding resource %d", current_resource->id);
                            json_object_set_new(j_resource, "resourceId", json_integer(current_resource->id));
                            json_object_set_new(j_resource, "operations", json_integer(current_resource->operations));
                            json_object_set_new(j_resource,
                                                "type",
                                                json_string(convert_resource_type_to_str(current_resource->type)));
                            json_object_set_new(j_resource, "value", json_string(encoded_value));
                            free(encoded_value);
                            json_array_append_new(j_resources, j_resource);
                        }
                    }
                    json_object_set_new(j_object_instance, "resources", j_resources);
                }
            }
        }
    }
    return status;
}

static pt_status_t check_device_unregistration_preconditions(pt_device_t *device, const char *action)
{
    if (device == NULL) {
        tr_err("Cannot %s null device.", action);
        return PT_STATUS_NOT_FOUND;
    }
    return PT_STATUS_SUCCESS;
}

EDGE_LOCAL pt_status_t check_registration_data_allocated(json_t *register_msg,
                                                         json_t *params,
                                                         json_t *j_objects,
                                                         json_t *device_lifetime,
                                                         json_t *device_queuemode,
                                                         json_t *device_id,
                                                         pt_device_customer_callback_t *customer_callback)
{
    if (register_msg == NULL || params == NULL || j_objects == NULL || customer_callback == NULL ||
        device_lifetime == NULL || device_queuemode == NULL || device_id == NULL) {
        json_decref(register_msg);
        json_decref(params);
        json_decref(j_objects);
        json_decref(device_lifetime);
        json_decref(device_queuemode);
        json_decref(device_id);
        if (NULL != customer_callback) {
            device_customer_callback_free(customer_callback);
        }
        return PT_STATUS_ALLOCATION_FAIL;
    }
    return PT_STATUS_SUCCESS;
}

static send_message_params_t *pt_device_register_common_by_device(connection_t *connection,
                                                                  pt_device_t *device,
                                                                  pt_device_response_handler success_handler,
                                                                  pt_device_response_handler failure_handler,
                                                                  void *userdata,
                                                                  pt_status_t *status)
{
    if (device->state != PT_STATE_REGISTERED) {
        device->state = PT_STATE_REGISTERING;

        tr_info("Registering device: '%s'", device->device_id);
        json_t *register_msg = allocate_base_request("device_register");
        json_t *params = json_object_get(register_msg, "params");
        json_t *j_objects = json_array();
        json_t *device_lifetime = json_integer(device->lifetime);
        const char *queuemode = device->queuemode == QUEUE ? "Q" : "-";
        json_t *device_queuemode = json_string(queuemode);
        json_t *device_id = json_string(device->device_id);
        pt_device_customer_callback_t *customer_callback = allocate_device_customer_callback(connection->id,
                                                                                             success_handler,
                                                                                             failure_handler,
                                                                                             device->device_id,
                                                                                             userdata);

        *status = check_registration_data_allocated(register_msg,
                                                    params,
                                                    j_objects,
                                                    device_lifetime,
                                                    device_queuemode,
                                                    device_id,
                                                    customer_callback);
        if (PT_STATUS_SUCCESS != *status) {
            return NULL;
        }

        // TODO: Check failures in following block
        json_object_set_new(params, "lifetime", device_lifetime);
        json_object_set_new(params, "queuemode", device_queuemode);
        json_object_set_new(params, "deviceId", device_id);
        json_object_set_new(params, "objects", j_objects);
        parse_objects(device->objects, j_objects);
        device->changed_status = PT_CHANGING;
        send_message_params_t *message = construct_outgoing_message(register_msg,
                                                                    pt_handle_device_register_success,
                                                                    pt_handle_device_register_failure,
                                                                    device_customer_callback_free_func,
                                                                    PT_DEVICE_CUSTOMER_CALLBACK_T,
                                                                    customer_callback,
                                                                    status);
        return message;
    } else {
        *status = PT_STATUS_UNNECESSARY;
        return NULL;
    }
}

static send_message_params_t *pt_device_register_common(connection_id_t connection_id,
                                                        const char *device_id,
                                                        pt_device_response_handler success_handler,
                                                        pt_device_response_handler failure_handler,
                                                        void *userdata,
                                                        pt_status_t *status)
{
    connection_t *connection = find_connection(connection_id);
    if (!connection) {
        *status = PT_STATUS_INVALID_PARAMETERS;
        return NULL;
    }

    pt_device_t *device = pt_devices_find_device(connection->client->devices, device_id);
    if (!device) {
        *status = PT_STATUS_ERROR;
        return NULL;
    }

    return pt_device_register_common_by_device(connection, device, success_handler, failure_handler, userdata, status);
}

/**
 * \brief Public API to register a device.
 */
pt_status_t pt_device_register(const connection_id_t connection_id,
                               const char *device_id,
                               pt_device_response_handler success_handler,
                               pt_device_response_handler failure_handler,
                               void *userdata)
{
    api_lock();
    pt_status_t status;
    send_message_params_t *message = pt_device_register_common(connection_id,
                                                               device_id,
                                                               success_handler,
                                                               failure_handler,
                                                               userdata,
                                                               &status);
    api_unlock();
    if (PT_STATUS_SUCCESS == status) {
        status = send_message_to_event_loop(connection_id, message);
    }
    //api_unlock();
    return status;
}

EDGE_LOCAL pt_status_t check_unregistration_data_allocated(json_t *unregister_msg,
                                                           json_t *params,
                                                           json_t *device_id,
                                                           pt_device_customer_callback_t *customer_callback)
{
    if (unregister_msg == NULL || params == NULL || device_id == NULL || customer_callback == NULL) {
        json_decref(unregister_msg);
        json_decref(params);
        json_decref(device_id);
        if (NULL != customer_callback) {
            device_customer_callback_free(customer_callback);
        }
        return PT_STATUS_ALLOCATION_FAIL;
    }
    return PT_STATUS_SUCCESS;
}

static send_message_params_t *pt_device_unregister_common_by_device(connection_t *connection,
                                                                    pt_device_t *device,
                                                                    pt_device_response_handler success_handler,
                                                                    pt_device_response_handler failure_handler,
                                                                    void *userdata,
                                                                    pt_status_t *status)
{
    *status = check_device_unregistration_preconditions(device, "unregister");

    if (PT_STATUS_SUCCESS != *status) {
        return NULL;
    }
    if (device->state != PT_STATE_UNREGISTERED) {
        device->state = PT_STATE_UNREGISTERING;
        tr_info("Unregistering device: '%s'", device->device_id);
        json_t *unregister_msg = allocate_base_request("device_unregister");
        json_t *params = json_object_get(unregister_msg, "params");
        json_t *device_id = json_string(device->device_id);
        pt_device_customer_callback_t *customer_callback = allocate_device_customer_callback(connection->id,
                                                                                             success_handler,
                                                                                             failure_handler,
                                                                                             device->device_id,
                                                                                             userdata);
        *status = check_unregistration_data_allocated(unregister_msg, params, device_id, customer_callback);
        if (PT_STATUS_SUCCESS != *status) {
            return NULL;
        }
        json_object_set_new(params, "deviceId", device_id);

        return construct_outgoing_message(unregister_msg,
                                          pt_handle_device_unregister_success,
                                          pt_handle_device_unregister_failure,
                                          device_customer_callback_free_func,
                                          PT_DEVICE_CUSTOMER_CALLBACK_T,
                                          customer_callback,
                                          status);
    } else {
        *status = PT_STATUS_UNNECESSARY;
        return NULL;
    }
}

pt_status_t pt_device_unregister(const connection_id_t connection_id,
                                 const char *device_id,
                                 pt_device_response_handler success_handler,
                                 pt_device_response_handler failure_handler,
                                 void *userdata)
{
    pt_status_t status;
    api_lock();

    connection_t *connection = find_connection(connection_id);
    if (!connection) {
        api_unlock();
        return PT_STATUS_NOT_CONNECTED;
    }

    pt_device_t *device = pt_devices_find_device(connection->client->devices, device_id);

    send_message_params_t *message = pt_device_unregister_common_by_device(connection,
                                                                           device,
                                                                           success_handler,
                                                                           failure_handler,
                                                                           userdata,
                                                                           &status);
    api_unlock();
    if (PT_STATUS_SUCCESS == status) {
        status = send_message_to_event_loop(connection_id, message);
    }
    return status;
}

pt_userdata_t *pt_api_create_userdata(void *data, pt_userdata_free_cb_t free_userdata_cb)
{
    pt_userdata_t *userdata = malloc(sizeof(pt_userdata_t));
    if (NULL == userdata && data && free_userdata_cb) {
        (*free_userdata_cb)(data);
    }
    userdata->data = data;
    userdata->pt_free_userdata = free_userdata_cb;
    return userdata;
}

static void call_free_userdata_conditional(pt_userdata_t *userdata)
{
    if (userdata) {
        if (userdata->pt_free_userdata && userdata->data) {
            (*(userdata->pt_free_userdata))(userdata->data);
        }
        free(userdata);
    }
}

pt_status_t pt_device_create_with_feature_flags(const connection_id_t connection_id,
                                                const char *device_id,
                                                const uint32_t lifetime,
                                                const queuemode_t queuemode,
                                                const uint32_t features,
                                                pt_userdata_t *userdata)
{
    if (NULL == device_id) {
        return PT_STATUS_INVALID_PARAMETERS;
    }

    api_lock();
    connection_t *connection = find_connection(connection_id);
    if (NULL == connection) {
        api_unlock();
        return PT_STATUS_NOT_CONNECTED;
    }

    pt_device_t *device = pt_devices_find_device(connection->client->devices, device_id);
    if (device) {
        api_unlock();
        return PT_STATUS_ITEM_EXISTS;
    }

    device = (pt_device_t *) malloc(sizeof(pt_device_t));
    char *id = strdup(device_id);
    pt_object_list_t *objects = (pt_object_list_t *) calloc(1, sizeof(pt_object_list_t));
    if (device == NULL || id == NULL || objects == NULL) {
        free(device);
        free(id);
        free(objects);
        api_unlock();
        return PT_STATUS_ALLOCATION_FAIL;
    }
    device->state = PT_STATE_UNREGISTERED;
    device->changed_status = PT_CHANGED;
    device->device_id = id;
    device->lifetime = lifetime;
    device->queuemode = queuemode;
    device->userdata = userdata;
    device->devices_data = NULL;
    device->features = features;
    device->csr_request_id = NULL;
    device->csr_request_id_len = 0;

    ns_list_init(objects);
    device->objects = objects;

    pt_devices_add_device(connection->client->devices, device);

    if (device->features & PT_DEVICE_FEATURE_CERTIFICATE_RENEWAL) {
        pt_status_t status = pt_device_init_certificate_renewal_resources(connection_id, device_id);
        if (status != PT_STATUS_SUCCESS) {
            tr_error("Initializing certificate renewal resource failed, status %d", status);
            pt_devices_remove_and_free_device(connection->client->devices, device);
            api_unlock();
            return PT_STATUS_FEATURE_INITIALIZATION_FAIL;
        }
    }

    api_unlock();
    return PT_STATUS_SUCCESS;
}


pt_status_t pt_device_create_with_userdata(const connection_id_t connection_id,
                                           const char *device_id,
                                           const uint32_t lifetime,
                                           const queuemode_t queuemode,
                                           pt_userdata_t *userdata)
{
    return pt_device_create_with_feature_flags(connection_id, device_id, lifetime, queuemode, PT_DEVICE_FEATURE_NONE, userdata);
}

pt_status_t pt_device_create(const connection_id_t connection_id,
                      const char *device_id,
                      const uint32_t lifetime,
                      const queuemode_t queuemode)
{
    return pt_device_create_with_userdata(connection_id, device_id, lifetime, queuemode, NULL);
}

void pt_device_free(pt_device_t *device)
{
    if (device) {
        ns_list_foreach_safe(pt_object_t, current_object, device->objects)
        {
            pt_object_instance_list_t *instances = current_object->instances;
            ns_list_foreach_safe(pt_object_instance_t, current_instance, instances)
            {
                pt_resource_list_t *resources = current_instance->resources;
                ns_list_foreach_safe(pt_resource_t, current_resource, resources)
                {
                    pt_resource_t *opaque = (pt_resource_t *) current_resource;
                    if (opaque->value_free != NULL) {
                        opaque->value_free(opaque->value);
                    }
                    ns_list_remove(resources, current_resource);
                    call_free_userdata_conditional(current_resource->userdata);
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
        call_free_userdata_conditional(device->userdata);
        free(device);
    }
}

pt_status_t pt_device_get_feature_flags(const connection_id_t connection_id,
                                        const char *device_id,
                                        uint32_t *flags)
{
    api_lock();

    connection_t *connection = find_connection(connection_id);
    if (connection == NULL || connection->client == NULL) {
        api_unlock();
        return PT_STATUS_NOT_CONNECTED;
    }

    pt_device_t *device = pt_devices_find_device(connection->client->devices, device_id);
    if (device == NULL) {
        api_unlock();
        return PT_STATUS_NOT_FOUND;
    }

    *flags = device->features;

    api_unlock();
    return PT_STATUS_SUCCESS;
}


// Note: this method is expecting that device is not NULL
pt_object_t *pt_device_add_object_or_create(pt_device_t *device, const uint16_t id, pt_status_t *status)
{
    pt_object_t *object = pt_device_find_object(device, id);
    if (object) {
        *status = PT_STATUS_ITEM_EXISTS;
        return object;
    }

    object = (pt_object_t *) calloc(1, sizeof(pt_object_t));
    if (object == NULL) {
        *status = PT_STATUS_ALLOCATION_FAIL;
        return NULL;
    }
    object->id = id;
    pt_object_instance_list_t *instances = (pt_object_instance_list_t *) calloc(1, sizeof(pt_object_instance_list_t));
    if (instances == NULL) {
        free(object);
        *status = PT_STATUS_ALLOCATION_FAIL;
        return NULL;
    }
    ns_list_init(instances);
    object->instances = instances;
    object->parent = device;
    object_set_changed(object, PT_CHANGED);
    ns_list_add_to_end(device->objects, object);

    *status = PT_STATUS_SUCCESS;
    return object;
}

pt_object_t *pt_device_find_object(const pt_device_t *device, const uint16_t object_id)
{
    if (device == NULL || !device->objects) {
        return NULL;
    }

    ns_list_foreach(pt_object_t, cur, device->objects)
    {
        if (cur->id == object_id) {
            return (pt_object_t *) cur;
        }
    }
    return NULL;
}

pt_object_instance_t *pt_device_find_object_instance(const pt_device_t *device,
                                                     const uint16_t object_id,
                                                     const uint16_t object_instance_id)
{
    pt_object_instance_t *object_instance = NULL;
    pt_object_t *object = pt_device_find_object(device, object_id);
    if (object) {
        object_instance = pt_object_find_object_instance(object, object_instance_id);
    }
    return object_instance;
}

pt_resource_t *pt_device_find_resource(const pt_device_t *device,
                                       const uint16_t object_id,
                                       const uint16_t object_instance_id,
                                       const uint16_t resource_id)
{
    pt_resource_t *resource = NULL;
    pt_object_instance_t *object_instance = pt_device_find_object_instance(device, object_id, object_instance_id);
    if (object_instance) {
        resource = pt_object_instance_find_resource(object_instance, resource_id);
    }
    return resource;
}

pt_resource_t *pt_devices_find_resource(const pt_devices_t *devices,
                                        const char *device_id,
                                        const uint16_t object_id,
                                        const uint16_t object_instance_id,
                                        const uint16_t resource_id)
{
    pt_device_t *device = pt_devices_find_device(devices, device_id);
    return pt_device_find_resource(device, object_id, object_instance_id, resource_id);
}

pt_object_instance_t *pt_device_add_object_instance_or_create(pt_object_t *object,
                                                              const uint16_t id,
                                                              pt_status_t *status)
{
    if (NULL == status) {
        return NULL;
    }

    if (object == NULL) {
        *status = PT_STATUS_INVALID_PARAMETERS;
        return NULL;
    }

    pt_object_instance_t *instance = pt_object_find_object_instance(object, id);
    if (instance) {
        *status = PT_STATUS_ITEM_EXISTS;
        return instance;
    }

    *status = PT_STATUS_SUCCESS;
    instance = (struct pt_object_instance *) calloc(1, sizeof(pt_object_instance_t));
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
    object_instance_set_changed(instance, PT_CHANGED);
    ns_list_add_to_end(object->instances, instance);
    return instance;
}

pt_object_instance_t *pt_object_find_object_instance(const pt_object_t *object, const uint16_t id)
{
    if (object == NULL || !object->instances) {
        return NULL;
    }

    ns_list_foreach(pt_object_instance_t, cur, object->instances)
    {
        if (cur->id == id) {
            return (pt_object_instance_t *) cur;
        }
    }
    return NULL;
}

int32_t pt_device_get_next_free_object_instance_id(connection_id_t connection_id,
                                                   const char *device_id,
                                                   uint16_t object_id)
{
    connection_t *connection = find_connection(connection_id);
    if (!connection) {
        return -1;
    }
    pt_device_t *device = pt_devices_find_device(connection->client->devices, device_id);
    if (!device) {
        return -1;
    }

    pt_object_t *object = pt_device_find_object(device, object_id);
    if (!object) {
        // If the object is not found, we return 0 as that is actually the first
        // free instance id for that resource if it is created. User would be able
        // to create the object and object  instance 0 by calling the pt_device_add_resource API.
        return 0;
    }

    for (uint16_t id = 0; id < UINT16_MAX; id++) {
        if (NULL == pt_object_find_object_instance(object, id)) {
            return id;
        }
    }
    return -1;
}

pt_status_t pt_device_add_resource(const connection_id_t connection_id,
                            const char *device_id,
                            const uint16_t object_id,
                            const uint16_t object_instance_id,
                            const uint16_t resource_id,
                            const Lwm2mResourceType type,
                            uint8_t *value,
                            uint32_t value_size,
                            pt_resource_value_free_callback value_free_cb)
{
    return pt_device_add_resource_with_callback(connection_id,
                                                device_id,
                                                object_id,
                                                object_instance_id,
                                                resource_id,
                                                type,
                                                OPERATION_READ,
                                                value,
                                                value_size,
                                                value_free_cb,
                                                NULL);
}

static void free_value(pt_resource_value_free_callback value_free_cb, uint8_t *value)
{
    if (value_free_cb && value) {
        (*value_free_cb)(value);
    }
}

pt_status_t pt_device_add_resource_with_callback(const connection_id_t connection_id,
                                          const char *device_id,
                                          const uint16_t object_id,
                                          const uint16_t object_instance_id,
                                          const uint16_t resource_id,
                                          const Lwm2mResourceType type,
                                          const uint8_t operations,
                                          uint8_t *value,
                                          uint32_t value_size,
                                          pt_resource_value_free_callback value_free_cb,
                                          pt_resource_callback callback)
{
    api_lock();

    connection_t *connection = find_connection(connection_id);
    if (connection == NULL || connection->client == NULL) {
        free_value(value_free_cb, value);
        api_unlock();
        return PT_STATUS_NOT_CONNECTED;
    }

    pt_device_t *device = pt_devices_find_device(connection->client->devices, device_id);
    if (device == NULL) {
        free_value(value_free_cb, value);
        api_unlock();
        return PT_STATUS_NOT_FOUND;
    }

    pt_status_t status;
    pt_object_t *object = pt_device_add_object_or_create(device, object_id, &status);
    if (object == NULL) {
        // Happens if memory cannot be allocated
        free_value(value_free_cb, value);
        api_unlock();
        return status;
    }

    pt_object_instance_t *object_instance = pt_device_add_object_instance_or_create(object, object_instance_id, &status);
    if (object_instance == NULL) {
        // Happens if memory cannot be allocated
        free_value(value_free_cb, value);
        api_unlock();
        return status;
    }

    if (pt_object_instance_find_resource(object_instance, resource_id)) {
        free_value(value_free_cb, value);
        api_unlock();
        return PT_STATUS_ITEM_EXISTS;
    }

    if ((operations & OPERATION_WRITE) && (operations & OPERATION_EXECUTE)) {
        free_value(value_free_cb, value);
        api_unlock();
        return PT_STATUS_INVALID_PARAMETERS;
    }

    pt_resource_t *resource = (pt_resource_t *) calloc(1, sizeof(pt_resource_t));
    if (resource == NULL) {
        free_value(value_free_cb, value);
        api_unlock();
        return PT_STATUS_ALLOCATION_FAIL;
    }
    resource->id = resource_id;
    resource->type = type;
    resource->operations = operations;
    resource->value = value;
    resource->value_size = value_size;
    resource->value_free = value_free_cb;
    if (operations & (OPERATION_WRITE | OPERATION_EXECUTE)) {
        resource->callback = callback;
    }
    resource->parent = object_instance;
    resource_set_changed(resource, PT_CHANGED);

    ns_list_add_to_end(object_instance->resources, resource);

    api_unlock();
    return PT_STATUS_SUCCESS;
}

pt_resource_t *pt_object_instance_find_resource(const pt_object_instance_t *instance, const uint16_t id)
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

EDGE_LOCAL void pt_handle_pt_write_values_success(json_t *response, void *userdata)
{
    (void) response;
    tr_debug("Handling write value success");
    if (userdata != NULL) {
        pt_device_customer_callback_t *customer_callback = (pt_device_customer_callback_t *) userdata;
        pt_device_t *device = find_client_device(customer_callback);
        if (device->changed_status == PT_CHANGING) {
            device_set_changed_recursive(device, PT_NOT_CHANGED);
        }

        customer_callback->success_handler(customer_callback->connection_id,
                                           customer_callback->device_id,
                                           customer_callback->userdata);
    }
}

EDGE_LOCAL void pt_handle_pt_write_values_failure(json_t *response, void *userdata)
{
    (void) response;
    tr_debug("Handling write value failure");
    if (userdata != NULL) {
        pt_device_customer_callback_t *customer_callback = (pt_device_customer_callback_t *) userdata;
        customer_callback->failure_handler(customer_callback->connection_id,
                                           customer_callback->device_id,
                                           customer_callback->userdata);
    }
}

static send_message_params_t *pt_device_write_values_common(connection_id_t connection_id,
                                                            pt_device_t *device,
                                                            pt_device_response_handler success_handler,
                                                            pt_device_response_handler failure_handler,
                                                            void *userdata,
                                                            pt_status_t *status)
{
    if (device == NULL) {
        *status = PT_STATUS_INVALID_PARAMETERS;
        return NULL;
    }
    tr_debug("Writing values to the device '%s'", device->device_id);
    json_t *request = allocate_base_request("write");
    json_t *params = json_object_get(request, "params");
    json_t *j_objects = json_array();
    json_t *device_id = json_string(device->device_id);
    pt_device_customer_callback_t *customer_callback = allocate_device_customer_callback(connection_id,
                                                                                         success_handler,
                                                                                         failure_handler,
                                                                                         device->device_id,
                                                                                         userdata);

    if (request == NULL || params == NULL || j_objects == NULL || customer_callback == NULL || device_id == NULL) {
        json_decref(request);
        json_decref(j_objects);
        json_decref(device_id);
        if (NULL != customer_callback) {
            device_customer_callback_free(customer_callback);
        }

        *status = PT_STATUS_ALLOCATION_FAIL;
        return NULL;
    }
    // TODO: Check failures in next block
    json_object_set_new(params, "deviceId", device_id);
    json_object_set_new(params, "objects", j_objects);
    (void) parse_objects(device->objects, j_objects);
    send_message_params_t *message = construct_outgoing_message(request,
                                                                pt_handle_pt_write_values_success,
                                                                pt_handle_pt_write_values_failure,
                                                                device_customer_callback_free_func,
                                                                PT_DEVICE_CUSTOMER_CALLBACK_T,
                                                                customer_callback,
                                                                status);
    if (PT_STATUS_SUCCESS != *status) {
        if (NULL != customer_callback) {
            device_customer_callback_free(customer_callback);
        }
        tr_info("Could not write data to Edge Core, deallocate customer callbacks.");
    }

    return message;
}

pt_status_t pt_device_write_values(const connection_id_t connection_id,
                                   const char *device_id,
                                   pt_device_response_handler success_handler,
                                   pt_device_response_handler failure_handler,
                                   void *userdata)
{
    pt_status_t status = PT_STATUS_SUCCESS;
    send_message_params_t *message = NULL;
    if (NULL == device_id) {
        return PT_STATUS_INVALID_PARAMETERS;
    }
    api_lock();
    connection_t *connection = find_connection(connection_id);
    if (NULL == connection) {
        status = PT_STATUS_NOT_CONNECTED;
    } else {
        pt_device_t *device = pt_devices_find_device(connection->client->devices, device_id);
        message = pt_device_write_values_common(connection_id,
                                                device,
                                                success_handler,
                                                failure_handler,
                                                userdata,
                                                &status);
    }
    api_unlock();
    if (PT_STATUS_SUCCESS == status) {
        status = send_message_to_event_loop(connection_id, message);
    } else {
        assert(NULL == message);
    }
    return status;
}

/**
 * \brief Find the device by device id from the devices list.
 *
 * \param device_id The device identifier.
 * \return The device if found.\n
 *         NULL is returned if the device is not found.
 */
pt_device_t *pt_devices_find_device(const pt_devices_t *devices, const char *device_id)
{
    ns_list_foreach(pt_device_t, cur, ((const pt_devices_data_t *) devices)->list)
    {
        if (strlen(cur->device_id) == strlen(device_id) &&
            strncmp(cur->device_id, device_id, strlen(cur->device_id)) == 0) {
            return cur;
        }
    }
    return NULL;
}

static void device_cb_common(void *userdata, pt_device_t *device, bool success)
{
    (void) device;
    device_cb_data_t *data = (device_cb_data_t *) userdata;
    devices_cb_data_t *common = data->common_data;
    if (!success) {
        common->num_failed++;
    }
    if (data->last) {
        if (!common->num_failed) {
            common->success_cb(common->connection_id, common->userdata);
        } else {
            common->failure_cb(common->connection_id, common->userdata);
        }
        free(common);
    }
    free_device_cb_data(data);
}

static void device_unregistration_success(const connection_id_t connection_id, const char *device_id, void *userdata)
{
    (void) connection_id;
    tr_debug("Unregistering device '%s' succeeded", device_id);
    device_cb_common(userdata, NULL, true);
}

static void device_unregistration_failure(const connection_id_t connection_id, const char *device_id, void *userdata)
{
    (void) connection_id;
    tr_err("Unregistering device '%s' failed", device_id);
    device_cb_common(userdata, NULL, false);
}

static void set_last_callback_flag(send_message_params_t *message)
{
    device_cb_data_t *device_data = message->device_cb_data_context;
    if (!(message->link.next)) {
        device_data->last = true;
    }
}

static bool acceptable_status_for_multiple(pt_status_t status)
{
    if (PT_STATUS_SUCCESS != status && PT_STATUS_UNNECESSARY != status) {
        return false;
    }
    return true;
}

static pt_status_t send_device_messages(devices_cb_data_t *devices_data,
                                        send_message_list_t *messages,
                                        pt_status_t status)
{
    bool ok_to_send = acceptable_status_for_multiple(status);
    pt_status_t ret_status = PT_STATUS_UNNECESSARY;
    bool something_sent = false;
    ns_list_foreach_safe(send_message_params_t, message, messages)
    {
        set_last_callback_flag(message);
        ns_list_remove(messages, message);
        if (ok_to_send) {
            ret_status = send_message_to_event_loop(devices_data->connection_id, message);
            if (PT_STATUS_SUCCESS == ret_status) {
                something_sent = true;
            }
        } else {
            free_event_loop_send_message(message, false /*customer callback called */);
        }
    }
    // If nothing was sent free the common structure.
    if (!something_sent) {
        free(devices_data);
    }
    // ret_status is changed only if ok_to_send is true.
    // In this case, ret_status error is more important. It tells if the messages could be sent if
    // the API call was otherwise valid.
    if (ret_status != PT_STATUS_SUCCESS) {
        return ret_status;
    } else {
        return status;
    }
}

/**
 * \brief Unregisters all the devices
 *         After unregistering the devices, it's safe to destroy the devices using for example
 * pt_devices_remove_and_free_all.
 */
pt_status_t pt_devices_unregister_devices(connection_id_t connection_id,
                                          pt_devices_cb success_cb,
                                          pt_devices_cb failure_cb,
                                          void *userdata)
{
    api_lock();
    connection_t *connection = find_connection(connection_id);
    if (!connection) {
        api_unlock();
        return PT_STATUS_INVALID_PARAMETERS;
    }
    pt_devices_t *devices = connection->client->devices;

    devices_cb_data_t *devices_data = calloc(1, sizeof(devices_cb_data_t));
    devices_data->userdata = userdata;
    devices_data->connection_id = connection_id;
    devices_data->failure_cb = failure_cb;
    devices_data->success_cb = success_cb;
    send_message_list_t messages_to_send;
    ns_list_init(&messages_to_send);
    pt_status_t status = PT_STATUS_UNNECESSARY;
    ns_list_foreach_safe(pt_device_t, device, devices->list)
    {
        device_cb_data_t *device_data = alloc_device_cb_data(devices_data);
        send_message_params_t *send_message = pt_device_unregister_common_by_device(connection,
                                                                                    device,
                                                                                    device_unregistration_success,
                                                                                    device_unregistration_failure,
                                                                                    device_data,
                                                                                    &status);
        add_message_to_send_messages(&messages_to_send, send_message, device_data);
        if (!acceptable_status_for_multiple(status)) {
            tr_err("Call to pt_device_unregister_common failed for device: %p status: %d", device, status);
            break;
        }
    }
    api_unlock();
    status = send_device_messages(devices_data, &messages_to_send, status);
    //api_unlock();
    return status;
}

pt_devices_t *pt_devices_create(pt_client_t *client)
{
    pt_devices_data_t *devices = calloc(1, sizeof(pt_devices_data_t));
    devices->list = calloc(1, sizeof(pt_device_list_internal_t));
    ns_list_init(devices->list);
    client->devices = devices;

    return (pt_devices_t *) devices;
}

void pt_devices_destroy(pt_devices_t *devices)
{
    if (NULL == devices) {
        return;
    }
    pt_devices_data_t *data = (pt_devices_data_t *) devices;
    free(data->list);
    free(data);
}

pt_status_t pt_devices_add_device(pt_devices_t *devices, pt_device_t *device)
{
    pt_device_list_internal_t *device_list = devices->list;
    ns_list_add_to_end(device_list, device);
    device->devices_data = devices;
    devices->changed_status = PT_CHANGED;
    return PT_STATUS_SUCCESS;
}

pt_status_t pt_devices_remove_and_free_device(pt_devices_t *devices, pt_device_t *device)
{
    pt_devices_remove_device(devices, device);
    pt_device_free(device);
    return PT_STATUS_SUCCESS;
}

pt_status_t pt_devices_remove_device(pt_devices_t *devices, pt_device_t *device)
{
    pt_status_t status = PT_STATUS_NOT_FOUND;
    if (device) {
        pt_device_list_internal_t *device_list = devices->list;
        ns_list_remove(device_list, device);
        device->devices_data = NULL;
        devices->changed_status = PT_CHANGED;
        status = PT_STATUS_SUCCESS;
    }
    return status;
}

pt_device_t *pt_devices_get_first_device(const pt_devices_t *devices)
{
    const pt_device_list_internal_t *device_list = devices->list;
    return ns_list_get_first(device_list);
}

static void device_registration_success(const connection_id_t connection_id, const char *device_id, void *userdata)
{
    (void) connection_id;
    tr_debug("registering device '%s' succeeded", device_id);
    device_cb_common(userdata, NULL, true);
}

static void device_registration_failure(const connection_id_t connection_id, const char *device_id, void *userdata)
{
    (void) connection_id;
    tr_err("registering device '%s' failed", device_id);
    device_cb_common(userdata, NULL, false);
}

static void device_write_values_success(const connection_id_t connection_id, const char *device_id, void *userdata)
{
    (void) connection_id;
    tr_debug("writing values to '%s' succeeded", device_id);
    device_cb_common(userdata, NULL, true);
}

static void device_write_values_failure(const connection_id_t connection_id, const char *device_id, void *userdata)
{
    (void) connection_id;
    tr_err("writing values to '%s' failed", device_id);
    device_cb_common(userdata, NULL, false);
}

static device_cb_data_t *alloc_device_cb_data(devices_cb_data_t *devices_data)
{
    device_cb_data_t *device_data = calloc(1, sizeof(device_cb_data_t));
    device_data->common_data = devices_data;
    return device_data;
}

/**
 * \brief Counter operation for `alloc_device_cb_data`
 */
static void free_device_cb_data(device_cb_data_t *data)
{
    free(data);
}

static void add_message_to_send_messages(send_message_list_t *messages_to_send,
                                         send_message_params_t *send_message,
                                         device_cb_data_t *device_data)
{
    if (send_message) {
        send_message->device_cb_data_context = device_data;
        ns_list_add_to_end(messages_to_send, send_message);
    } else {
        free_device_cb_data(device_data);
    }
}
/**
 * \brief registers all the devices
 */
pt_status_t pt_devices_register_devices(const connection_id_t connection_id,
                                        pt_devices_cb devices_registration_success,
                                        pt_devices_cb devices_registration_failure,
                                        void *userdata)
{
    api_lock();
    connection_t *connection = find_connection(connection_id);
    if (!connection) {
        api_unlock();
        return PT_STATUS_INVALID_PARAMETERS;
    }
    pt_devices_t *devices = connection->client->devices;

    devices_cb_data_t *devices_data = calloc(1, sizeof(devices_cb_data_t));
    devices_data->userdata = userdata;
    devices_data->connection_id = connection_id;
    devices_data->failure_cb = devices_registration_failure;
    devices_data->success_cb = devices_registration_success;
    send_message_list_t messages_to_send;
    ns_list_init(&messages_to_send);
    pt_status_t status = PT_STATUS_UNNECESSARY;
    ns_list_foreach_safe(pt_device_t, device, devices->list)
    {
        device_cb_data_t *device_data = alloc_device_cb_data(devices_data);

        send_message_params_t *send_message = pt_device_register_common_by_device(connection,
                                                                                  device,
                                                                                  device_registration_success,
                                                                                  device_registration_failure,
                                                                                  device_data,
                                                                                  &status);

        add_message_to_send_messages(&messages_to_send, send_message, device_data);
        if (!acceptable_status_for_multiple(status)) {
            tr_err("Call to pt_device_register_common failed for device: %p status: %d", device, status);
            break;
        }
    }
    api_unlock();
    status = send_device_messages(devices_data, &messages_to_send, status);
    return status;
}

pt_status_t pt_devices_update(const connection_id_t connection_id,
                              pt_devices_cb success_handler,
                              pt_devices_cb failure_handler,
                              void *userdata)
{
    api_lock();
    connection_t *connection = find_connection(connection_id);
    if (!connection) {
        api_unlock();
        return PT_STATUS_INVALID_PARAMETERS;
    }
    pt_devices_t *devices = connection->client->devices;

    pt_status_t status = PT_STATUS_SUCCESS;
    devices_cb_data_t *devices_data = calloc(1, sizeof(devices_cb_data_t));
    devices_data->userdata = userdata;
    devices_data->connection_id = connection_id;
    devices_data->success_cb = success_handler;
    devices_data->failure_cb = failure_handler;
    send_message_list_t messages_to_send;
    ns_list_init(&messages_to_send);
    tr_info("pt_devices_update - connection_id: %d devices: %p userdata: %p", connection_id, devices, userdata);

    ns_list_foreach_safe(pt_device_t, device, devices->list)
    {
        if (device->state == PT_STATE_REGISTERED && device->changed_status != PT_NOT_CHANGED) {
            device->changed_status = PT_CHANGING;
            device_cb_data_t *device_data = alloc_device_cb_data(devices_data);
            send_message_params_t *send_message = pt_device_write_values_common(connection_id,
                                                                                device,
                                                                                device_write_values_success,
                                                                                device_write_values_failure,
                                                                                device_data,
                                                                                &status);
            add_message_to_send_messages(&messages_to_send, send_message, device_data);
            if (!acceptable_status_for_multiple(status)) {
                tr_err("Call to pt_device_write_values_common failed for device: %p status: %d", device, status);
                break;
            }
        }
    }

    api_unlock();
    status = send_device_messages(devices_data, &messages_to_send, status);

    return status;
}

pt_status_t pt_devices_remove_and_free_all(pt_devices_t *devices)
{
    if (NULL == devices) {
        return PT_STATUS_UNNECESSARY;
    }
    pt_device_list_internal_t *device_list = devices->list;
    pt_status_t ret_val = PT_STATUS_SUCCESS;
    ns_list_foreach_safe(pt_device_t, device, device_list)
    {
        if (device->state != PT_STATE_UNREGISTERED) {
            tr_warn("Device '%s' is not unregistered. Should unregister for example with pt_device_unregister",
                    device->device_id);
            ret_val = PT_STATUS_ERROR;
        }
        ns_list_remove(device_list, device);
        pt_device_free(device);
    }
    return ret_val;
}

/* Device methods */
const char *pt_device_get_id(const pt_device_t *device)
{
    return device->device_id;
}

pt_device_t *pt_device_get_next(const pt_device_t *device)
{
    return ns_list_get_next(device->devices_data->list, device);
}

pt_object_t *pt_device_first_object(const pt_device_t *device)
{
    return ns_list_get_first(device->objects);
}

pt_object_t *pt_object_get_next(const pt_object_t *object)
{
    return ns_list_get_next(object->parent->objects, object);
}

/* Object methods */
pt_device_t *pt_object_get_parent(const pt_object_t *object)
{
    return object->parent;
}

pt_object_instance_t *pt_object_first_object_instance(const pt_object_t *object)
{
    return ns_list_get_first(object->instances);
}

pt_object_instance_t *pt_object_instance_get_next(const pt_object_instance_t *object_instance)
{
    return ns_list_get_next(object_instance->parent->instances, object_instance);
}

/* Resource methods */
pt_resource_t *pt_object_instance_first_resource(const pt_object_instance_t *object_instance)
{
    return ns_list_get_first(object_instance->resources);
}

pt_resource_t *pt_resource_get_next(const pt_resource_t *resource)
{
    pt_object_instance_t *object_instance = resource->parent;
    return ns_list_get_next(object_instance->resources, resource);
}

EDGE_LOCAL void resource_set_changed_recursive(pt_resource_t *resource, pt_changed_status_e changed_status)
{
    resource->changed_status = changed_status;
}

EDGE_LOCAL void object_instance_set_changed_recursive(pt_object_instance_t *object_instance,
                                                      pt_changed_status_e changed_status)
{
    object_instance->changed_status = changed_status;
    pt_resource_t *resource = pt_object_instance_first_resource(object_instance);
    while (resource != NULL) {
        resource_set_changed_recursive(resource, changed_status);
        resource = pt_resource_get_next(resource);
    }
}

EDGE_LOCAL void object_set_changed_recursive(pt_object_t *object, pt_changed_status_e changed_status)
{
    object->changed_status = changed_status;
    pt_object_instance_t *object_instance = pt_object_first_object_instance(object);
    while (object_instance != NULL) {
        object_instance_set_changed_recursive(object_instance, changed_status);
        object_instance = pt_object_instance_get_next(object_instance);
    }
}

EDGE_LOCAL void device_set_changed_recursive(pt_device_t *device, pt_changed_status_e changed_status)
{
    device->changed_status = changed_status;
    pt_object_t *object = pt_device_first_object(device);
    while (object != NULL) {
        object_set_changed_recursive(object, changed_status);
        object = pt_object_get_next(object);
    }
}

EDGE_LOCAL void device_list_set_changed(pt_devices_data_t *devices_data, pt_changed_status_e changed_status)
{
    devices_data->changed_status = changed_status;
}

EDGE_LOCAL void device_set_changed(pt_device_t *device, pt_changed_status_e changed_status)
{
    if (device->devices_data) {
        device_list_set_changed(device->devices_data, changed_status);
    }
    device->changed_status = changed_status;
}

EDGE_LOCAL void object_set_changed(pt_object_t *object, pt_changed_status_e changed_status)
{
    device_set_changed(object->parent, changed_status);
    object->changed_status = changed_status;
}

EDGE_LOCAL void object_instance_set_changed(pt_object_instance_t *instance, pt_changed_status_e changed_status)
{
    object_set_changed(instance->parent, changed_status);
    instance->changed_status = changed_status;
}

EDGE_LOCAL void resource_set_changed(pt_resource_t *resource, pt_changed_status_e changed_status)
{
    object_instance_set_changed(resource->parent, changed_status);
    resource->changed_status = changed_status;
}

void pt_devices_set_all_to_unregistered_state(pt_devices_t *devices)
{
    pt_device_list_internal_t *device_list = devices->list;
    ns_list_foreach_safe(pt_device_t, device, device_list)
    {
        device->state = PT_STATE_UNREGISTERED;
        device_set_changed(device, PT_CHANGED);
        // Need to set the resource values changed too to make a full reregistration.
        device_set_changed_recursive(device, PT_CHANGED);
    }
}

uint8_t *pt_resource_get_value(const pt_resource_t *resource)
{
    return resource->value;
}

void pt_resource_set_value(pt_resource_t *resource,
                           const uint8_t *value,
                           const uint32_t value_size,
                           pt_resource_value_free_callback value_free_cb)
{
    if (resource->value != value && resource->value_free != NULL) {
        resource->value_free(resource->value);
    }
    resource->value = (uint8_t *) value;
    resource->value_size = value_size;
    resource->value_free = value_free_cb;
    resource_set_changed(resource, PT_CHANGED);
}

bool pt_device_exists(const connection_id_t connection_id, const char *device_id)
{
    api_lock();
    connection_t *connection = find_connection(connection_id);
    if (!connection) {
        api_unlock();
        tr_warn("Connection not found when checking device %s", device_id);
        return false;
    }
    bool exists = NULL != pt_devices_find_device(connection->client->devices, device_id);
    api_unlock();
    return exists;
}

bool pt_device_resource_exists(const connection_id_t connection_id,
                               const char *device_id,
                               const uint16_t object_id,
                               const uint16_t object_instance_id,
                               const uint16_t resource_id)
{
    api_lock();
    connection_t *connection = find_connection(connection_id);
    if (!connection) {
        api_unlock();
        tr_warn("Connection not found when checking resource %d/%d/%d from device %s", object_id, object_instance_id, resource_id, device_id);
        return false;
    }
    pt_device_t *device = pt_devices_find_device(connection->client->devices, device_id);
    if (!device) {
        api_unlock();
        tr_warn("Device not found when checking resource %d/%d/%d from device %s", object_id, object_instance_id, resource_id, device_id);
        return false;
    }
    bool exists = NULL != pt_device_find_resource(device, object_id, object_instance_id, resource_id);
    api_unlock();
    return exists;
}

pt_status_t pt_device_set_resource_value(const connection_id_t connection_id,
                                         const char *device_id,
                                         const uint16_t object_id,
                                         const uint16_t object_instance_id,
                                         const uint16_t resource_id,
                                         const uint8_t *value,
                                         uint32_t value_len,
                                         pt_resource_value_free_callback value_free_cb)
{
    api_lock();
    connection_t *connection = find_connection(connection_id);

    if (!connection) {
        free_value(value_free_cb, (uint8_t *) value);
        api_unlock();
        return PT_STATUS_NOT_CONNECTED;
    }

    pt_device_t *device = pt_devices_find_device(connection->client->devices, device_id);
    if (!device) {
        free_value(value_free_cb, (uint8_t *) value);
        api_unlock();
        return PT_STATUS_NOT_FOUND;
    }

    pt_resource_t *resource = pt_device_find_resource(device, object_id, object_instance_id, resource_id);
    if (!resource) {
        free_value(value_free_cb, (uint8_t *) value);
        api_unlock();
        return PT_STATUS_NOT_FOUND;
    }
    pt_resource_set_value(resource, value, value_len, value_free_cb);
    api_unlock();
    return PT_STATUS_SUCCESS;
}

pt_status_t pt_device_get_resource_value(connection_id_t connection_id,
                                         const char *device_id,
                                         const uint16_t object_id,
                                         const uint16_t object_instance_id,
                                         const uint16_t resource_id,
                                         uint8_t **value_out,
                                         uint32_t *value_len_out)
{
    api_lock();

    if (!value_out || !value_len_out) {
        api_unlock();
        return PT_STATUS_INVALID_PARAMETERS;
    }
    *value_out = NULL;
    *value_len_out = 0;
    connection_t *connection = find_connection(connection_id);

    if (!connection) {
        api_unlock();
        return PT_STATUS_NOT_CONNECTED;
    }

    pt_device_t *device = pt_devices_find_device(connection->client->devices, device_id);
    if (!device) {
        api_unlock();
        return PT_STATUS_NOT_FOUND;
    }

    pt_resource_t *resource = pt_device_find_resource(device, object_id, object_instance_id, resource_id);
    if (!resource) {
        api_unlock();
        return PT_STATUS_NOT_FOUND;
    }

    *value_out = pt_resource_get_value(resource);
    *value_len_out = resource->value_size;
    api_unlock();

    return PT_STATUS_SUCCESS;
}

pt_userdata_t *pt_device_get_userdata(connection_id_t connection_id, const char *device_id)
{
    pt_userdata_t *userdata = NULL;
    api_lock();
    connection_t *connection = find_connection(connection_id);

    if (connection) {
        pt_device_t *device = pt_devices_find_device(connection->client->devices, device_id);
        if (device) {
            userdata = device->userdata;
        }
    }
    api_unlock();
    return userdata;
}

pt_userdata_t *pt_resource_get_userdata(connection_id_t connection_id,
                                        const char *device_id,
                                        const uint16_t object_id,
                                        const uint16_t object_instance_id,
                                        const uint16_t resource_id)
{
    pt_userdata_t *userdata = NULL;
    api_lock();
    connection_t *connection = find_connection(connection_id);

    if (connection) {
        pt_resource_t *resource = pt_devices_find_resource(connection->client->devices,
                                                           device_id,
                                                           object_id,
                                                           object_instance_id,
                                                           resource_id);
        if (resource) {
            userdata = resource->userdata;
        }
    }
    api_unlock();
    return userdata;
}

pt_status_t pt_device_set_userdata(connection_id_t connection_id, const char *device_id, pt_userdata_t *userdata)
{
    pt_status_t status = PT_STATUS_SUCCESS;
    api_lock();
    connection_t *connection = find_connection(connection_id);

    if (connection) {
        pt_device_t *device = pt_devices_find_device(connection->client->devices, device_id);
        if (device) {
            call_free_userdata_conditional(device->userdata);
            device->userdata = userdata;
        } else {
            status = PT_STATUS_NOT_FOUND;
        }
    } else {
        status = PT_STATUS_NOT_CONNECTED;
    }
    api_unlock();
    return status;
}

pt_status_t pt_resource_set_userdata(connection_id_t connection_id,
                                     const char *device_id,
                                     const uint16_t object_id,
                                     const uint16_t object_instance_id,
                                     const uint16_t resource_id,
                                     pt_userdata_t *userdata)
{
    pt_status_t status = PT_STATUS_SUCCESS;
    api_lock();
    connection_t *connection = find_connection(connection_id);

    if (connection) {
        pt_resource_t *resource = pt_devices_find_resource(connection->client->devices,
                                                           device_id,
                                                           object_id,
                                                           object_instance_id,
                                                           resource_id);
        if (resource) {
            call_free_userdata_conditional(resource->userdata);
            resource->userdata = userdata;
        } else {
            status = PT_STATUS_NOT_FOUND;
        }
    } else {
        status = PT_STATUS_NOT_CONNECTED;
    }
    api_unlock();
    return status;
}

