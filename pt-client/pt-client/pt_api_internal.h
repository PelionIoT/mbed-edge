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

#ifndef PT_API_INTERNAL_H_
#define PT_API_INTERNAL_H_

#include <jansson.h>
#include <common/test_support.h>
#include "pt-client/pt_api.h"

struct ctx_data;

struct context {
    struct event_base *ev_base;
    const char *socket_path;
    size_t json_flags;
    struct ctx_data *ctx_data;
};

struct pt_customer_callback {
    struct connection *connection;
    pt_response_handler success_handler;
    pt_response_handler failure_handler;
    void *userdata;
};

struct pt_device_customer_callback {
    struct connection *connection;
    pt_device_response_handler success_handler;
    pt_device_response_handler failure_handler;
    char* device_id;
    void *userdata;
};

typedef struct transport_connection {
    void *transport;
    write_func write_function;
} transport_connection_t;

struct connection {
    bool connected;
    struct context *ctx;
    client_data_t *client_data;
    const protocol_translator_callbacks_t *protocol_translator_callbacks;
    // Move to websocket_connection_t
    struct lws_context *lws_context;
    transport_connection_t *transport_connection;
    void *userdata;
};

/**
 * \brief Deallocate connections.
 * \param connection The array to deallocate.
 */
void pt_client_connection_destroy(struct connection **connection);

client_data_t *pt_client_create_protocol_translator(char *name);
void pt_client_protocol_translator_destroy(client_data_t **pt);

int pt_client_read_data(connection_t *connection, char *data, size_t len);

typedef bool (*pt_f_close_condition)(bool client_close);

extern struct jsonrpc_method_entry_t pt_service_method_table[];

#ifdef BUILD_TYPE_TEST
void pt_reset_api();
void pt_handle_pt_register_success(json_t *response, void *callback_data);
void pt_handle_pt_register_failure(json_t *response, void *callback_data);
void pt_handle_device_register_success(json_t *response, void *callback_data);
void pt_handle_device_register_failure(json_t *response, void *callback_data);
void pt_handle_device_unregister_success(json_t *response, void *callback_data);
void pt_handle_device_unregister_failure(json_t *response, void *callback_data);
void pt_handle_pt_write_value_success(json_t *response, void* userdata);
void pt_handle_pt_write_value_failure(json_t *response, void* userdata);
pt_status_t check_device_registration_preconditions(struct connection *connection,
                                                    pt_device_t *device, const char *action, const char *message);
pt_status_t check_registration_data_allocated(json_t *register_msg,
                                              json_t *params,
                                              json_t *j_objects,
                                              json_t *device_lifetime,
                                              json_t *device_queuemode,
                                              json_t *device_id,
                                              struct pt_device_customer_callback *customer_callback);

pt_status_t check_unregistration_data_allocated(json_t *unregister_msg,
                                                json_t *params,
                                                json_t *device_id,
                                                struct pt_device_customer_callback *customer_callback);
struct pt_device_customer_callback *allocate_device_customer_callback(
    struct connection *connection,
        pt_device_response_handler success_handler,
        pt_device_response_handler failure_handler,
        const char *device_id,
        void *userdata);

pt_status_t write_data_frame(json_t *message,
                             rpc_response_handler success_handler,
                             rpc_response_handler failure_handler,
                             rpc_free_func free_func,
                             void *customer_callback);

pt_status_t check_write_value_data_allocated(json_t *request,
                                             json_t *params,
                                             json_t *j_objects,
                                             json_t *device_id,
                                             struct pt_device_customer_callback *customer_callback);
void device_customer_callback_free_func(rpc_request_context_t *callback_data);
void customer_callback_free_func(rpc_request_context_t *callback_data);

void pt_init_check_close_condition_function(pt_f_close_condition func);

extern struct jsonrpc_method_entry_t pt_service_method_table[];

#endif

#endif
