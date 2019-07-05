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

#ifndef PROTOCOL_API_INTERNAL_H
#define PROTOCOL_API_INTERNAL_H

#include "edge-rpc/rpc.h"
#include "client_type.h"
#include "edge-core/server.h"

typedef struct transport_connection {
    void *transport;
    write_func write_function;
} transport_connection_t;


typedef struct connection {
    struct context *ctx;
    client_data_t *client_data;
    transport_connection_t *transport_connection;
    void *userdata;
    connection_id_t id;
    bool connected;
} connection_t;

typedef struct protocol_api_async_request_context_ {
    uint8_t *data_ptr;
    int data_int;
    connection_id_t connection_id;
    char *request_id;
} protocol_api_async_request_context_t;

void transport_connection_t_destroy(transport_connection_t **transport_connection);
void edge_core_protocol_api_client_data_destroy(client_data_t *client_data);
bool pt_api_check_request_id(struct json_message_t *jt);
bool pt_api_check_service_availability(json_t **result);
json_t *pt_api_allocate_response_common(const char *request_id);
void protocol_api_free_async_ctx_func(rpc_request_context_t *ctx);
protocol_api_async_request_context_t *protocol_api_prepare_async_ctx(const json_t *request, const connection_id_t connection_id);

extern struct jsonrpc_method_entry_t method_table[];

#endif // PROTOCOL_API_INTERNAL_H
