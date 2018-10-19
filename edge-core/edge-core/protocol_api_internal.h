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

typedef struct transport_connection {
    void *transport;
    write_func write_function;
} transport_connection_t;

struct connection {
    bool connected;
    struct context *ctx;
    client_data_t *client_data;
    transport_connection_t *transport_connection;
    void *userdata;
};

void transport_connection_t_destroy(transport_connection_t **transport_connection);
void edge_core_protocol_api_client_data_destroy(client_data_t *client_data);

extern struct jsonrpc_method_entry_t method_table[];

#endif // PROTOCOL_API_INTERNAL_H
