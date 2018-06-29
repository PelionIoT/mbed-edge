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

typedef struct protocol_translator {
    char* name;
    bool registered;
    int id;
} protocol_translator_t;

typedef struct transport_connection {
    void *transport;
    write_func write_function;
} transport_connection_t;

struct connection {
    bool connected;
    struct context *ctx;
    protocol_translator_t *protocol_translator;
    transport_connection_t *transport_connection;
    void *userdata;
};

/*
 * \brief Create a new protocol translator
 */
protocol_translator_t *edge_core_create_protocol_translator();

void edge_core_protocol_translator_destroy(protocol_translator_t **protocol_translator);
void transport_connection_t_destroy(transport_connection_t **transport_connection);

#endif
