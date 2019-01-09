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

#include <event2/listener.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/thread.h>
#include <event2/http.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "edge-core/client_type.h"
#include "edge-core/protocol_api.h"
#include "edge-core/protocol_api_internal.h"
#include "edge-core/http_server.h"
#include "edge-core/server.h"
#include "edge-client/edge_client.h"
#include "edge-core/srv_comm.h"
#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP "serv"

struct context;
struct connection;

struct connection* connection_init(struct context *ctx, client_data_t *client_data)
{
    struct connection *connection = (struct connection *)calloc(1, sizeof(struct connection));

    connection->client_data = client_data;
    connection->ctx = ctx;
    return connection;
}

void connection_destroy(struct connection **connection)
{
    if ((*connection)) {
        free(*connection);
        *connection = NULL;
    }
}

uint32_t connection_free(struct connection *connection)
{
    tr_debug("Freeing connection structure %p", connection);
    edgeclient_remove_resources_owned_by_client((void *) connection);
    uint32_t num_endpoints_removed = edgeclient_remove_objects_owned_by_client((void *) connection);

    edge_core_client_data_destroy(&connection->client_data);

    connection_destroy(&connection);
    return num_endpoints_removed;
}

static int configure_libevent()
{
    if (evthread_use_pthreads() == 0) {
        tr_debug("Libevent evthread configured to use pthreads.");
        return 0;
    }
    tr_error("Libevent evthread not configured to use pthreads!");
    return 1;
}

bool create_server_event_loop(struct context *ctx, int http_port)
{
    init_protocol();

    /* Configure libevent */
    if (configure_libevent() != 0) {
        tr_err("Libevent configuring failed!");
        return false;
    }

    ctx->ev_base = event_base_new();
    if (!ctx->ev_base) {
        tr_err("Cannot create event base");
        return false;
    }

    bool http_server_init_ok = http_server_init(ctx, http_port);
    if (!http_server_init_ok) {
        tr_err("Cannot create http server to port %d.", http_port);
    }

    if (!http_server_init_ok) {
        event_base_free(ctx->ev_base);
        ctx->ev_base = NULL;
        return false;
    }

    return true;
}
