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

#include "edge-core/server.h"
#include "edge-core/edge_server.h"
#include "edge-core/srv_comm.h"
#include "common/websocket_comm.h"
#include "edge-core/websocket_serv.h"

#include "event2/event.h"
#include "event2/bufferevent.h"

#include "ns_list.h"

#include "mbed-trace/mbed_trace.h"
#include "edge-client/edge_client.h"
#define TRACE_GROUP "edge-common-srv"

static bool close_connection_common(struct connection *connection, bool free_connection);

static bool remove_connection_from_list(struct connection *connection, connection_elem_list *list)
{
    bool conn_found = false;
    ns_list_foreach_safe(struct connection_list_elem, cur, list) {
        if (cur->conn == connection) {
            ns_list_remove(list, cur);
            free(cur);
            conn_found = true;
            break;
        }
    }
    return conn_found;
}

/**
 * \brief Finds the connection from registered translators.
 *        Note: it doesn't find it from not registered_translators though!
 */
connection_t *srv_comm_find_connection(connection_id_t connection_id)
{
    connection_t *connection = NULL;
    ns_list_foreach_safe(struct connection_list_elem, cur, edge_server_get_registered_translators())
    {
        if (connection_id == cur->conn->id) {
            connection = cur->conn;
            break;
        }
    }

    return connection;
}

static bool remove_connection_from_lists(struct connection *connection)
{
    struct ctx_data *ctx_data = connection->ctx->ctx_data;
    tr_debug("Checking registered PTs first...");
    bool conn_found = remove_connection_from_list(connection, &ctx_data->registered_translators);
    if (conn_found) {
        tr_debug("Found from registered translators.");
    } else {
        conn_found = remove_connection_from_list(connection, &ctx_data->not_accepted_translators);
        if (conn_found) {
            tr_debug("Found from not accepted translators.");
        } else {
            tr_warn("Connection %p was not found in lists.", connection);
        }
    }
    return conn_found;
}

static uint32_t accepted_connection_count(struct connection *connection)
{
    struct ctx_data *ctx_data = connection->ctx->ctx_data;
    return ns_list_count(&ctx_data->registered_translators);
}

bool close_connection(struct connection *connection)
{
    tr_debug("close_connection %p", connection);
    websocket_server_connection_destroy((websocket_connection_t *) connection->transport_connection->transport);
    transport_connection_t_destroy(&connection->transport_connection);

    bool result = close_connection_common(connection, false);
    uint32_t open_connections_amount = accepted_connection_count(connection);
    bool exiting = connection->ctx->ctx_data->exiting;
    int32_t endpoints_removed = (int32_t) connection_free(connection);
    edgeserver_change_number_registered_endpoints_by_delta(-endpoints_removed);

    if (exiting) {
        if (open_connections_amount == 0) {
            edgeserver_exit_event_loop();
        } else {
            tr_debug("Still waiting for %d connections", open_connections_amount);
        }
    }
    // In connection_free, the PT resource are destroyed. Therefore we should reregister.
    edgeclient_update_register_conditional();
    return result;
}

void close_connection_trigger(struct connection *connection)
{
    tr_debug("close_connection_trigger %p", connection);

    struct websocket_connection *websocket_conn = (websocket_connection_t*) connection->transport_connection->transport;
    websocket_close_connection_trigger(websocket_conn);
}

static bool close_connection_common(struct connection *connection, bool free_connection)
{
    bool result = remove_connection_from_lists(connection);
    if (free_connection) {
        connection_free(connection);
    }
    return result;
}

int edge_core_write_data_frame_websocket(struct connection *connection, char *data, size_t len)
{
    if (((websocket_connection_t*)connection->transport_connection->transport)->to_close) {
        tr_info("Protocol translator is closing down, dropping message: %.*s", (int) len, data);
        return -1;
    }
    return send_to_websocket((uint8_t *) data, len, connection->transport_connection->transport);
}

void edge_core_process_data_frame_websocket(struct connection *connection,
                                            bool *protocol_error,
                                            size_t len,
                                            const char *data)
{
    (void) rpc_handle_message(data,
                              len,
                              connection,
                              connection->client_data->method_table,
                              edge_core_write_data_frame_websocket,
                              protocol_error,
                              false /* mutex_acquired */);
}
