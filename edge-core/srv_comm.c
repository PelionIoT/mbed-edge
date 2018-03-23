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
#include "common/edge_common.h"
#include "fstrm/fstrm.h"

#include <event2/event.h>
#include <event2/bufferevent.h>

#include "ns_list.h"

#include "mbed-trace/mbed_trace.h"
#include "edge-client/edge_client.h"
#define TRACE_GROUP "edge-common-srv"

static bool close_connection_common(struct connection *connection, bool free_connection);

/*
 * Process reading READY frame from writer
 */
bool process_control_frame_ready(struct connection *connection)
{
    fstrm_res res;

    if (!edge_common_match_ct(connection)) {
        return false;
    }

    fstrm_control_reset(connection->control);
    res = fstrm_control_set_type(connection->control, FSTRM_CONTROL_ACCEPT);
    if (res != fstrm_res_success) {
        return false;
    }
    res = fstrm_control_add_field_content_type(connection->control, (const uint8_t *) "jsonrpc", strlen("jsonrpc"));
    if (res != fstrm_res_success) {
        return false;
    }

    if (!edge_common_write_control_frame(connection)) {
        return false;
    }

    connection->state = CONNECTION_STATE_READING_CONTROL_START;
    return true;
}

bool process_control_frame_start(struct connection *connection)
{
    /* Match the "Content Type" against ours. */
    if (!edge_common_match_ct(connection))
        return false;

    /* Success. */
    connection->state = CONNECTION_STATE_DATA;
    tr_info("Connection ready to accept data frames from protocol translator.");
    return true;
}

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

static bool remove_connection_from_lists(struct connection *connection)
{
    bool conn_found = false;
    struct ctx_data *ctx_data = connection->ctx->ctx_data;
    tr_debug("Checking registered PTs first...");
    conn_found = remove_connection_from_list(connection, &ctx_data->registered_translators);
    if (conn_found) {
        tr_debug("Found from registered translators.");
    } else {
        conn_found = remove_connection_from_list(connection, &ctx_data->not_accepted_translators);
        if (conn_found) {
            tr_debug("Found from unregistered translators.");
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

static bool close_connection(struct connection *connection)
{
    bool result = close_connection_common(connection, false);
    uint32_t open_connections_amount = accepted_connection_count(connection);
    bool exiting = connection->ctx->ctx_data->exiting;
    connection_free(connection);
    if (exiting) {
        if (open_connections_amount == 0) {
            edgeserver_exit_event_loop();
        } else {
            tr_debug("Still waiting for %d connections", open_connections_amount);
        }
    }
    // In connection_free, the PT resource are destroyed. Therefore we should reregister.
    edgeclient_update_register_conditional(EDGECLIENT_LOCK_MUTEX);
    return result;
}

void stop_free_bufferevent(struct bufferevent *bev, short events, void *arg)
{
    if ((events & BEV_EVENT_READING) && (events & BEV_EVENT_EOF)) {
        (void) close_connection((struct connection *) arg);
    }
}

bool process_control_frame_stop(struct connection *connection)
{
    tr_debug("process_control_frame_stop");
    fstrm_res res;

    connection->state = CONNECTION_STATE_STOPPED;

    /* Setup the FINISH frame. */
    fstrm_control_reset(connection->control);
    res = fstrm_control_set_type(connection->control, FSTRM_CONTROL_FINISH);
    if (res != fstrm_res_success) {
        return false;
    }

    //Set callback to free bufferevent after FINISH frame has been sent
    bufferevent_setcb(connection->bev, NULL, NULL, stop_free_bufferevent, connection);

    /* Send the FINISH frame. */
    if (!edge_common_write_control_frame(connection)) {
        return false;
    }

    return true;
}

static bool process_control_frame_finish(struct connection *connection)
{
    tr_debug("process_control_frame_finish %p", connection);
    return close_connection(connection);
}

bool edge_common_process_control_frame(struct connection *connection, bool *destroyed_connection)
{
    fstrm_res res;
    fstrm_control_type type;

    tr_debug("Process control frame.");
    *destroyed_connection = false;
    res = fstrm_control_get_type(connection->control, &type);
    if (res != fstrm_res_success) {
        tr_warn("Control frame type get failed.");
        return false;
    }

    tr_debug("Received %s (%u).", fstrm_control_type_to_str(type), type);

    switch (connection->state) {
        case CONNECTION_STATE_READING_CONTROL_READY: {
            tr_debug("Handling READY state read");
            if (type != FSTRM_CONTROL_READY)
                return false;
            return process_control_frame_ready(connection);
        }
        case CONNECTION_STATE_READING_CONTROL_START: {
            tr_debug("Handling START state");
            if (type != FSTRM_CONTROL_START)
                return false;
            return process_control_frame_start(connection);
        }
        case CONNECTION_STATE_DATA: {
            tr_debug("Handling DATA state");
            if (type != FSTRM_CONTROL_STOP)
                return false;
            return process_control_frame_stop(connection);
        }
        case CONNECTION_STATE_READING_CONTROL_FINISH: {
            tr_debug("Handling READING_CONTROL_FINISH");
            if (type != FSTRM_CONTROL_FINISH) {
                return false;
            }
            *destroyed_connection = true;
            return process_control_frame_finish(connection);
        }

        default:
            tr_debug("Default state, return false.");
            return false;
    }
    return true;
}

static bool close_connection_common(struct connection *connection, bool free_connection)
{
    struct bufferevent *bev = connection->bev;
    bool result = remove_connection_from_lists(connection);
    if (free_connection) {
        connection_free(connection);
    }
    bufferevent_free(bev);
    return result;
}

void edge_common_process_data_frame_specific(struct connection *connection, bool *connection_destroyed)
{
    bool protocol_error;
    edge_common_process_data_frame(connection, &protocol_error);
    if (protocol_error) {
        close_connection_common(connection, true);
        *connection_destroyed = true;
        // In connection_free, the PT resource are destroyed. Therefore we should reregister.
        edgeclient_update_register_conditional(EDGECLIENT_LOCK_MUTEX);
    }
}

