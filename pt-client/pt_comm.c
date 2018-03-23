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

#include "common/edge_common.h"
#include "common/test_support.h"
#include "pt-client/pt_api.h"
#include "fstrm/fstrm.h"

#include <event2/event.h>
#include <event2/bufferevent.h>

#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP "edge-common-clnt"

/*
 * Send the READY control to server
 */
static bool process_control_frame_ready_write(struct connection *connection)
{
    fstrm_res res;

    const uint8_t *ct = NULL;
    size_t len_ct = 0;
    size_t n_ct = 0;

    res = fstrm_control_get_num_field_content_type(connection->control, &n_ct);
    if (res != fstrm_res_success) {
        return false;
    }

    for (size_t i = 0; i < n_ct; i++) {
        res = fstrm_control_get_field_content_type(connection->control, i, &ct,
                                                   &len_ct);

        if (res != fstrm_res_success) {
            return false;
        }
    }

    if (!edge_common_match_ct(connection)) {
        return false;
    }

    if (!edge_common_write_control_frame(connection)) {
        return false;
    }

    connection->state = CONNECTION_STATE_READING_CONTROL_ACCEPT;

    return true;
}

/*
 * Read the ACCEPT frame from server
 */
bool process_control_frame_accept(struct connection *connection)
{
    fstrm_res res;

    /* Match the "Content Type" against ours. */
    if (!edge_common_match_ct(connection))
        return false;

    res = fstrm_control_set_type(connection->control, FSTRM_CONTROL_START);
    if (res != fstrm_res_success)
        return false;

    /* Write the START frame. */
    if (!edge_common_write_control_frame(connection)) {
        return false;
    }

    /* Success. */
    connection->state = CONNECTION_STATE_DATA;
    tr_info("Connection ready to pass data frames.");

    connection->protocol_translator_callbacks->connection_ready_cb(connection, connection->userdata);
    return true;
}

EDGE_LOCAL void stop_free_bufferevent(struct bufferevent *bev, short events, void *arg)
{
    (void) bev;
    tr_debug("stop_free_bufferevent events=0x%x connection=%p", events, arg);

    if ((events & BEV_EVENT_READING) && (events & BEV_EVENT_EOF)) {
        struct event_base *base = bufferevent_get_base(bev);
        tr_debug("EOF received. Breaking the event loop.");
        event_base_loopexit(base, NULL);
    }
}

bool process_control_frame_stop(struct connection *connection)
{
    fstrm_res res;
    connection->state = CONNECTION_STATE_STOPPED;

    /* Setup the FINISH frame. */
    fstrm_control_reset(connection->control);
    res = fstrm_control_set_type(connection->control, FSTRM_CONTROL_FINISH);
    if (res != fstrm_res_success)
        return false;

    //Set callback to free bufferevent after FINISH frame has been sent
    bufferevent_setcb(connection->bev, NULL, NULL, stop_free_bufferevent, connection);

    /* Send the FINISH frame. */
    if (!edge_common_write_control_frame(connection)) {
        tr_warn("Writing FINISH frame failed.");
        return false;
    }

    // Return true on successful stop
    return true;
}

static bool process_control_frame_finish(struct connection *connection)
{
    tr_debug("process_control_frame_finish");
    connection->state = CONNECTION_STATE_STOPPED;

    event_base_loopexit(connection->ctx->ev_base, NULL);

    //Return true on successful stop
    return true;
}

void edge_common_process_data_frame_specific(struct connection *connection, bool *destroyed_connection)
{
    edge_common_process_data_frame(connection, destroyed_connection);
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

    tr_debug("Received %s (%u) in connection state(%d).", fstrm_control_type_to_str(type), type, connection->state);

    switch (connection->state) {
        case CONNECTION_STATE_WRITING_CONTROL_READY: {
            tr_debug("Handling READY state write");
            if (type != FSTRM_CONTROL_READY)
                return false;
            return process_control_frame_ready_write(connection);
        }
        case CONNECTION_STATE_READING_CONTROL_ACCEPT: {
            tr_debug("Handling ACCEPTED state");
            if (type != FSTRM_CONTROL_ACCEPT)
                return false;
            return process_control_frame_accept(connection);
        }
        case CONNECTION_STATE_READING_CONTROL_FINISH: {
            tr_debug("Handling FINISH state");
            if (type != FSTRM_CONTROL_FINISH)
                return false;
            return process_control_frame_finish(connection);
        }
        case CONNECTION_STATE_DATA: {
            tr_debug("Handling DATA state");
            if (type != FSTRM_CONTROL_STOP) {
                return false;
            }
            return process_control_frame_stop(connection);
        }
        default:
            tr_debug("Default state, return false.");
            return false;
    }
    return true;
}
