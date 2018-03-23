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

#include <netinet/tcp.h>
#include <event2/bufferevent.h>
#include <event2/thread.h>
#include <time.h>

#include "fstrm/fstrm.h"
#include "common/edge_common.h"
#include "pal.h"

#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP "edge-common"

char *timestamp_prefix;

palMutexID_t TraceMutex;

void (*_event_cb)(struct bufferevent *bev, short events, void *arg);

protocol_translator_t *edge_common_create_protocol_translator()
{
    protocol_translator_t *pt = calloc(1, sizeof(protocol_translator_t));
    // Set the id to invalid
    if (NULL != pt) {
        pt->id = -1;
    }
    return pt;
}

void edge_common_init_event_cb(void (*event_cb)(struct bufferevent *bev, short events, void *arg))
{
    _event_cb = event_cb;
}

bool edge_common_match_ct(struct connection *connection)
{
    fstrm_res res;
    res = fstrm_control_match_field_content_type(connection->control, (const uint8_t *) "jsonrpc", strlen("jsonrpc"));
    if (res != fstrm_res_success) {
        tr_warn("CT not matching.");
        return false;
    }
    return true;
}

bool send_frame(struct connection *connection, const void *data, size_t size)
{
    if (!connection) {
        return false;
    }
    if (bufferevent_write(connection->bev, data, size) != 0) {
        tr_warn("Failed to write.");
        return false;
    }
    tr_debug("Writing frame done.");
    return true;
}

bool edge_common_write_control_frame(struct connection *connection)
{
    fstrm_res res;
    uint8_t control_frame[FSTRM_CONTROL_FRAME_LENGTH_MAX];
    size_t len_control_frame = sizeof(control_frame);

    /* Encode the control frame. */
    res = fstrm_control_encode(connection->control, control_frame, &len_control_frame, FSTRM_CONTROL_FLAG_WITH_HEADER);
    if (res != fstrm_res_success)
        return false;

    /* Send the control frame. */
    fstrm_control_type type;
    if (fstrm_control_get_type(connection->control, &type) == fstrm_res_failure) {
        return false;
    }
    tr_debug("Sending %s (%d).", fstrm_control_type_to_str(type), type);

    if (!send_frame(connection, control_frame, len_control_frame))
        return false;

    /* Success. */
    return true;
}

int32_t edge_common_construct_and_send_message(struct connection *connection,
                                               json_t *message,
                                               rpc_response_handler success_handler,
                                               rpc_response_handler failure_handler,
                                               rpc_free_func free_func,
                                               void *customer_callback)
{
    void *message_entry;
    char *data;
    char *message_id;
    int rc = rpc_construct_message(message, success_handler, failure_handler,
                                   free_func, customer_callback, &message_entry,
                                   &data, &message_id);

    if (rc == 1 || data == NULL) {
        json_decref(message);
        free_func(customer_callback);
        return -1;
    }

    /*
     * Add message to list before writing to socket.
     * There is a condition when other end may respond back before
     * having the message in the message list.
     */
    rpc_add_message_entry_to_list(message_entry);

    tr_debug("Data from rpc_construct_message, %s", data);
    if (!edge_common_write_data_frame(connection, data, strlen(data))) {
        remove_message_for_id(message_id);
        rpc_dealloc_message_entry(message_entry);
        free(message_id);
        return -2;
    }
    free(message_id);

    return 0;
}

bool edge_common_write_data_frame(struct connection *connection, char *data, size_t len_data)
{
    tr_debug("Writing payload: \"%s\" -> length: %zu", data, len_data);
    /* 8 byte char data and 32 byte length data */
    size_t frame_size = sizeof(uint32_t) + len_data;
    uint8_t dt_frame[frame_size];
    memset(&dt_frame, 0, frame_size);
    tr_debug("Reserved size: %zu", frame_size);

    uint32_t payload_size = htonl(len_data);
    memcpy(dt_frame, &payload_size, sizeof(payload_size));

    for (int i = 0; i < len_data; i++) {
        dt_frame[i + 4] = data[i];
    }
    free(data);
    return send_frame(connection, dt_frame, frame_size);
}

static bool can_read_full_frame(struct connection *connection)
{
    uint32_t tmp[2] = { 0 };

    connection->len_frame_total = 0;

    if (connection->len_buffer < sizeof(uint32_t))
        return false; // frame length field has not arrived

    evbuffer_copyout(connection->ev_input, &tmp[0], sizeof(uint32_t));
    connection->len_frame_payload = ntohl(tmp[0]);

    connection->len_frame_total += sizeof(uint32_t);
    connection->len_frame_total += connection->len_frame_payload;

    if (connection->len_frame_payload == 0) {
        /* Control frame */
        uint32_t len_control_frame = 0;

        if (connection->len_buffer < 2 * sizeof(uint32_t)) {
            /* Control frame length not arrived, input not drained */
            return false;
        }

        evbuffer_copyout(connection->ev_input, &tmp[0], 2 * sizeof(uint32_t));
        len_control_frame = ntohl(tmp[1]);

        connection->len_frame_total += sizeof(uint32_t);

        if (len_control_frame < sizeof(uint32_t) || len_control_frame > FSTRM_CONTROL_FRAME_LENGTH_MAX) {
            /* Enforce control frame length */
            tr_warn("Frame size incorrect.");
            _event_cb(connection->bev, BEV_EVENT_ERROR, connection);
            return false;
        }
        connection->len_frame_total += len_control_frame;
    }

    if (connection->len_buffer < connection->len_frame_total) {
        /* frame not fully arrived */
        tr_warn("Frame did not arrive fully. Incomplete message.");
        return false;
    }
    return true; // Full frame available
}

static bool read_control_frame(struct connection *connection)
{
    fstrm_res res;
    uint8_t *control_frame = NULL;

    if (connection->len_frame_total >= FSTRM_CONTROL_FRAME_LENGTH_MAX) {
        /* malformed */
        return false;
    }

    control_frame = evbuffer_pullup(connection->ev_input, connection->len_frame_total);
    if (!control_frame) {
        /* malformed */
        return false;
    }

    res = fstrm_control_decode(connection->control, control_frame, connection->len_frame_total,
                               FSTRM_CONTROL_FLAG_WITH_HEADER);

    if (res != fstrm_res_success) {
        /* malformed */
        return false;
    }

    evbuffer_drain(connection->ev_input, connection->len_frame_total);
    return true;
}

void edge_common_process_data_frame(struct connection *connection, bool *protocol_error)
{
    tr_debug("Process data, total %d -> payload %d.", connection->len_frame_total, connection->len_frame_payload);

    /* remove payload size */
    evbuffer_drain(connection->ev_input, sizeof(uint32_t));

    char *data = malloc(connection->len_frame_payload + 1);
    if (NULL == data) {
        tr_error("edge_common_process_data_frame - malloc fail");
        return;
    }
    /* add null-termination for the trace */
    memset(data, 0, connection->len_frame_payload + 1);

    size_t len = bufferevent_read(connection->bev, data, connection->len_frame_payload);
    tr_debug("Received: (%zu) %s.", len, data);
    (void) rpc_handle_message(data, len, connection, edge_common_write_data_frame, protocol_error);
}

void edge_common_read_cb(struct bufferevent *bev, void *ctx)
{
    tr_debug("Read callback processing.");
    struct connection *connection = (struct connection*) ctx;
    bool destroyed_connection = false;
    connection->bev = bev;
    connection->ev_input = bufferevent_get_input(connection->bev);
    connection->ev_output = bufferevent_get_output(connection->bev);

    for (;;) {
        connection->len_buffer = evbuffer_get_length(connection->ev_input);

        if (connection->len_buffer <= 0) {
            return;
        }

        /* if full frame not available return */
        if (!can_read_full_frame(connection)) {
            return;
        }

        if (connection->len_frame_payload > 0) {
            /* Data frame */
            edge_common_process_data_frame_specific(connection, &destroyed_connection);
            if (destroyed_connection) {
                break;
            }
        } else {
            /* Control frames */
            tr_debug("Reading control frame.");
            if (!read_control_frame(connection)) {
                /* malformed frame */
                tr_err("Malformed control frame.");
                _event_cb(connection->bev, BEV_EVENT_ERROR, connection);
                return;
            }

            if (!edge_common_process_control_frame(connection, &destroyed_connection)) {
                /* invalid state, eos */
                tr_err("Invalid control frame.");
                _event_cb(connection->bev, BEV_EVENT_ERROR, connection);
                return;
            }
            if (destroyed_connection) {
                break;
            }
        }
    }
}

void edge_common_connection_destroy(struct connection **connection)
{
    if ((*connection)) {
        (*connection)->protocol_translator_callbacks->connection_shutdown_cb(connection, (*connection)->userdata);
        if ((*connection)->bev) {
            bufferevent_free((*connection)->bev);
            (*connection)->bev = NULL;
        }

        fstrm_control_destroy(&(*connection)->control);
        free(*connection);
        *connection = NULL;
    }
}

/*
 * Options:
 * Disable Nagle-algorithm, TCP_NODELAY
 *
 * Returns 0 if all good
 */
int edge_common_set_socket_options(evutil_socket_t fd)
{
    int flag = 1;
    int rc = 0;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int)) < 0) {
        tr_warn("Could not set socket TCP_NODELAY for the socket.");
        rc = 1;
    }

    return rc;
}

int edge_common_configure_libevent()
{
    if (evthread_use_pthreads() == 0) {
        tr_debug("Libevent evthread configured to use pthreads.");
        return 0;
    }
    tr_error("Libevent evthread not configured to use pthreads!");
    return 1;
}

bool edge_common_write_stop_frame(struct connection *connection)
{
    fstrm_res res;

    connection->state = CONNECTION_STATE_READING_CONTROL_FINISH;

    res = fstrm_control_set_type(connection->control, FSTRM_CONTROL_STOP);
    bool rc = true;
    if (res != fstrm_res_success) {
        tr_warn("Could not set control frame type, not sending STOP");
        rc = false;
    }
    else {
        if (!edge_common_write_control_frame(connection)) {
            tr_warn("Could not write STOP frame");
            rc = false;
        }
    }
    return rc;
}

void trace_mutex_init() {
    palStatus_t err;
    err = pal_osMutexCreate(&TraceMutex);
    assert(err == PAL_SUCCESS);
    (void)err;
}
void trace_mutex_wait() {
    palStatus_t err;
    err = pal_osMutexWait(TraceMutex, PAL_RTOS_WAIT_FOREVER);
    assert(err == PAL_SUCCESS);
    (void)err;
}
void trace_mutex_release() {
    palStatus_t err;
    err = pal_osMutexRelease(TraceMutex);
    assert(err == PAL_SUCCESS);
    (void)err;
}

char* trace_prefix(size_t size){

#define failed_time_prefix "No time! "

    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    if (NULL != t) {
        strftime(timestamp_prefix, TIMESTAMP_SIZE, "%F %H:%M:%S ", t);
    }
    else {
        strncpy(timestamp_prefix, failed_time_prefix, TIMESTAMP_SIZE);
    }
    return timestamp_prefix;
}
