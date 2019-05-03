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

#include <pthread.h>

#include "event2/event.h"
#include "event2/thread.h"

#include "libwebsockets.h"

#include "common/default_message_id_generator.h"
#include "common/websocket_comm.h"
#include "edge-rpc/rpc.h"
#include "pt-client/pt_api.h"
#include "pt-client/pt_api_internal.h"

#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP "clnt"

#define CLIENT_JSONRPC_WEBSOCKET_VERSION_PATH "/1/pt"
static generate_msg_id g_generate_msg_id;
static volatile bool close_client;
static volatile bool close_connection;

bool default_check_close_condition(bool client_close)
{
    return client_close;
}
pt_f_close_condition close_condition_impl = default_check_close_condition;

connection_t *connection_init(struct context *ctx,
                              client_data_t *client_data,
                              const protocol_translator_callbacks_t *pt_cbs,
                              void *userdata)
{
    connection_t *connection;
    // TODO: who frees this?
    connection = (connection_t*) calloc(1, sizeof(connection_t));
    if (!connection) {
        tr_err("Could not allocation internal connection structure.");
        return NULL;
    }

    connection->ctx = ctx;
    connection->client_data = client_data;
    connection->protocol_translator_callbacks = pt_cbs;
    connection->userdata = userdata;

    return connection;
}

void pt_client_set_msg_id_generator(generate_msg_id generate_msg_id)
{
    if (generate_msg_id == NULL) {
        g_generate_msg_id = edge_default_generate_msg_id;
    } else {
        g_generate_msg_id = generate_msg_id;
    }
}

static void clean(connection_t **connection)
{
    pt_client_connection_destroy(connection);
}

static void trigger_close_connection()
{
    close_connection = true;
}

static void trigger_close_client()
{
    trigger_close_connection();
    close_client = true;
}

void pt_client_shutdown(connection_t *connection)
{
    if(connection) {
        if(connection->ctx) {
            event_base_loopbreak(connection->ctx->ev_base);
        }
    }
    trigger_close_client();
}

static int check_protocol_translator_callbacks(const protocol_translator_callbacks_t *pt_cbs)
{
    if (pt_cbs->connection_ready_cb == NULL || pt_cbs->received_write_cb == NULL || pt_cbs->connection_shutdown_cb == NULL) {
        return 1;
    }
    return 0;
}

int pt_client_write_data(connection_t *connection, char *data, size_t len)
{
    websocket_connection_t *websocket_connection = (websocket_connection_t*) connection->transport_connection->transport;
    int ret = send_to_websocket((uint8_t *) data, len, websocket_connection);
    if (!ret) {
        return 0;
    } else {
        tr_err("sending to websocket failed returning %d", ret);
        return 1;
    }
}

int pt_client_read_data(connection_t *connection, char *data, size_t len)
{
    tr_debug("Reading data from connection.");
    bool protocol_error;
    int rc = rpc_handle_message(data,
                                len,
                                connection,
                                (struct jsonrpc_method_entry_t *) connection->client_data->method_table,
                                connection->transport_connection->write_function,
                                &protocol_error,
                                false /* mutex_acquired */);
    if (protocol_error) {
        return 1;
    }

    if (rc != 0) {
        return 2;
    }
    return 0;
}

static void websocket_disconnected(websocket_connection_t *websock_conn)
{
    struct connection *conn = NULL;
    conn = websock_conn->conn;
    tr_debug("websocket_disconnected: connection %p - breaking event loop", conn);
    conn->connected = false;
    conn->protocol_translator_callbacks->disconnected_cb(conn, conn->userdata);
    event_base_loopbreak(conn->ctx->ev_base);
}

int callback_edge_client_protocol_translator(struct lws *wsi,
                                             enum lws_callback_reasons reason,
                                             void *user,
                                             void *in,
                                             size_t len)
{
    const char *which = "http";

    websocket_connection_t *websock_conn = (websocket_connection_t*) user;
    struct connection *conn = NULL;

    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED: {
            tr_debug("lws_callback_client_established");
            conn = websock_conn->conn;
            conn->connected = true;
            if (g_generate_msg_id == NULL) {
                pt_client_set_msg_id_generator(NULL);
            }
            rpc_set_generate_msg_id(g_generate_msg_id);
            conn->protocol_translator_callbacks->connection_ready_cb(conn, conn->userdata);
            break;
        }
        case LWS_CALLBACK_CLOSED: {
            tr_debug("lws_callback_closed");
            websocket_disconnected(websock_conn);
            break;
        }

        case LWS_CALLBACK_CLIENT_RECEIVE: {
            tr_debug("lws_callback_client_receive: len(%zu), msg(%.*s)", len, (int) len, (char *) in);
            if (websocket_add_msg_fragment(websock_conn, in, len) != 0) {
                tr_err("lws_callback_client_receive: Message payload fragment concatenation failed. Closing connection.");
                trigger_close_connection();
            }

            const size_t remaining_bytes = lws_remaining_packet_payload(wsi);
            if (remaining_bytes && !lws_is_final_fragment(wsi)) {
                tr_debug("lws_callback_client_receive: Message fragmented, wait for more content.");
            } else {
                tr_debug("lws_callback_client_receive: Final fragment and no remaining bytes. Message: (%.*s)", (uint32_t) websock_conn->msg_len, websock_conn->msg);
                int ret = pt_client_read_data(websock_conn->conn, (char *) websock_conn->msg, websock_conn->msg_len);
                websocket_reset_message(websock_conn);
                if (ret == 1) {
                    tr_err("Protocol error happened when receiving data from edge-core. Closing connection!");
                    trigger_close_connection();
                    lws_callback_on_writable(wsi);
                }
            }
            break;
        }

        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR: {
            websock_conn->conn->connected = false;
            websock_conn->conn->client_data->registered = false;
            tr_err("lws_callback_client_connection_error");
            tr_err("client_connection_error: %s: %s", which, in ? (char *) in : "(null)");
            break;
        }

        case LWS_CALLBACK_CLIENT_WRITEABLE: {
            tr_debug("lsw_callback_client_writeable: wsi %p writeable", wsi);
            if (close_connection) {
                tr_warn("lws_callback_client_writeable: closing client, writing blocked.");
                lws_close_reason(wsi, LWS_CLOSE_STATUS_GOINGAWAY, NULL, 0);
                return -1;
            }

            websocket_message_t *message = ns_list_get_first(websock_conn->sent);
            if (message == NULL) {
                tr_warn("lws_callback_client_writeable: was supposed to write message, but none found!");
                break;
            }

            unsigned char *buf = calloc(1, LWS_SEND_BUFFER_PRE_PADDING + message->len);
            if (!buf) {
                tr_err("Could not allocate buffer for data to write.");
                return -1;
            }
            tr_debug("lws_callback_client_send: %zu bytes '%.*s'",
                     message->len,
                     (int) message->len,
                     (char *) message->bytes);
            memcpy(buf + LWS_SEND_BUFFER_PRE_PADDING, message->bytes, message->len);
            lws_write(wsi, buf + LWS_SEND_BUFFER_PRE_PADDING, message->len, LWS_WRITE_TEXT);
            free(buf);
            ns_list_remove(websock_conn->sent, message);
            websocket_message_t_destroy(message);

            if (ns_list_count(websock_conn->sent) > 0) {
                /*
                 * There are still messages to send, and we can't rely on the lws
                 * to generate the writeable callbacks.
                 * Thus we need to call on_writable to ensure that the messages
                 * don't get stuck.
                 */
                lws_callback_on_writable(wsi);
            }
            break;
        }

        case LWS_CALLBACK_WSI_DESTROY: {
            tr_debug("lsw_callback_client_wsi_destroyed: wsi %p", wsi);
            websocket_disconnected(websock_conn);
            break;
        }

        default: {
            tr_debug("lws callback: %s wsi: %p", websocket_lws_callback_reason(reason), wsi);
            break;
        }
    }

    return 0;
}

static const struct lws_protocols protocols[] = {
    { "edge_protocol_translator",
      callback_edge_client_protocol_translator,
      sizeof(websocket_connection_t),
      2048,
      1,
      NULL,
      2048 },
    { NULL, NULL, 0, 0, 0, NULL, 0 } /* end */
};

static const struct lws_extension exts[] = {
    {
        "permessage-deflate",
        lws_extension_callback_pm_deflate,
        "permessage-deflate; client_no_context_takeover"
    },
    {
        "deflate-frame",
        lws_extension_callback_pm_deflate,
        "deflate_frame"
    },
    { NULL, NULL, NULL /* terminator */ }
};

static void websocket_connection_t_destroy(websocket_connection_t **wct)
{
    if (*wct) {
        ns_list_foreach_safe(websocket_message_t, cur, (*wct)->sent) {
            free(cur->bytes);
            ns_list_remove((*wct)->sent, cur);
            free(cur);
        }
        free((*wct)->sent);

        lws_context_destroy((*wct)->lws_context);
        free(*wct);
    }
    *wct = NULL;
}

static client_data_t *initialize_protocol_translator(const protocol_translator_callbacks_t *pt_cbs, const char *name)
{
    if (check_protocol_translator_callbacks(pt_cbs)) {
        tr_err("Protocol translator callbacks not set.");
        return NULL;
    }

    return pt_client_create_protocol_translator(strdup(name));
}

static websocket_connection_t *initialize_websocket_connection()
{

    // Initialize web connection structure for this client
    websocket_connection_t *websocket_conn = (websocket_connection_t*) calloc(1, sizeof(websocket_connection_t));
    websocket_conn->sent = (websocket_message_list_t*) calloc(1, sizeof(websocket_message_list_t));

    if (!websocket_conn || !websocket_conn->sent) {
        tr_err("Could not allocate protocol translator connection structures.");
        websocket_connection_t_destroy(&websocket_conn);
        return NULL;
    }

    ns_list_init(websocket_conn->sent);

    return websocket_conn;
}

static struct lws_context *libwebsocket_create_context(struct event_base *ev_base, const char *socket_path)
{
    // Initialize the libwebsocket connection info
    void *foreign_loops[1];
    struct lws_context_creation_info info;
    memset(&info, 0, sizeof info);
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;
    info.iface = socket_path;
    info.extensions = exts;
    info.options = 0 | LWS_SERVER_OPTION_LIBEVENT;
    info.options = info.options | LWS_SERVER_OPTION_UNIX_SOCK;
    foreign_loops[0] = ev_base;
    info.foreign_loops = foreign_loops;

    return lws_create_context(&info);
}

static struct lws *initialize_libwebsocket_connection_info(struct event_base *ev_base,
                                                           websocket_connection_t *websocket_conn,
                                                           struct lws_context *context)
{
    struct lws_client_connect_info info;
    static struct lws *wsi_edge_protocol_translator;
    memset(&info, 0, sizeof(struct lws_client_connect_info));

    info.path = CLIENT_JSONRPC_WEBSOCKET_VERSION_PATH;
    info.port = 7682;
    info.address = "localhost";
    info.context = context;
    info.ssl_connection = 0;
    info.host = info.address;
    info.origin = info.address;
    info.ietf_version_or_minus_one = -1;
    info.protocol = "edge_protocol_translator";
    info.pwsi = &wsi_edge_protocol_translator;
    info.userdata = websocket_conn;
    struct lws *wsi = lws_client_connect_via_info(&info);

    return wsi;
}

transport_connection_t *initialize_transport_connection(websocket_connection_t *websocket_connection)
{
    transport_connection_t *transport_connection = (transport_connection_t*) malloc(sizeof(transport_connection_t));
    if (!transport_connection) {
        tr_err("Could not allocate transport connection structure.");
        return NULL;
    }
    transport_connection->write_function = pt_client_write_data;
    transport_connection->transport = websocket_connection;
    return transport_connection;
}

void transport_connection_t_destroy(transport_connection_t **transport_connection)
{
    if (transport_connection && *transport_connection) {
        free(*transport_connection);
        *transport_connection = NULL;
    }
}

#ifdef BUILD_TYPE_TEST
void pt_init_check_close_condition_function(pt_f_close_condition func)
{
    close_condition_impl = func;
}
#endif

static int configure_libevent()
{
    if (evthread_use_pthreads() == 0) {
        tr_debug("Libevent evthread configured to use pthreads.");
        return 0;
    }
    tr_error("Libevent evthread not configured to use pthreads!");
    return 1;
}

int pt_client_start(const char *socket_path,
                    const char *name,
                    const protocol_translator_callbacks_t *pt_cbs,
                    void *userdata,
                    connection_t **connection)
{
    tr_debug("socket_path: %s, name=%s ", socket_path, name);
    close_client = false;
    int rc = 1;
    // Backoff time in seconds
    int backoff_time = 1;
    int tries = 0;
    websocket_connection_t *websocket_conn = NULL;
    client_data_t *client_data = NULL;
    transport_connection_t *transport_connection = NULL;
    struct event_base *ev_base = NULL;

    struct context *program_context = (struct context*) calloc(1, sizeof(struct context));
    if (!program_context) {
        tr_err("Could not allocate program context.");
        goto cleanup;
    }
    program_context->socket_path = socket_path;
    program_context->json_flags = JSON_COMPACT;

    rpc_init();

    /* Configure libevent */
    if (configure_libevent() != 0) {
        tr_err("Libevent configuring failed!");
        rc = 1;
        goto cleanup;
    }

    ev_base = event_base_new();
    if (!ev_base) {
        tr_err("Couldn't create client event loop.");
        goto cleanup;
    }
    program_context->ev_base = ev_base;

    client_data = initialize_protocol_translator(pt_cbs, name);
    // Set up connection for client code to track.
    *connection = connection_init(program_context, client_data, pt_cbs, userdata);
    websocket_set_log_level_and_emit_function();

    while(!close_client) {
        tr_debug("Connecting to Edge Core.");
        close_connection = false;

        websocket_conn = initialize_websocket_connection();
        transport_connection = initialize_transport_connection(websocket_conn);

        /* Wire the connection and websocket connection together */
        websocket_conn->conn = *connection;
        (*connection)->transport_connection = transport_connection;
        struct lws_context *context = libwebsocket_create_context(ev_base, socket_path);
        websocket_conn->lws_context = context;
        struct lws *wsi = initialize_libwebsocket_connection_info(ev_base, websocket_conn, context);
        if (wsi) {
            websocket_conn->wsi = wsi;

            int ret = event_base_dispatch(ev_base);
            if (ret != 0) {
                tr_err("event_base_dispatch failed: %d", ret);
            } else {
                tries = 0;
            }
        }
        if (*connection && !close_condition_impl(close_client)) {
            // try to reconnect to the server
            websocket_connection_t_destroy(&websocket_conn);
            transport_connection_t_destroy(&transport_connection);
            (*connection)->transport_connection = NULL;

            if (!close_client) {
                if (tries < 5) {
                    tries++;
                    backoff_time = tries * 1;
                } else {
                    backoff_time = 5;
                }
                tr_info("Waiting a backoff time of %d", backoff_time);
                sleep(backoff_time);
            }
        } else {
            tr_err("Connection %p has been destroyed. Breaking loop in pt_client_start.", *connection);
            break;
        }
    }

    tr_info("Protocol translator api eventloop closed.");
cleanup:
    clean(connection);
    websocket_connection_t_destroy(&websocket_conn);
    transport_connection_t_destroy(&transport_connection);
    pt_client_protocol_translator_destroy(&client_data);
    event_base_free(ev_base);
    free(program_context);
    program_context = NULL;
    if((*connection) != NULL) {
        (*connection)->ctx = NULL;
    }
    libevent_global_shutdown();
    rpc_destroy_messages();
    rpc_deinit();
    return rc;
}

void pt_client_final_cleanup()
{
    // Deprecated
}
