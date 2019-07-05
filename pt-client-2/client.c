/*
 * ----------------------------------------------------------------------------
 * Copyright 2019 ARM Ltd.
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1 // needed for strdup
#endif

#include <pthread.h>
#include <assert.h>

#include "event2/event.h"
#include "event2/thread.h"

#include "libwebsockets.h"

#include "common/default_message_id_generator.h"
#include "common/websocket_comm.h"
#include "edge-rpc/rpc.h"
#include "pt-client-2/pt_api.h"
#include "pt-client-2/pt_api_internal.h"

#include "mbed-trace/mbed_trace.h"
#include "edge-rpc/rpc_timeout_api.h"
#define TRACE_GROUP "clnt"

#define CLIENT_JSONRPC_WEBSOCKET_VERSION_PATH "/1/pt"

connection_list_t connection_list;
connection_id_t next_connection_id = 1;

static int check_protocol_translator_callbacks(const protocol_translator_callbacks_t *pt_cbs);
EDGE_LOCAL bool create_client_connection(pt_client_t *client);
EDGE_LOCAL void websocket_connection_t_destroy(websocket_connection_t **wct);
EDGE_LOCAL void transport_connection_t_destroy(transport_connection_t **transport_connection);
static void trigger_reconnection_or_exit(pt_client_t *client);

bool default_check_close_condition(pt_client_t *client, bool client_close)
{
    return client_close;
}

pt_client_t *pt_client_create(const char *socket_path,
                              const protocol_translator_callbacks_t *pt_cbs)
{
    tr_debug("pt_client_create - socket_path: %s", socket_path);
    if (!pt_cbs || check_protocol_translator_callbacks(pt_cbs)) {
        tr_err("Protocol translator callbacks not set.");
        return NULL;
    }

    if (NULL == socket_path) {
        tr_err("The protocol translator socket path cannot be NULL.");
        return NULL;
    }

    pt_client_t *client = calloc(1, sizeof(pt_client_t));
    client->json_flags = JSON_COMPACT;
    client->protocol_translator_callbacks = pt_cbs;
    client->socket_path = socket_path;
    client->close_condition_impl = default_check_close_condition;
    client->close_client = false;
    // Set the id to invalid
    client->id = -1;
    client->registered = false;
    client->method_table = pt_service_method_table;
    client->devices = pt_devices_create(client);
    return client;
}

pt_devices_t *pt_client_get_devices(pt_client_t *client)
{
    return client->devices;
}

connection_id_t pt_client_get_connection_id(pt_client_t *client)
{
    return client->connection_id;
}

void pt_client_free(pt_client_t *client)
{
    pt_devices_remove_and_free_all(client->devices);
    pt_devices_destroy(client->devices);
    free(client->name);
    free(client);
}

connection_t *connection_init(pt_client_t *client)
{
    connection_t *connection;
    connection = (connection_t*) calloc(1, sizeof(connection_t));
    if (!connection) {
        tr_err("Could not allocation internal connection structure.");
        return NULL;
    }

    connection->id = next_connection_id;
    connection->client = client;
    next_connection_id++;
    ns_list_add_to_end(&connection_list, connection);

    return connection;
}

struct event_base *connection_get_ev_base(connection_t *connection)
{
    return connection->client->ev_base;
}

void connection_destroy(connection_t *connection)
{
    ns_list_remove(&connection_list, connection);
    free(connection);
}

connection_t *find_connection(connection_id_t connection_id)
{
    connection_t *connection = NULL;
    ns_list_foreach_safe(connection_t, cur, &connection_list)
    {
        if (cur->id == connection_id) {
            connection = cur;
            break;
        }
    }
    return connection;
}

connection_id_t get_connection_id(connection_t *connection)
{
    return connection->id;
}

void pt_client_set_msg_id_generator(pt_client_t *client, generate_msg_id generate_msg_id)
{
    assert(client);
    if (generate_msg_id == NULL) {
        client->generate_msg_id = edge_default_generate_msg_id;
    } else {
        client->generate_msg_id = generate_msg_id;
    }
}

static void trigger_close_connection(connection_t *connection)
{
    connection->client->close_connection = true;
    if (connection->transport_connection) {
        websocket_connection_t *websocket_connection = (websocket_connection_t *)
                                                               connection->transport_connection->transport;
        if (websocket_connection && websocket_connection->wsi) {
            lws_callback_on_writable(websocket_connection->wsi);
            return;
        }
    }
    tr_err("trigger_close_connection: websocket connection is NULL");
}

static void trigger_close_client(pt_client_t *client)
{
    client->close_client = true;
    connection_t *connection = find_connection(client->connection_id);
    if (connection) {
        trigger_close_connection(connection);
    }
}

EDGE_LOCAL void pt_client_shutdown_cb(void *arg)
{
    //pt_api_lock_connection();
    tr_debug("pt_client_shutdown_cb");
    api_lock();
    pt_client_t *client = (pt_client_t *) arg;
    trigger_close_client(client);
    api_unlock();
}

pt_status_t pt_client_shutdown(pt_client_t *client)
{
    pt_status_t status = PT_STATUS_SUCCESS;
    tr_info("pt_client_shutdown client: %p", client);
    if (client) {
        if (!msg_api_send_message(client->ev_base, client, pt_client_shutdown_cb)) {
            tr_err("Cannot shutdown");
            status = PT_STATUS_ERROR;
        }
    } else {
        tr_err("Cannot shutdown, because client is NULL");
        status = PT_STATUS_ERROR;
    }
    return status;
}

static int check_protocol_translator_callbacks(const protocol_translator_callbacks_t *pt_cbs)
{
    if (pt_cbs->connection_ready_cb == NULL || pt_cbs->connection_shutdown_cb == NULL ||
        pt_cbs->certificate_renewal_notifier_cb == NULL || pt_cbs->disconnected_cb == NULL ||
        pt_cbs->device_certificate_renew_request_cb == NULL) {
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
                                (struct jsonrpc_method_entry_t *) connection->client->method_table,
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

EDGE_LOCAL void create_connection_cb(void *arg)
{
    pt_client_t *client = (pt_client_t *) arg;
    tr_debug("create_connection_cb");

    api_lock();
    client->reconnection_triggered = false;
    // Client close request could have come before this callback gets called.
    if (!client->close_client) {
        if (!create_client_connection(client)) {
            tr_err("Creating connection failed. Triggering reconnection.");
            trigger_reconnection_or_exit(client);
        }
    } else {
        tr_warn("create_connection_cb received when client close is already requested.");
    }

    api_unlock();
}

static void destroy_connection_and_structures(connection_t *connection)
{
    transport_connection_t *transport_connection = connection->transport_connection;
    websocket_connection_t *websocket_conn = (websocket_connection_t *) transport_connection->transport;

    websocket_connection_t_destroy(&websocket_conn);
    transport_connection_t_destroy(&transport_connection);
    connection->transport_connection = NULL;
    connection->client = NULL;
    connection_destroy(connection);
}

static void trigger_reconnection_or_exit(pt_client_t *client)
{
    if (!client->close_client) {
        if (!client->reconnection_triggered) {
            if (client->tries < 5) {
                client->tries++;
                client->backoff_time_in_sec = client->tries * 1;
            } else {
                client->backoff_time_in_sec = 5;
            }
            tr_info("Waiting a backoff time of %d", client->backoff_time_in_sec);
            client->reconnection_triggered = true;
            msg_api_send_message_after_timeout_in_ms(client->ev_base,
                                                     client,
                                                     create_connection_cb,
                                                     client->backoff_time_in_sec * 1000);
        }
    } else {
        tr_info("Close client requested. Exiting the event loop");
        event_base_loopexit(client->ev_base, NULL);
    }
}

void destroy_connection_and_restart_reconnection_timer(connection_t *connection)
{
    pt_client_t *client = connection->client;
    destroy_connection_and_structures(connection);
    trigger_reconnection_or_exit(client);
}

/**
 * \brief The connection went disconnected.
 */
EDGE_LOCAL void pt_client_disconnected_cb(void *arg)
{
    tr_debug("pt_client_disconnected_cb");
    pt_client_t *client = (pt_client_t *) arg;
    connection_id_t connection_id = client->connection_id;

    api_lock();
    connection_t *connection = find_connection(connection_id);

    if (!client->close_condition_impl(client, client->close_client)) {
        if (connection) {
            destroy_connection_and_restart_reconnection_timer(connection);
        } else {
            trigger_reconnection_or_exit(client);
        }
    } else {
        tr_err("Client close requested - exiting loop in pt_client_disconnected_cb.");
        if (connection) {
            destroy_connection_and_structures(connection);
        }
        event_base_loopexit(client->ev_base, NULL);
    }

    api_unlock();
}

EDGE_LOCAL void websocket_disconnected(websocket_connection_t *websock_conn)
{
    connection_t *connection;
    connection = websock_conn->conn;
    tr_debug("> websocket_disconnected");
    if (connection) {
        tr_debug("websocket_disconnected: connection %p", connection);
        connection->connected = false;
        rpc_remote_disconnected(connection);
        connection->client->protocol_translator_callbacks->disconnected_cb(get_connection_id(connection),
                                                                           connection->client->userdata);

        tr_debug("Sending pt_client_disconnected_cb message.");
        if (!msg_api_send_message(connection->client->ev_base, connection->client, pt_client_disconnected_cb)) {
            tr_err("Unabled to send pt_client_disconnected_cb message");
        }
    } else {
        tr_err("Websocket_disconnect called when connection is NULL");
    }
    tr_debug("< websocket_disconnected");
}

int callback_edge_client_protocol_translator(struct lws *wsi,
                                             enum lws_callback_reasons reason,
                                             void *user,
                                             void *in,
                                             size_t len)
{

    websocket_connection_t *websock_conn = (websocket_connection_t*) user;
    struct connection *conn = NULL;

    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED: {
            tr_debug("lws_callback_client_established");
            pt_client_t *client;
            conn = websock_conn->conn;
            conn->connected = true;
            if (conn->client->generate_msg_id == NULL) {
                pt_client_set_msg_id_generator(conn->client, NULL);
            }
            // FIXME: does RPC prevent using multiple client threads?
            rpc_set_generate_msg_id(conn->client->generate_msg_id);
            client = conn->client;

            conn->client->protocol_translator_callbacks->connection_ready_cb(get_connection_id(conn),
                                                                             conn->client->name,
                                                                             conn->client->userdata);
            // This allows to update all device registration status and resource data.
            api_lock();
            pt_devices_set_all_to_unregistered_state(conn->client->devices);
            api_unlock();

            pt_status_t status = pt_register_protocol_translator(conn->id,
                                                                 client->success_handler,
                                                                 client->failure_handler,
                                                                 client->name,
                                                                 client->userdata);
            if (status != PT_STATUS_SUCCESS) {
                client->failure_handler(client->userdata);
            }

            break;
        }
        case LWS_CALLBACK_CLOSED: {
            tr_debug("lws_callback_closed");
            //api_lock();
            websocket_disconnected(websock_conn);
            //api_unlock();
            break;
        }

        case LWS_CALLBACK_CLIENT_RECEIVE: {
            tr_debug("lws_callback_client_receive: len(%zu), msg(%.*s)", len, (int) len, (char *) in);
            if (websocket_add_msg_fragment(websock_conn, in, len) != 0) {
                tr_err("lws_callback_client_receive: Message payload fragment concatenation failed. Closing connection.");
                trigger_close_connection(websock_conn->conn);
                break;
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
                    trigger_close_connection(websock_conn->conn);
                }
            }
            break;
        }

        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR: {
            // Cannot lock connection here, because this is called in creating the connection.
            const char *which = "http";
            websock_conn->conn->connected = false;
            websock_conn->conn->client->registered = false;
            tr_err("lws_callback_client_connection_error");
            tr_err("client_connection_error: %s: %s", which, in ? (char *) in : "(null)");
            websocket_disconnected(websock_conn);
            break;
        }

        case LWS_CALLBACK_CLIENT_WRITEABLE: {
            tr_debug("lsw_callback_client_writeable: wsi %p writeable", wsi);
            if (websock_conn->conn->client->close_connection) {
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

EDGE_LOCAL void websocket_connection_t_destroy(websocket_connection_t **wct)
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

static websocket_connection_t *initialize_websocket_connection()
{

    // Initialize web connection structure for this client
    websocket_connection_t *websocket_conn = (websocket_connection_t *) calloc(1, sizeof(websocket_connection_t));

    if (!websocket_conn) {
        tr_err("Could not allocate websocket connection structure.");
        return NULL;
    }

    websocket_conn->sent = (websocket_message_list_t*) calloc(1, sizeof(websocket_message_list_t));

    if (!websocket_conn->sent) {
        tr_err("Could not allocate websockt connection `sent` list");
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

EDGE_LOCAL void transport_connection_t_destroy(transport_connection_t **transport_connection)
{
    if (transport_connection && *transport_connection) {
        free(*transport_connection);
        *transport_connection = NULL;
    }
}

#ifdef BUILD_TYPE_TEST
void pt_init_check_close_condition_function(pt_client_t *client, pt_f_close_condition func)
{
    client->close_condition_impl = func;
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

int pt_api_init()
{
    int rc = 0;
    /* Configure libevent */
    if (configure_libevent() != 0) {
        tr_err("Libevent configuring failed!");
        rc = 1;
    }

    ns_list_init(&connection_list);
    return rc;
}

EDGE_LOCAL bool create_client_connection(pt_client_t *client)
{
    websocket_connection_t *websocket_conn;
    struct event_base *ev_base = client->ev_base;
    bool ret_val = true;
    connection_t *connection;
    client->close_connection = false;

    connection = connection_init(client);
    if (!connection) {
        tr_err("Cannot create connection");
        ret_val = false;
        goto error_exit;
    }
    client->connection_id = get_connection_id(connection);
    websocket_conn = initialize_websocket_connection();
    if (!websocket_conn) {
        tr_err("Websocket initialization connection failed");
        ret_val = false;
        goto error_exit;
    }
    transport_connection_t *transport_connection = initialize_transport_connection(websocket_conn);

    /* Wire the connection and websocket connection together */
    websocket_conn->conn = connection;
    connection->transport_connection = transport_connection;
    struct lws_context *context = libwebsocket_create_context(ev_base, client->socket_path);
    if (!context) {
        tr_err("Cannot create libwebsocket context!");
        ret_val = false;
        goto error_exit;
    }
    websocket_conn->lws_context = context;
    struct lws *wsi = initialize_libwebsocket_connection_info(ev_base, websocket_conn, context);
    if (wsi) {
        websocket_conn->wsi = wsi;
    } else {
        tr_err("Cannot initialize websocket connection info");
        ret_val = false;
        goto error_exit;
    }

    goto exit_label;
error_exit:
    websocket_connection_t_destroy(&websocket_conn);
    transport_connection_t_destroy(&transport_connection);
    if (connection) {
        connection_destroy(connection);
    }
exit_label:
    return ret_val;
}

int pt_client_start(pt_client_t *client,
                    pt_response_handler success_handler,
                    pt_response_handler failure_handler,
                    const char *name,
                    void *userdata)
{
    rpc_request_timeout_hander_t *timeout_handler = NULL;
    if (NULL == client) {
        tr_err("Protocol translator client cannot be NULL.");
        return 1;
    }

    int rc = 1;

    if (!name) {
        tr_err("Protocol translator name cannot be NULL.");
        return rc;
    }

    client->json_flags = JSON_COMPACT;

    if (!success_handler || !failure_handler) {
        tr_err("success_handler and failure_handler need to valid response handlers.");
        return rc;
    }
    client->success_handler = success_handler;
    client->failure_handler = failure_handler;
    client->userdata = userdata;
    if (client->name) {
        free(client->name);
    }
    client->name = strdup(name);

    struct event_base *ev_base = event_base_new();
    if (!ev_base) {
        tr_err("Couldn't create client event base instance.");
        goto cleanup;
    }
    client->ev_base = ev_base;

    websocket_set_log_level_and_emit_function();
    timeout_handler = rpc_request_timeout_api_start(ev_base,
                                                    CLIENT_TIMEOUT_CHECK_INTERVAL_MS,
                                                    CLIENT_REQUEST_TIMEOUT_THRESHOLD_MS);

    if (!timeout_handler) {
        // error message already printed.
        goto cleanup;
    }
    tr_debug("Connecting to Edge Core.");
    if (!msg_api_send_message(ev_base, client, create_connection_cb)) {
        tr_err("Cannot send the initial connection message");
        goto cleanup;
    }

    int ret = event_base_dispatch(ev_base);
    if (ret != 0) {
        tr_err("event_base_dispatch failed: %d", ret);
    } else {
        // Successful exit of the event loop
        rc = 0;
    }

    tr_info("Protocol translator api eventloop closed.");
cleanup:
    rpc_request_timeout_api_stop(timeout_handler);
    client->protocol_translator_callbacks->connection_shutdown_cb(client->connection_id, client->userdata);
    event_base_free(ev_base);
    libevent_global_shutdown();
    rpc_destroy_messages();
    return rc;
}

