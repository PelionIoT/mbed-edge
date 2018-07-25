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

#include <signal.h>
#include <unistd.h>
#include <assert.h>
#include "libwebsockets.h"

#include "edge-client/edge_client.h"
#include "edge-client/edge_client_byoc.h"
#include "edge-core/protocol_api.h"
#include "edge-core/server.h"
#include "edge-core/srv_comm.h"
#include "edge-core/edge_server.h"
#include "edge-core/http_server.h"
#include "common/websocket_comm.h"
#include "common/edge_mutex.h"
#include "common/edge_trace.h"
#include "edge-core/websocket_serv.h"

// Cloud client
#include "ns_list.h"
#include "mbed-trace/mbed_trace.h"
#include "common/test_support.h"
#include "edge_core_clip.h"
#include "edge-client/reset_factory_settings.h"
#include "edge_version_info.h"
#define TRACE_GROUP "serv"

// current protocol API version
#define SERVER_JSONRPC_WEBSOCKET_VERSION_PATH "/1/pt"

EDGE_LOCAL struct context *g_program_context = NULL;
EDGE_LOCAL void free_old_cloud_error(struct ctx_data *ctx_data);
EDGE_LOCAL edgeclient_create_parameters_t edgeclient_create_params = {0};

EDGE_LOCAL const char *cloud_connection_status_in_string(struct context *ctx)
{
    const char *ret;

    switch ((ctx->ctx_data)->cloud_connection_status) {
        case EDGE_STATE_CONNECTING:
            ret = "connecting";
            break;
        case EDGE_STATE_CONNECTED:
            ret = "connected";
            break;
        case EDGE_STATE_ERROR:
            ret = "error";
            break;
        default:
            ret = "undefined";
            break;
    }
    return ret;
}

static struct connection *initialize_client_connection(protocol_translator_t *pt)
{
    struct connection *connection = (struct connection *)calloc(1, sizeof(struct connection));
    if (!connection) {
        tr_err("Could not allocate connection structure.");
    }
    connection->protocol_translator = pt;
    connection->ctx = g_program_context;
    return connection;
}

transport_connection_t *initialize_transport_connection(websocket_connection_t *websocket_connection)
{
    if (!websocket_connection) {
        tr_err("Could not initialize transport connection, websocket connection is NULL.");
        return NULL;
    }

    transport_connection_t *transport_connection = (transport_connection_t*) malloc(sizeof(transport_connection_t));
    if (!transport_connection) {
        tr_err("Could not allocate transport connection structure.");
        return NULL;
    }
    transport_connection->write_function = edge_core_write_data_frame_websocket;
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

int callback_edge_core_protocol_translator(struct lws *wsi,
                                           enum lws_callback_reasons reason,
                                           void *user,
                                           void *in,
                                           size_t len)
{
    websocket_connection_t *websocket_connection = (websocket_connection_t *) user;
    struct connection *connection = NULL;

    switch (reason) {
        case LWS_CALLBACK_ESTABLISHED: {
            tr_info("lws_callback_established: initializing protocol translator connection: server wsi %p", wsi);
            protocol_translator_t *pt = edge_core_create_protocol_translator();
            websocket_connection = websocket_server_connection_initialize(websocket_connection);
            connection = initialize_client_connection(pt);
            transport_connection_t *transport_connection = initialize_transport_connection(websocket_connection);

            if (!pt || !websocket_connection || !connection || !transport_connection) {
                tr_err("lws_callback_established: could not allocate memory for protocol translator connection");
                edge_core_protocol_translator_destroy(&pt);
                websocket_server_connection_destroy(websocket_connection);
                transport_connection_t_destroy(&transport_connection);
                connection_destroy(&connection);
                return 1;
            }

            /* Wire websocket connection and connection together */
            websocket_connection->conn = connection;
            websocket_connection->wsi = wsi;
            connection->connected = true;

            transport_connection->transport = websocket_connection;
            connection->transport_connection = transport_connection;

            tr_info("lws_callback_established: connection initialized for protocol translator");
            break;
        }

        case LWS_CALLBACK_SERVER_WRITEABLE: {
            connection = websocket_connection->conn;
            if(websocket_connection->to_close && ns_list_count(websocket_connection->sent) == 0){
                return -1;
            }
            websocket_message_t *message = ns_list_get_first(websocket_connection->sent);
            if(!message) {
                tr_err("LWS_CALLBACK_SERVER_WRITEABLE but no message to send");
                break;
            }

            tr_info("lws_callback_server_send: wsi %p %zu bytes '%.*s'",
                    wsi,
                    message->len,
                    (int) message->len,
                    message->bytes);
            unsigned char *buf = calloc(1, LWS_SEND_BUFFER_PRE_PADDING + message->len + 1);

            memcpy(buf+LWS_SEND_BUFFER_PRE_PADDING, message->bytes, message->len);
            lws_write( wsi, buf+LWS_SEND_BUFFER_PRE_PADDING, message->len, LWS_WRITE_TEXT );
            ns_list_remove(websocket_connection->sent, message);
            free(message->bytes);
            free(message);
            free(buf);

            if (ns_list_count(websocket_connection->sent) > 0 || websocket_connection->to_close) {
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

        case LWS_CALLBACK_CLOSED: {
            tr_warn("lws_callback_closed: client went away: server wsi %p", wsi);
            if (websocket_connection) {
                struct connection *connection = (struct connection*) websocket_connection->conn;
                close_connection(connection);
            }
            break;
        }

        case LWS_CALLBACK_RECEIVE: {
            tr_info("lws_callback_server_receive: wsi %p len(%zu), msg(%.*s)", wsi, len, (int) len, (char *) in);
            bool protocol_error;
            if (websocket_connection) {
                connection = (struct connection*) websocket_connection->conn;
            }

            if (connection) {
                edge_core_process_data_frame_websocket(connection, &protocol_error, len, (const char*) in);
                if (protocol_error || !connection->connected) {
                    tr_err("Protocol error happened when receiving data from client!");
                    websocket_connection->to_close = true;
                    lws_callback_on_writable(wsi);
                }
            } else {
                tr_err("lws_callback_receive: error");
            }

            break;
        }
        case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION: {
            tr_info("lws_callback_filter_protocol_connection: wsi %p", wsi);
            bool reject_connection = false;
            int uri_length = lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI);
            char *get_uri = calloc(1, uri_length + 1);

            int header_ok = lws_hdr_copy(wsi, get_uri, uri_length + 1, WSI_TOKEN_GET_URI);
            tr_debug("URI in header: \"%s\" (len: %d)", get_uri, strlen(get_uri));
            if (header_ok <= 0 && strcmp(get_uri, SERVER_JSONRPC_WEBSOCKET_VERSION_PATH)) {
                tr_err("No matching uri is found for '%s'. Reject connection!", get_uri);
                reject_connection = true;
            }
            free(get_uri);
            if (reject_connection) {
                return -1;
            }
            break;
        }

        default: {
            tr_debug("lws callback: %s: server wsi %p", websocket_lws_callback_reason(reason), wsi);
            break;
        }
    }

    return 0;
}

EDGE_LOCAL struct lws_protocols edge_server_protocols[] = { { "edge_protocol_translator",
                                                              callback_edge_core_protocol_translator,
                                                              sizeof(struct websocket_connection),
                                                              2048,
                                                              1,
                                                              NULL,
                                                              2048 },
                                                            { NULL, NULL, 0, 0, 0, NULL, 0 } };

json_t *http_state_in_json(struct context *ctx)
{
    json_t *res = json_object();
    json_object_set_new(res, "status", json_string(cloud_connection_status_in_string(ctx)));
    json_object_set_new(res, "internal-id", json_string(edgeclient_get_internal_id()));
    json_object_set_new(res, "endpoint-name", json_string(edgeclient_get_endpoint_name()));
    json_object_set_new(res, "edge-version", json_string(VERSION_STRING));

    if (ctx->ctx_data->cloud_connection_status  == EDGE_STATE_ERROR) {
        json_object_set_new(res, "error_code", json_integer(ctx->ctx_data->cloud_error->error_code));
        json_object_set_new(res, "error_description", json_string(ctx->ctx_data->cloud_error->error_description));
    }
    return res;
}

EDGE_LOCAL void shutdown_handler(int signum)
{
    tr_info("shutdown_handler signal: %d", signum);
    tr_info("edgeclient status when shutting down: %s", cloud_connection_status_in_string(g_program_context));
    edgeclient_stop();
}

void edgeserver_exit_event_loop()
{
    tr_debug("edgeserver_exit_event_loop");
    event_base_loopexit(g_program_context->ev_base, NULL);
}

bool edgeserver_remove_protocol_translator_nodes()
{
    struct ctx_data *ctx_data = g_program_context->ctx_data;
    bool connections_removed = false;
    tr_info("edgeserver_remove_protocol_translator_nodes");

    ns_list_foreach_safe(struct connection_list_elem, cur, &ctx_data->registered_translators) {
        struct connection *connection = cur->conn;
        edge_core_protocol_translator_destroy(&connection->protocol_translator);
        connections_removed = true;
    }
    return connections_removed;
}

void *edgeserver_graceful_shutdown()
{
    struct ctx_data *ctx_data = g_program_context->ctx_data;
    tr_info("edgeserver_graceful_shutdown");
    ctx_data->exiting = true;
    bool stop_frame_sent = false;

    ns_list_foreach_safe(struct connection_list_elem, cur, &ctx_data->registered_translators) {
        struct connection *connection = cur->conn;
        close_connection_trigger(connection);
        stop_frame_sent = true;
    }
    if(!stop_frame_sent) {
        // If there is no client connected, we can start exiting immediately.
        edgeserver_exit_event_loop();
    }
    return NULL;
}

#ifndef BUILD_TYPE_TEST
EDGE_LOCAL bool setup_signals(void)
{
    struct sigaction sa = { .sa_handler = shutdown_handler, };
    struct sigaction sa_pipe = { .sa_handler = SIG_IGN, };
    int ret_val;

    if (sigemptyset(&sa.sa_mask) != 0) {
        return false;
    }
    if (sigaction(SIGTERM, &sa, NULL) != 0) {
        return false;
    }
    if (sigaction(SIGINT, &sa, NULL) != 0) {
        return false;
    }
    ret_val = sigaction(SIGPIPE, &sa_pipe, NULL);
    if (ret_val != 0) {
        tr_warn("setup_signals: sigaction with SIGPIPE returned error=(%d) errno=(%d) strerror=(%s)",
                ret_val,
                errno,
                strerror(errno));
    }
#ifdef DEBUG
    tr_info("Setting support for SIGUSR2");
    if (sigaction(SIGUSR2, &sa, NULL) != 0) {
        return false;
    }
#endif
    return true;
}
#endif

EDGE_LOCAL void clean(struct context *ctx)
{
    if (ctx->ev_sighup != NULL) {
        event_free(ctx->ev_sighup);
    }
    http_server_clean(&((ctx->ctx_data)->http_server));
    if (ctx->ev_base != NULL) {
        event_base_free(ctx->ev_base);
    }
    free_old_cloud_error(ctx->ctx_data);
    edgeclient_destroy();
    if (g_program_context->ctx_data->rfs_customer_code_succeeded) {
        rfs_finalize_reset_factory_settings();
    }
}

void register_cb(void)
{
    (g_program_context->ctx_data)->cloud_connection_status = EDGE_STATE_CONNECTED;
}

void unregister_cb(void)
{
    (g_program_context->ctx_data)->cloud_connection_status = EDGE_STATE_CONNECTING;
}

EDGE_LOCAL void free_old_cloud_error(struct ctx_data *ctx_data)
{
    if (ctx_data->cloud_error) {
        free(ctx_data->cloud_error->error_description);
        free(ctx_data->cloud_error);
        ctx_data->cloud_error = NULL;
    }
}

void error_cb(int error_code, const char *error_description)
{
    struct cloud_error *ce = (struct cloud_error *) calloc(1, sizeof(struct cloud_error));
    struct ctx_data *ctx_data = g_program_context->ctx_data;
    ce->error_code = error_code;
    ce->error_description = strdup(error_description);
    free_old_cloud_error(ctx_data);
    ctx_data->cloud_error = ce;
    ctx_data->cloud_connection_status = EDGE_STATE_ERROR;
}

int32_t edgeserver_get_number_registered_endpoints_count()
{
    return g_program_context->ctx_data->registered_endpoint_count;
}

int32_t edgeserver_get_number_registered_endpoints_limit()
{
    return g_program_context->ctx_data->registered_endpoint_limit;
}

void edgeserver_change_number_registered_endpoints_by_delta(int32_t delta)
{
    (g_program_context->ctx_data->registered_endpoint_count) += delta;
    tr_debug("current endpoints count = %d (delta=%d)", edgeserver_get_number_registered_endpoints_count(), delta);
}

#ifdef BUILD_TYPE_TEST
EDGE_LOCAL void edgeserver_set_number_registered_endpoints_limit(int32_t limit)
{
    g_program_context->ctx_data->registered_endpoint_limit = limit;
}
#endif

EDGE_LOCAL void create_program_context_and_data()
{
    g_program_context = calloc(1, sizeof(struct context));
    g_program_context->ctx_data = calloc(1, sizeof(struct ctx_data));
    g_program_context->ctx_data->registered_endpoint_limit = EDGE_REGISTERED_ENDPOINT_LIMIT;
    g_program_context->json_flags = JSON_COMPACT | JSON_SORT_KEYS;
}

EDGE_LOCAL void free_program_context_and_data()
{
    free(g_program_context->ctx_data);
    free(g_program_context);
}

struct event_base *edge_server_get_base()
{
    return g_program_context->ev_base;
}

void edgeserver_rfs_customer_code_succeeded()
{
    g_program_context->ctx_data->rfs_customer_code_succeeded = true;
}

EDGE_LOCAL struct lws_context *initialize_libwebsocket_context(struct event_base *ev_base,
                                                               const char *edge_pt_socket,
                                                               struct lws_protocols protocols[])
{
    void *foreign_loops[1];

    struct lws_context *lwsc = NULL;
    struct lws_context_creation_info info;
    memset(&info, 0, sizeof (struct lws_context_creation_info));
    int opts = 0;
    info.port = 7681;
    info.iface = edge_pt_socket;
    info.protocols = protocols;
    info.extensions = NULL;
    info.ssl_cert_filepath = NULL;
    info.ssl_private_key_filepath = NULL;
    info.gid = -1;
    info.uid = -1;
    info.max_http_header_pool = 1;
    info.options = opts | LWS_SERVER_OPTION_LIBEVENT | LWS_SERVER_OPTION_UNIX_SOCK;
    foreign_loops[0] = ev_base;
    info.foreign_loops = foreign_loops;

    lwsc = lws_create_context(&info);
    if (lwsc == NULL) {
        tr_err("Could not create libwebsocket context.");
        return NULL;
    }

    return lwsc;
}

EDGE_LOCAL void clean_resources(struct lws_context *lwsc, const char *edge_pt_socket)
{
    tr_info("Edge server cleaning resources");
    if (lwsc) {
        lws_context_destroy(lwsc);
    }
    unlink(edge_pt_socket);
    clean(g_program_context);
    free_program_context_and_data();
}

#ifndef BUILD_TYPE_TEST
int main(int argc, char **argv)
#else
int testable_main(int argc, char **argv)
#endif
{
    int rc = 0;
    int counter;
    struct lws_context *lwsc = NULL;
    memset(&edgeclient_create_params, 0, sizeof(edgeclient_create_parameters_t));
    DocoptArgs args = docopt(argc, argv, /* help */ 1, /* version */ VERSION_STRING);

    if (args.reset_storage) {
        edgeclient_create_params.reset_storage = true;
    }

    char* edge_pt_socket = args.edge_pt_domain_socket;
    int http_port = atoi(args.http_port);

    for (counter = 0; counter < 1; counter ++) {
        // Initialize trace and trace mutex
        edge_trace_init();
        create_program_context_and_data();
        struct ctx_data *ctx_data = g_program_context->ctx_data;
        ns_list_init(&ctx_data->registered_translators);
        ns_list_init(&ctx_data->not_accepted_translators);

        if (!create_server_event_loop(g_program_context, http_port)) {
            tr_err("Could not create http server.");
            rc = 1;
            break;
        }

        // Create client
        tr_info("Starting mbed Edge Core cloud client");
        edgeclient_create_params.handle_write_to_pt_cb = write_to_pt;
        edgeclient_create_params.handle_register_cb = register_cb;
        edgeclient_create_params.handle_unregister_cb = unregister_cb;
        edgeclient_create_params.handle_error_cb = error_cb;

        byoc_data_t *byoc_data = edgeclient_create_byoc_data(args.cbor_conf);

        edgeclient_create(&edgeclient_create_params, byoc_data);
        rfs_add_factory_reset_resource();

        // Connect client
        edgeclient_connect();

#ifndef BUILD_TYPE_TEST
        if (!setup_signals()) {
            tr_err("Failed to setup signals.");
            rc = 1;
            break;
        }
#endif
        lws_set_log_level(LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_INFO | LLL_DEBUG, websocket_set_log_emit_function);

        lwsc = initialize_libwebsocket_context(g_program_context->ev_base, edge_pt_socket, edge_server_protocols);
        if (event_base_dispatch(g_program_context->ev_base) != 0) {
            tr_err("Failed to start event loop.");
            rc = 1;
            break;
        }
    }
    clean_resources(lwsc, edge_pt_socket);
    edge_trace_destroy();
    return rc;
}

