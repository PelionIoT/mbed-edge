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
#include <errno.h>
#include <assert.h>
#include "libwebsockets.h"
#include <event2/event_struct.h>
#include <event2/event.h>

#include "edge-client/edge_client.h"
#include "edge-client/edge_client_byoc.h"
#include "edge-core/client_type.h"
#include "edge-core/protocol_api.h"
#include "edge-core/protocol_crypto_api.h"
#include "edge-core/server.h"
#include "edge-core/protocol_api.h"
#include "edge-core/srv_comm.h"
#include "edge-core/edge_server.h"
#include "edge-core/http_server.h"
#include "edge-rpc/rpc.h"
#include "common/websocket_comm.h"
#include "common/edge_mutex.h"
#include "common/edge_trace.h"
#include "edge-core/websocket_serv.h"
#include "common/edge_io_lib.h"

// Cloud client
#include "ns_list.h"
#include "mbed-trace/mbed_trace.h"
#include "common/test_support.h"
#include "edge_core_clip.h"
#include "edge-client/reset_factory_settings.h"
#include "edge_version_info.h"
#include "edge-rpc/rpc_timeout_api.h"
#include "common/msg_api.h"

#define TRACE_GROUP "serv"

// current protocol API version
#define SERVER_PT_WEBSOCKET_VERSION_PATH "/1/pt"
#define SERVER_MGMT_WEBSOCKET_VERSION_PATH "/1/mgmt"

EDGE_LOCAL connection_id_t g_connection_id_counter = 1;
EDGE_LOCAL struct context *g_program_context = NULL;
EDGE_LOCAL struct event ev_sigint = {0};
EDGE_LOCAL struct event ev_sigterm = {0};
EDGE_LOCAL struct event ev_sigusr2 = {0};
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

static struct connection *initialize_client_connection(client_data_t *client_data)
{
    struct connection *connection = (struct connection *) calloc(1, sizeof(struct connection));
    if (!connection) {
        tr_err("Could not allocate connection structure.");
    }
    connection->client_data = client_data;
    connection->id = g_connection_id_counter;
    g_connection_id_counter++;
    connection->ctx = g_program_context;
    return connection;
}

typedef struct {
    connection_id_t connection_id;
    json_t *response;
    rpc_free_func free_func;
    rpc_request_context_t *customer_callback_ctx;
} safe_response_params_t;

EDGE_LOCAL void safe_response_callback(void *data)
{
    safe_response_params_t *params = (safe_response_params_t *) data;
    connection_t *connection = srv_comm_find_connection(params->connection_id);
    if (connection) {
        (void) rpc_construct_and_send_response(connection,
                                               params->response,
                                               params->free_func,
                                               params->customer_callback_ctx,
                                               connection->transport_connection->write_function);
    } else {
        tr_warn("safe_response_callback: response not send because connection id %d no longer exists",
                params->connection_id);
        json_decref(params->response);
        params->free_func(params->customer_callback_ctx);
    }
    free(params);
}

void edge_server_construct_and_send_response_safe(connection_id_t connection_id,
                                                  json_t *response,
                                                  rpc_free_func free_func,
                                                  rpc_request_context_t *customer_callback_ctx)
{
    safe_response_params_t *params = calloc(1, sizeof(safe_response_params_t));
    if (params) {
        params->connection_id = connection_id;
        params->response = response;
        params->free_func = free_func;
        params->customer_callback_ctx = customer_callback_ctx;
        if (!msg_api_send_message(g_program_context->ev_base, params, safe_response_callback)) {
            tr_err("edge_server_construct_and_send_response_safe: couldn't send response back to client");
            json_decref(response);
            free(params);
            free_func(customer_callback_ctx);
        }
    }
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

            int uri_length = lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI);
            char *get_uri = calloc(1, uri_length + 1);
            int header_ok = lws_hdr_copy(wsi, get_uri, uri_length + 1, WSI_TOKEN_GET_URI);

            client_data_t *client_data;
            if (header_ok && strcmp(get_uri, SERVER_PT_WEBSOCKET_VERSION_PATH) == 0) {
                client_data = edge_core_create_client(PT);
            } else if (header_ok && strcmp(get_uri, SERVER_MGMT_WEBSOCKET_VERSION_PATH) == 0) {
                client_data = edge_core_create_client(MGMT);
            } else {
                tr_err("Could not select client type from \"%s\".", get_uri);
                free(get_uri);
                return 1;
            }
            free(get_uri);

            tr_info("lws_callback_established: initializing client connection: server wsi %p.", wsi);

            websocket_connection = websocket_server_connection_initialize(websocket_connection);
            connection = initialize_client_connection(client_data);
            transport_connection_t *transport_connection = initialize_transport_connection(websocket_connection);

            if (!client_data || !websocket_connection || !connection || !transport_connection) {
                tr_err("lws_callback_established: could not allocate memory for client connection.");
                edge_core_client_data_destroy(&client_data);
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

            tr_info("lws_callback_established: connection initialized for client.");
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
                rpc_remote_disconnected(connection);
                close_connection(connection);
            }
            break;
        }

        case LWS_CALLBACK_RECEIVE: {
            tr_debug("lws_callback_server_receive: wsi %p len(%zu), msg(%.*s)", wsi, len, (int) len, (char *) in);

            if (websocket_add_msg_fragment(websocket_connection, in, len) != 0) {
                tr_err("lws_callback_server_receive: wsi %p. Message payload fragment concatenation failed. Closing connection.", wsi);
                return 1;
            }

            const size_t remaining_bytes = lws_remaining_packet_payload(wsi);
            if (remaining_bytes && !lws_is_final_fragment(wsi)) {
                tr_debug("lws_callback_server_receive: wsi %p. Message fragmented, wait for more content.", wsi);
                // Return control and wait for more bytes to arrive.
                break;
            } else {
                if (websocket_connection && websocket_connection->conn) {
                    tr_debug("lws_callback_server_receive: wsi %p. Final fragment and no remaining bytes. Message: (%.*s)",
                             wsi,
                             (int32_t) websocket_connection->msg_len,
                             websocket_connection->msg);
                    bool protocol_error;
                    connection = (struct connection*) websocket_connection->conn;
                    edge_core_process_data_frame_websocket(connection, &protocol_error,
                                                           websocket_connection->msg_len,
                                                           (const char*) websocket_connection->msg);
                    websocket_reset_message(websocket_connection);
                    if (protocol_error || !connection->connected) {
                        tr_err("Protocol error happened when receiving data from client! wsi %p", wsi);
                        websocket_connection->to_close = true;
                        lws_callback_on_writable(wsi);
                    }
                } else {
                    tr_err("lws_callback_server_receive: error. wsi: %p", wsi);
                }
            }
            break;
        }
        case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION: {
            tr_info("lws_callback_filter_protocol_connection: wsi %p", wsi);
            bool reject_connection = false;
            int uri_length = lws_hdr_total_length(wsi, WSI_TOKEN_GET_URI);
            char *get_uri = calloc(1, uri_length + 1);

            int header_ok = lws_hdr_copy(wsi, get_uri, uri_length + 1, WSI_TOKEN_GET_URI);
            tr_debug("URI in header: \"%s\" (len: %d)", get_uri, (int32_t) strlen(get_uri));

            if (header_ok <= 0 &&
                strcmp(get_uri, SERVER_PT_WEBSOCKET_VERSION_PATH) &&
                strcmp(get_uri, SERVER_MGMT_WEBSOCKET_VERSION_PATH)) {
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
    json_object_set_new(res, "account-id", json_string(edgeclient_get_account_id()));
    json_object_set_new(res, "lwm2m-server-uri", json_string(edgeclient_get_lwm2m_server_uri()));

    if (ctx->ctx_data->cloud_connection_status  == EDGE_STATE_ERROR) {
        json_object_set_new(res, "error_code", json_integer(ctx->ctx_data->cloud_error->error_code));
        json_object_set_new(res, "error_description", json_string(ctx->ctx_data->cloud_error->error_description));
    }
    return res;
}

EDGE_LOCAL void shutdown_handler(evutil_socket_t s, short x, void * args)
{
    tr_info("shutdown_handler signal: %d", x);
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
        edge_core_client_data_destroy(&connection->client_data);
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

EDGE_LOCAL bool setup_signal_handler(struct event *event,
                                     struct event_base *ev_base,
                                     evutil_socket_t fd,
                                     const char *desc)
{
    int ret_val = event_assign(event, ev_base, fd, EV_SIGNAL | EV_PERSIST, shutdown_handler, NULL);
    if (ret_val != 0) {
        tr_err("setup_signal_handler: event_assign returned %d for fd: %d '%s'", ret_val, fd, desc);
        return false;
    }

    ret_val = event_add(event, NULL);
    if (ret_val != 0) {
        tr_err("setup_signal_handler: event_add returned %d for fd: %d '%s'", ret_val, fd, desc);
        return false;
    }
    return true;
}

#ifndef BUILD_TYPE_TEST
EDGE_LOCAL bool setup_signals(struct event_base *ev_base)
{
    struct sigaction sa_pipe = { .sa_handler = SIG_IGN, };
    int ret_val;

    ret_val = sigaction(SIGPIPE, &sa_pipe, NULL);
    if (ret_val != 0) {
        tr_warn("setup_signals: sigaction with SIGPIPE returned error=(%d) errno=(%d) strerror=(%s)",
                ret_val,
                errno,
                strerror(errno));
        return false;
    }

    // use libevent signal handler for shut down
    if (!setup_signal_handler(&ev_sigint, ev_base, SIGINT, "SIGINT")) {
        return false;
    }

    if (!setup_signal_handler(&ev_sigterm, ev_base, SIGTERM, "SIGTERM")) {
        return false;
    }

    if (!setup_signal_handler(&ev_sigusr2, ev_base, SIGUSR2, "SIGUSR2")) {
        return false;
    }

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

connection_elem_list *edge_server_get_registered_translators()
{
    return &(g_program_context->ctx_data->registered_translators);
}

void edgeserver_rfs_customer_code_succeeded()
{
    g_program_context->ctx_data->rfs_customer_code_succeeded = true;
}

EDGE_LOCAL struct lws_context *initialize_libwebsocket_context(struct event_base *ev_base,
                                                               const char *edge_pt_socket,
                                                               struct lws_protocols protocols[],
                                                               int *lock_fd)
{
    void *foreign_loops[1];

    struct lws_context *lwsc = NULL;
    struct lws_context_creation_info info;

    // If the Protocol Translator socket lock file already exists, Edge Core should not start,
    // because there's probably another Edge Core already running.
    if (!edge_io_acquire_lock_for_socket(edge_pt_socket, lock_fd)) {
        return NULL;
    }

    // Remove the old Unix domain socket file if it exists.
    if (edge_io_file_exists(edge_pt_socket)) {
        int ret = edge_io_unlink(edge_pt_socket);
        if (ret != 0) {
            tr_err("Unable to remove the dangling %s file. Error code: %d (%s)",
                   edge_pt_socket,
                   errno,
                   strerror(errno));
            return NULL;
        }
    }
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

EDGE_LOCAL void clean_resources(struct lws_context *lwsc, const char *edge_pt_socket, int lock_fd)
{
    tr_info("Edge server cleaning resources");
    if (lwsc) {
        lws_context_destroy(lwsc);
    }
    // Only remove the socket and locks if we were able acquire the socket lock.
    if (lock_fd != -1) {
        edge_io_release_lock_for_socket(edge_pt_socket, lock_fd);
        edge_io_unlink(edge_pt_socket);
    }
    clean(g_program_context);
    free_program_context_and_data();
    rpc_destroy_messages();
    rpc_deinit();
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
    int lock_fd = -1;
    rpc_request_timeout_hander_t *timeout_handler = NULL;

    for (counter = 0; counter < 1; counter ++) {
        // Initialize trace and trace mutex
        edge_trace_init(args.color_log);
        tr_info("Edge Core starting... pid: %d", getpid());
        create_program_context_and_data();
        struct ctx_data *ctx_data = g_program_context->ctx_data;
        ns_list_init(&ctx_data->registered_translators);
        ns_list_init(&ctx_data->not_accepted_translators);

        if (!create_server_event_loop(g_program_context, http_port)) {
            tr_err("Could not create http server.");
            rc = 1;
            break;
        }

        timeout_handler = rpc_request_timeout_api_start(g_program_context->ev_base,
                                                        SERVER_TIMEOUT_CHECK_INTERVAL_MS,
                                                        SERVER_REQUEST_TIMEOUT_THRESHOLD_MS);

        if (!timeout_handler) {
            // error message already printed.
            break;
        }
        // Create client
        tr_info("Starting Device Management Edge Cloud Client");
        edgeclient_create_params.handle_write_to_pt_cb = write_to_pt;
        edgeclient_create_params.handle_register_cb = register_cb;
        edgeclient_create_params.handle_unregister_cb = unregister_cb;
        edgeclient_create_params.handle_error_cb = error_cb;
        edgeclient_create_params.handle_cert_renewal_status_cb = (handle_cert_renewal_status_cb)
                certificate_renewal_notifier;
        edgeclient_create_params.handle_est_status_cb = (handle_est_status_cb)
            est_enrollment_result_notifier;
        edgeclient_create_params.cert_renewal_ctx = &g_program_context->ctx_data->registered_translators;

        // args.cbor_conf is in stack
        #ifdef DEVELOPER_MODE
        if (args.cbor_conf) {
           tr_err("developer mode, cannot give cbor conf.");
           rc = 1;
           break;
        }
        #endif
        byoc_data_t *byoc_data = edgeclient_create_byoc_data(args.cbor_conf);

        edgeclient_create(&edgeclient_create_params, byoc_data);
        rfs_add_factory_reset_resource();

        // Connect client
        edgeclient_connect();

        // Need to initialize crypto RPC API after client as we use tasklet to
        // synchronise crypto operations
        crypto_api_protocol_init();
#ifndef BUILD_TYPE_TEST
        if (!setup_signals(g_program_context->ev_base)) {
            tr_err("Failed to setup signals.");
            rc = 1;
            break;
        }
#endif
        websocket_set_log_level_and_emit_function();
        lwsc = initialize_libwebsocket_context(g_program_context->ev_base,
                                               edge_pt_socket,
                                               edge_server_protocols,
                                               &lock_fd);
        if (lwsc && event_base_dispatch(g_program_context->ev_base) != 0) {
            tr_err("Failed to start event loop.");
            rc = 1;
            break;
        }
    }
    crypto_api_protocol_destroy();
    rpc_request_timeout_api_stop(timeout_handler);
    clean_resources(lwsc, edge_pt_socket, lock_fd);
    libevent_global_shutdown();
    edge_trace_destroy();
    return rc;
}

