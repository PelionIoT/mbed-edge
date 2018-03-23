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

// libevent
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

// libfstrm, frame streams
#include <fstrm.h>

#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "common/edge_common.h"
#include "common/default_message_id_generator.h"
#include "pt-client/pt_api.h"

#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP "clnt"

static generate_msg_id g_generate_msg_id;

struct connection* connection_init(struct context *ctx,
                                   protocol_translator_t *protocol_translator,
                                   struct bufferevent *bev,
                                   const protocol_translator_callbacks_t *pt_cbs,
                                   void *userdata)
{
    struct connection *connection;
    connection = calloc(1, sizeof(*connection));
    connection->state = CONNECTION_STATE_WRITING_CONTROL_READY;
    connection->ctx = ctx;
    connection->control = fstrm_control_init();
    connection->bev = bev;
    connection->ev_input = bufferevent_get_input(connection->bev);
    connection->ev_output = bufferevent_get_output(connection->bev);
    connection->protocol_translator = protocol_translator;
    connection->protocol_translator_callbacks = pt_cbs;
    connection->userdata = userdata;

    fstrm_res res;
    res = fstrm_control_set_type(connection->control, FSTRM_CONTROL_READY);
    if (res != fstrm_res_success)
        exit(1);

    return connection;
}

void connection_free(struct connection *connection)
{
    tr_debug("Freeing connection structure");
    fstrm_control_destroy(&connection->control);
    free(connection->protocol_translator->name);
    free(connection->protocol_translator);
    free(connection);
}

void pt_client_set_msg_id_generator(generate_msg_id generate_msg_id)
{
    if (generate_msg_id == NULL) {
        g_generate_msg_id = edge_default_generate_msg_id;
    } else {
        g_generate_msg_id = generate_msg_id;
    }
}

void event_cb(struct bufferevent *bev, short events, void *arg)
{
    struct connection **connection = (struct connection **) arg;
    bool destroyed_connection = false;

    if (events & BEV_EVENT_ERROR) {
        tr_err("Libevent error: %s (%d)", strerror(errno), errno);

        /*
         * The BEV_OPT_CLOSE_ON_FREE flag is set on our bufferevent's, so the
         * following call to bufferevent_free() will close the underlying
         * socket transport.
         */
        //Free the connection, because freeing connection does not nullify the pointer
        edge_common_connection_destroy(connection);
    }
    if (events & BEV_EVENT_CONNECTED) {
        /*
         * Initialize the api with opened connection
         * Message generator initialization is checked here and if it is null
         * a default implementation is forced
         */
        if (g_generate_msg_id == NULL) pt_client_set_msg_id_generator(NULL);
        rpc_set_generate_msg_id(g_generate_msg_id);
        pt_init_service_api();

        if (!edge_common_process_control_frame(*connection, &destroyed_connection)) {
            tr_warn("Control frame process failed.");
        }
    }
    if ((events & BEV_EVENT_EOF) && (!destroyed_connection)) {
        tr_info("EOF on socket.");
        edge_common_connection_destroy(connection);
    }
}

void read_cb(struct bufferevent *bev, void *ctx)
{
    struct connection **connection = (struct connection **) ctx;
    edge_common_read_cb(bev, *connection);
}

static bool create_client_event_loop(struct context *ctx,
                                     protocol_translator_t *protocol_translator,
                                     const protocol_translator_callbacks_t *pt_cbs,
                                     struct connection **connection,
                                     void *userdata)
{
    bool ret_val = true;
    struct addrinfo hints;
    struct addrinfo *address_search_result = NULL;
    struct addrinfo *address_iter = NULL;
    struct sockaddr_in sin;
    int status;
    int32_t loop_iter;
    char ip_string[INET6_ADDRSTRLEN];
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    strncpy(ip_string, "127.0.0.1", INET6_ADDRSTRLEN);
    struct sockaddr *socket_address = (struct sockaddr *) &sin;
    socklen_t socket_address_length = sizeof(struct sockaddr_in);
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6 to force version
    hints.ai_socktype = SOCK_STREAM;
    char port_string[21];
    sprintf(port_string, "%u", ctx->port);

    for (loop_iter = 0; loop_iter < 1; loop_iter++) {
        if (ctx->hostname != NULL) {
            socket_address = NULL;
            socket_address_length = 0;
            if ((status = getaddrinfo(ctx->hostname, port_string, &hints, &address_search_result)) != 0) {
                tr_err("getaddrinfo: %s\n", gai_strerror(status));
                ret_val = false;
                break;
            }
            for (address_iter = address_search_result; address_iter != NULL; address_iter = address_iter->ai_next) {
                void *addr;

                // get the pointer to the address itself,
                // different fields in IPv4 and IPv6:
                if (address_iter->ai_family == AF_INET) { // IPv4
                    struct sockaddr_in *ipv4 = (struct sockaddr_in *) address_iter->ai_addr;
                    addr = &(ipv4->sin_addr);
                    tr_debug("found IPV4 address");
                } else { // IPv6
                    struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *) address_iter->ai_addr;
                    addr = &(ipv6->sin6_addr);
                    tr_debug("found IPV6 address");
                }

                // convert the IP to a string to print it:
                inet_ntop(address_iter->ai_family, addr, ip_string, sizeof(ip_string));
                socket_address = (struct sockaddr *) address_iter->ai_addr;
                socket_address_length = address_iter->ai_addrlen;
                break;
            }
        } else {
            sin.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
        }
        tr_info("Connecting to %s on port %d.", ip_string, ctx->port);
        ctx->ev_base = event_base_new();
        if (!ctx->ev_base) {
            ret_val = false;
            break;
        }

        struct bufferevent *bev = bufferevent_socket_new(ctx->ev_base, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);
        if (!bev) {
            tr_err("Could not allocate buffer.");
            ret_val = false;
            break;
        }
        edge_common_set_socket_options(bufferevent_getfd(bev));

        *connection = connection_init(ctx, protocol_translator, bev, pt_cbs, userdata);
        sin.sin_port = htons(ctx->port);

        bufferevent_setcb(bev, read_cb, NULL /* write_cb */, event_cb, connection);
        bufferevent_enable(bev, EV_READ | EV_WRITE);
        if (bufferevent_socket_connect(bev, socket_address, socket_address_length) < 0) {
            tr_err("Libevent error: %s (%d)", strerror(errno), errno);
            tr_err("Connection error.");
            ret_val = false;
            break;
        }
        tr_info("Connection up.");
    }
    freeaddrinfo(address_search_result); // free the linked list

    return ret_val;
}

static void clean(struct context *ctx, struct connection **connection)
{
    if (connection) {
        edge_common_connection_destroy(connection);
    }

    if (ctx && ctx->ev_base) {
        event_base_free(ctx->ev_base);
    }
    free(ctx);
}

void pt_client_shutdown(struct connection *connection)
{
    /*
     * Check that connection is valid.
     * if registration of protocol translator fails this is NULL.
     */
    if (connection) {
        edge_common_write_stop_frame(connection);
    }
}

void pt_client_initialize_trace_api()
{
    // Initialize trace and trace mutex
    mbed_trace_init();
    trace_mutex_init();
    mbed_trace_mutex_wait_function_set(trace_mutex_wait);
    mbed_trace_mutex_release_function_set(trace_mutex_release);

    //Initialize timestamp pointer and the prefix function
    timestamp_prefix = calloc(TIMESTAMP_SIZE, sizeof (char));
    mbed_trace_prefix_function_set(&trace_prefix);
}

static int check_protocol_translator_callbacks(const protocol_translator_callbacks_t *pt_cbs)
{
    if (pt_cbs->connection_ready_cb == NULL || pt_cbs->received_write_cb == NULL || pt_cbs->connection_shutdown_cb == NULL) {
        return 1;
    }
    return 0;
}

int pt_client_start(const char *hostname,
                    const int port,
                    const char *name,
                    const protocol_translator_callbacks_t *pt_cbs,
                    void *userdata,
                    struct connection **connection)
{
    tr_debug("hostname = %s, port=%d, name=%s ", hostname, port, name);
    int rc = 0;
    protocol_translator_t *protocol_translator = NULL;
    struct context *program_context = NULL;

    /* Configure libevent */
    if (edge_common_configure_libevent() != 0) {
        tr_err("Libevent configuring failed!");
        rc = 1;
        goto cleanup;
    }

    edge_common_init_event_cb(event_cb);

    protocol_translator = edge_common_create_protocol_translator();
    protocol_translator->name = (char *) name;
    protocol_translator->registered = false;

    if (check_protocol_translator_callbacks(pt_cbs)) {
        tr_err("Protocol translator callbacks not set.");
        rc = 1;
        goto cleanup;
    }

    program_context = calloc(1, sizeof(struct context));
    program_context->hostname = hostname;
    program_context->port = port;
    program_context->json_flags = JSON_COMPACT;

    if (true == create_client_event_loop(program_context, protocol_translator, pt_cbs, connection, userdata)) {
        if (event_base_dispatch(program_context->ev_base) != 0) {
            tr_err("event_base_dispatch failed");
            rc = 1;
            goto cleanup;
        }

    } else {
        rc = 1;
        tr_err("Couldn't create client event loop.");
    }
    tr_info("Protocol translator api eventloop closed.");
cleanup:
    clean(program_context, connection);
    program_context = NULL;
    free(protocol_translator);
    mbed_trace_free();
    return rc;
}

void pt_client_final_cleanup()
{
    rpc_destroy_messages();
}
