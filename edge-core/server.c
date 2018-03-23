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

#include <fstrm/fstrm.h>

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "edge-core/protocol_api.h"
#include "edge-core/protocol_api_internal.h"
#include "edge-core/http_server.h"
#include "edge-core/server.h"
#include "common/edge_common.h"
#include "edge-client/edge_client.h"
#include "edge-core/srv_comm.h"
#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP "serv"

struct context;
struct connection;

struct connection* connection_init(struct context *ctx)
{
    struct connection *connection = (struct connection *)calloc(1, sizeof(struct connection));
    protocol_translator_t *pt = edge_common_create_protocol_translator();

    connection->protocol_translator = pt;
    connection->state = CONNECTION_STATE_READING_CONTROL_READY;
    connection->ctx = ctx;
    connection->control = fstrm_control_init();

    /* Initialize all other fields to NULL */
    connection->len_frame_payload = 0;
    connection->len_frame_total = 0;
    connection->bev = NULL;
    connection->ev_input = NULL;
    connection->ev_output = NULL;
    return connection;
}

void connection_free(struct connection *connection)
{
    tr_debug("Freeing connection structure %p", connection);
    edgeclient_remove_resources_owned_by_client((void *) connection);
    edgeclient_remove_objects_owned_by_client((void *) connection);
    protocol_api_free_pt_resources(connection->protocol_translator);

    fstrm_control_destroy(&connection->control);
    free(connection->protocol_translator->name);
    free(connection->protocol_translator);
    free(connection);
}

EDGE_LOCAL void event_cb(struct bufferevent *bev, short events, void *arg)
{
    struct connection *connection = (struct connection *) arg;
    if (events & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
        if (events & BEV_EVENT_ERROR) {
            tr_err("event_cb: 0x%x <--> connection %p", events, connection);
        } else {
            tr_debug("event_cb: 0x%x <--> connection %p", events, connection);
        }
        stop_free_bufferevent(bev, events, arg);
    }
}

EDGE_LOCAL void accept_conn_cb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *address, int socklen,
                           void *ctx)
{
    /* Set common socket options */
    edge_common_set_socket_options(fd);

    /* We got a new connection! Set up a bufferevent for it. */
    struct event_base *base = evconnlistener_get_base(listener);
    struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);

    if (bev) {
        /* Set up the tracked connection */
        struct connection *connection = (struct connection *)connection_init(ctx);
        tr_debug("Accepted new connection %p", connection);
        bufferevent_setcb(bev, edge_common_read_cb, NULL /* write_cb */, event_cb, connection);
        bufferevent_enable(bev, EV_READ | EV_WRITE);
        tr_info("Connection accepted.");
    } else {
        tr_err("Connection error.");
        evutil_closesocket(fd);
        return;
    }
}

EDGE_LOCAL void cb_accept_error(struct evconnlistener *listener, void *arg)
{
    const int err = EVUTIL_SOCKET_ERROR();
    fprintf(stderr, "Accept() failed: %s\n", evutil_socket_error_to_string(err));
}

bool create_server_event_loop(struct context *ctx, int protocol_port, int http_port)
{
    init_protocol();
    edge_common_init_event_cb(event_cb);

    /* Configure libevent */
    if (edge_common_configure_libevent() != 0) {
        tr_err("Libevent configuring failed!");
        return false;
    }

    ctx->ev_base = event_base_new();
    if (!ctx->ev_base) {
        tr_err("Cannot create event base");
        return false;
    }

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;

    #ifdef BIND_TO_ALL_INTERFACES
        sin.sin_addr.s_addr = htonl(0x00000000); /* 0.0.0.0 bind to all interfaces */
    #else
        sin.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
    #endif

    sin.sin_port = htons(protocol_port);

    tr_info("Listening %d on port %d.", sin.sin_addr.s_addr, protocol_port);

    unsigned flags = 0;
    flags |= LEV_OPT_CLOSE_ON_FREE;
    flags |= LEV_OPT_CLOSE_ON_EXEC;
    flags |= LEV_OPT_REUSEABLE;

    bool http_server_init_ok = false;
    ctx->ev_connlistener = evconnlistener_new_bind(ctx->ev_base, accept_conn_cb, (void*) ctx, flags, /* backlog */-1,
                                                   (struct sockaddr*) &sin, sizeof(sin));
    if (!ctx->ev_connlistener) {
        tr_err("Cannot create connection listener to port %d", protocol_port);
    } else {
        http_server_init_ok = http_server_init(ctx, http_port);
        if (!http_server_init_ok) {
            tr_err("Cannot create http server to port %d.", http_port);
        }
    }

    if (!ctx->ev_connlistener || !http_server_init_ok) {
        event_base_free(ctx->ev_base);
        ctx->ev_base = NULL;
        return false;
    }

    evconnlistener_set_error_cb(ctx->ev_connlistener, cb_accept_error);

    return true;
}
