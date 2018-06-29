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

#include "event2/http.h"
#include "event2/buffer.h"

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "edge-core/http_server.h"

#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP "serv"

EDGE_LOCAL void add_ok_response_headers(struct evhttp_request *req)
{
    evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/json");
    evhttp_add_header(evhttp_request_get_output_headers(req), "Charset", "utf-8");
}

EDGE_LOCAL void reply_ok_and_status(struct context *ctx, struct evhttp_request *req, struct evbuffer *buf)
{
    json_t *obj = NULL;
    char *reply = NULL;

    add_ok_response_headers(req);

    obj = http_state_in_json(ctx);
    reply = json_dumps(obj, ctx->json_flags);
    evbuffer_add(buf, reply, strlen(reply));
    evhttp_send_reply(req, 200, "OK", buf);

    /* Cleanup */
    json_decref(obj);
    obj = NULL;
    free(reply);
    reply = NULL;
}

/* Callback used for the /status URI.
 * For every non-GET request:
 * returns error code 505 */
EDGE_LOCAL void status_request_cb(struct evhttp_request *req, void *arg)
{
    struct context *ctx = (struct context *) (arg);
    const char *uri = evhttp_request_get_uri(req);
    struct evhttp_uri *decoded_uri = NULL;
    const char *query = NULL;
    struct evbuffer *buf = evbuffer_new();

    decoded_uri = evhttp_uri_parse(uri);
    if (!decoded_uri) {
        tr_warn("It's not a good URI");
        evhttp_send_reply(req, HTTP_BADREQUEST, "Bad request", buf);
        goto cleanup;
    }

    query = evhttp_uri_get_query(decoded_uri);
    evhttp_uri_free(decoded_uri);
    decoded_uri = NULL;

    if (query) {
        tr_warn("No query is yet supported");
        evhttp_send_reply(req, HTTP_BADREQUEST, "Bad request", buf);
        goto cleanup;
    }
    if (evhttp_request_get_command(req) != EVHTTP_REQ_GET) {
        tr_warn("Request type is not get");
        evhttp_send_reply(req, HTTP_BADMETHOD, "Method not allowed", buf);
        evhttp_add_header(evhttp_request_get_output_headers(req), "Allow", "GET");
        goto cleanup;
    }

    reply_ok_and_status(ctx, req, buf);

    cleanup: evbuffer_free(buf);
}

EDGE_LOCAL void generic_request_cb(struct evhttp_request *req, void *arg)
{
    struct evbuffer *buf = evbuffer_new();
    (void) arg;
    evhttp_send_reply(req, HTTP_NOTFOUND, "Not found", buf);
    evbuffer_free(buf);
    buf = NULL;
}

bool http_server_init(struct context *ctx, int port)
{
    struct evhttp *http = NULL;
    struct evhttp_bound_socket *handle = NULL;
    bool init_succeeded = false;

    struct ctx_data *ctx_data = ctx->ctx_data;
    ctx_data->http_server = calloc(1, sizeof(struct http_server));
    ctx_data->http_server->http = http = evhttp_new(ctx->ev_base);
    if (!http) {
        tr_err("Couldn't create evhttp.\n");
    } else if (evhttp_set_cb(http, "/status", status_request_cb, ctx)) {
        tr_err("Couldn't set the status request call back.\n");
    } else {
        evhttp_set_gencb(http, generic_request_cb, NULL);
        ctx_data->http_server->bound_socket = handle = evhttp_bind_socket_with_handle(http, "127.0.0.1", port);
        if (!handle) {
            tr_err("Couldn't bind to port %d.\n", (int) port);
        } else {
            tr_info("Listening 127.0.0.1 on http port %d.", port);
            init_succeeded = true;
        }
    }
    if (!init_succeeded) {
        http_server_clean(&(ctx_data->http_server));
    }
    return init_succeeded;
}

void http_server_clean(struct http_server **server)
{
    tr_info("Cleaning http server resources");
    if (*server) {
        if ((*server)->bound_socket) {
            evhttp_del_accept_socket((*server)->http, (*server)->bound_socket);
            (*server)->bound_socket = NULL;
        }
        if ((*server)->http) {
            evhttp_free((*server)->http);
            (*server)->http = NULL;
        }
        free(*server);
        *server = NULL;
    }
}
