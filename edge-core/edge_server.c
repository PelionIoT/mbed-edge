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
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "edge-client/edge_client.h"
#include "edge-core/protocol_api.h"
#include "edge-core/protocol_api_internal.h"
#include "edge-core/server.h"
#include "edge-core/edge_server.h"
#include "edge-core/http_server.h"
#include "common/edge_common.h"

// Cloud client
#include "pal.h"
#include "ns_list.h"
#include "mbed-trace/mbed_trace.h"
#include "common/test_support.h"
#include "edge-core/edge_core_clip.h"
#include "edge-client/reset_factory_settings.h"
#define TRACE_GROUP "serv"

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
        protocol_api_free_pt_resources(connection->protocol_translator);
        connections_removed = true;
    }
    return connections_removed;
}

void edgeserver_graceful_shutdown()
{
    struct ctx_data *ctx_data = g_program_context->ctx_data;
    struct evconnlistener *ev_connlistener = g_program_context->ev_connlistener;
    tr_info("edgeserver_graceful_shutdown");
    ctx_data->exiting = true;
    bool stop_frame_sent = false;
    evconnlistener_disable(ev_connlistener);
    evconnlistener_set_cb(ev_connlistener, NULL, NULL);

    ns_list_foreach_safe(struct connection_list_elem, cur, &ctx_data->registered_translators) {
        struct connection *connection = cur->conn;
        edge_common_write_stop_frame(connection);
        stop_frame_sent = true;
    }
    if(!stop_frame_sent) {
        // If there is no client connected, we can start exiting immediately.
        edgeserver_exit_event_loop();
    }
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
    if (ctx->ev_connlistener != NULL) {
        evconnlistener_free(ctx->ev_connlistener);
    }
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
    clean(g_program_context);
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

#ifndef BUILD_TYPE_TEST
int main(int argc, char **argv)
#else
int testable_main(int argc, char **argv)
#endif
{
    int rc = 0;
    int counter;
    memset(&edgeclient_create_params, 0, sizeof(edgeclient_create_parameters_t));
    DocoptArgs args = docopt(argc, argv, /* help */ 1, /* version */ VERSION_STRING);
    bool free_resources = true;

    if (args.reset_storage) {
        edgeclient_create_params.reset_storage = true;
    }

    for (counter = 0; counter < 1; counter ++) {
        // Initialize trace and trace mutex
        mbed_trace_init();
        trace_mutex_init();
// enabling following will require to expecting wait mutexes for every trace in during the tests
#ifndef BUILD_TYPE_TEST
        mbed_trace_mutex_wait_function_set(trace_mutex_wait);
        mbed_trace_mutex_release_function_set(trace_mutex_release);
#endif
        pal_init();
        //Initialize timestamp pointer and the prefix function
        timestamp_prefix = calloc(TIMESTAMP_SIZE, sizeof (char));
        mbed_trace_prefix_function_set(&trace_prefix);

        int port = atoi(args.pt_api_port);
        int http_port = atoi(args.http_port);
        create_program_context_and_data();
        struct ctx_data *ctx_data = g_program_context->ctx_data;
        ns_list_init(&ctx_data->registered_translators);
        ns_list_init(&ctx_data->not_accepted_translators);

        // Create client
        tr_info("Starting mbed Edge Core cloud client");
        edgeclient_create_params.handle_write_to_pt_cb = write_to_pt;
        edgeclient_create_params.handle_register_cb = register_cb;
        edgeclient_create_params.handle_unregister_cb = unregister_cb;
        edgeclient_create_params.handle_error_cb = error_cb;
        edgeclient_create(&edgeclient_create_params);
        rfs_add_factory_reset_resource();
        // Connect client
        edgeclient_connect();

        if (create_server_event_loop(g_program_context, port, http_port)) {
#ifndef BUILD_TYPE_TEST
            if (!setup_signals()) {
                tr_err("Failed to setup signals.");
                rc = 1;
                break;
            }
#endif
            if (event_base_dispatch(g_program_context->ev_base) != 0) {
                tr_err("Failed to start event loop.");
                rc = 1;
                break;
            }
        } else {
            rc = 1;
            break;
        }
    }
    if (free_resources) {
        free_program_context_and_data();
        pal_destroy();
        free(timestamp_prefix);
        timestamp_prefix = NULL;
    }
    return rc;
}

