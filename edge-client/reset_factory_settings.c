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

#define TRACE_GROUP "edgerfs"
#include "edge-client/edge_client.h"
#include "edge-core/edge_device_object.h"
#include <stddef.h>
#include "key_config_manager.h"
#include "mbed-trace/mbed_trace.h"
#include "edge-core/edge_server.h"
#include "edge-client/msg_api.h"
#include "common/test_support.h"
#include "edge-client/edge_core_cb_result.h"
#include "edge-client/reset_factory_settings.h"
#include "edge-core/edge_server_customer_code.h"
#include "edge-client/reset_factory_settings_internal.h"
#include <string.h>

typedef struct x_rfs_thread_param {
    edgeclient_request_context_t *ctx;
    pthread_t *thread;
} rfs_thread_param_t;

typedef struct x_rfs_thread_result
{
    EVENT_MESSAGE_BASE;
    pthread_t *thread;
    bool customer_rfs_succeeded;
} rfs_thread_result_t;

typedef struct x_rfs_request_message {
    EVENT_MESSAGE_BASE;
    edgeclient_request_context_t *request_ctx;
} rfs_request_message_t;

void rfs_finalize_reset_factory_settings()
{
    tr_info("Finalizing rfs settings");
    kcm_status_e kcm_status = kcm_factory_reset();
    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_err("Failed to do factory reset - %d", kcm_status);
    }
}

EDGE_LOCAL void rfs_reset_factory_settings_request_cb(evutil_socket_t fd, short what, void *arg);
EDGE_LOCAL void rfs_reset_factory_settings_response_cb(evutil_socket_t fd, short what, void *arg);

void rfs_reset_factory_settings_requested(edgeclient_request_context_t *request_ctx)
{
    // Send request to main thread, because it's easier to join the RFS thread there.
    rfs_request_message_t *message =
            (rfs_request_message_t *) msg_api_allocate_and_init_message(sizeof(rfs_request_message_t));
    if (message) {
        message->request_ctx = request_ctx;
        msg_api_send_message((event_message_t *) message, rfs_reset_factory_settings_request_cb);
    } else {
        tr_err("Cannot send the reset factory settings request message!");
    }
}

static void *rfs_thread(void *arg)
{
    rfs_thread_param_t *param = arg;
    edgeclient_request_context_t *request_ctx = param->ctx;
    bool success = edgeserver_execute_rfs_customer_code(request_ctx);

    if (success) {
        edgecore_execute_success(request_ctx);
    } else {
        edgecore_execute_failure(request_ctx);
    }
    rfs_thread_result_t *result =
            (rfs_thread_result_t *) msg_api_allocate_and_init_message(sizeof(rfs_thread_result_t));
    if (result) {
        result->customer_rfs_succeeded = success;
        result->thread = param->thread;
        msg_api_send_message((event_message_t *) result, rfs_reset_factory_settings_response_cb);
    } else {
        tr_err("rfs_thread: cannot allocate message for sending the RFS result! thread leak!");
    }
    free(param);
    return NULL;
}

EDGE_LOCAL void rfs_reset_factory_settings_response_cb(evutil_socket_t fd, short what, void *arg)
{
    (void) fd;
    (void) what;
    rfs_thread_result_t *rfs_thread_result = (rfs_thread_result_t *) arg;
    free(rfs_thread_result->ev);
    tr_debug("Sending response to Mbed Cloud");
    pt_api_result_code_e status =
            edgeclient_send_delayed_response(NULL, EDGE_DEVICE_OBJECT_ID, 0, EDGE_FACTORY_RESET_RESOURCE_ID);
    if (status != PT_API_SUCCESS) {
        tr_err("edgeclient_send_delayed_response failed! returned status: %d", status);
    }
    void *result;
    int join_status = pthread_join(*rfs_thread_result->thread, &result);
    free(rfs_thread_result->thread);
    if (join_status) {
        tr_err("Failed to join the RFS thread! result was %d - %s", join_status, strerror(join_status));
    }
    if (rfs_thread_result->customer_rfs_succeeded) {
        edgeserver_rfs_customer_code_succeeded();
        edgeserver_graceful_shutdown();
    }
    free(rfs_thread_result);
}

// This will happen in main thread
EDGE_LOCAL void rfs_reset_factory_settings_request_cb(evutil_socket_t fd, short what, void *arg)
{
    (void) fd;
    (void) what;
    tr_debug("rfs_reset_factory_settings_request_cb");
    pthread_t *rfs_thread_p = (pthread_t *) calloc(1, sizeof(pthread_t));
    if (rfs_thread_p == NULL) {
        tr_err("Cannot allocate memory for the rfs thread struct");
        return;
    }

    rfs_request_message_t *message = (rfs_request_message_t *) arg;
    rfs_thread_param_t *param = (rfs_thread_param_t *) calloc(1, sizeof(rfs_thread_param_t));
    if (param == NULL) {
        free(rfs_thread_p);
        tr_err("Cannot allocate memory for the rfs thread struct parameters");
        return;
    }

    param->thread = rfs_thread_p;
    param->ctx = (edgeclient_request_context_t *) message->request_ctx;
    free(message->ev);
    free(message);
    if (!rfs_thread_p || pthread_create(rfs_thread_p, NULL, rfs_thread, (void *) param)) {
        tr_err("Cannot create the rfs thread");
        free(rfs_thread_p);
    }
}

void rfs_add_factory_reset_resource()
{
    edgeclient_set_resource_value(NULL,
                                  EDGE_DEVICE_OBJECT_ID,
                                  0,
                                  EDGE_FACTORY_RESET_RESOURCE_ID,
                                  (uint8_t *) NULL,
                                  0,
                                  LWM2M_OPAQUE,
                                  OPERATION_EXECUTE,
                                  /* userdata */ NULL);
    edgeclient_set_delayed_response(NULL, EDGE_DEVICE_OBJECT_ID, 0, EDGE_FACTORY_RESET_RESOURCE_ID, true);
}


