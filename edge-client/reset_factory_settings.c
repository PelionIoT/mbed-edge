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
#include "common/msg_api.h"
#include "common/test_support.h"
#include "edge-client/edge_core_cb_result.h"
#include "edge-client/reset_factory_settings.h"
#include "edge-core/edge_server_customer_code.h"
#include "edge-client/reset_factory_settings_internal.h"
#ifdef RFS_GPIO
#include "gpiod.h"
#endif
#include <string.h>

void rfs_finalize_reset_factory_settings()
{
    tr_info("Finalizing rfs settings");
    kcm_status_e kcm_status = kcm_factory_reset();
    if (kcm_status != KCM_STATUS_SUCCESS) {
        tr_err("Failed to do factory reset - %d", kcm_status);
    }
}

void rfs_reset_factory_settings_requested(edgeclient_request_context_t *request_ctx)
{
    // Send request to main thread, because it's easier to join the RFS thread there.
    rfs_request_message_t *message = (rfs_request_message_t *) calloc(1, sizeof(rfs_request_message_t));
    if (message) {
        message->request_ctx = request_ctx;
        struct event_base *base = edge_server_get_base();
        if (!msg_api_send_message(base, message, rfs_reset_factory_settings_request_cb)) {
            tr_err("Cannot sent the reset factory settings request message!");
        }
    } else {
        tr_err("Cannot allocate the reset factory settings request message!");
    }
}

static void *rfs_thread(void *arg)
{
    rfs_thread_param_t *param = arg;
    // Note request_ctx can be NULL if initiated via local GPIO
    edgeclient_request_context_t *request_ctx = param->ctx;
    bool success = edgeserver_execute_rfs_customer_code(request_ctx);

    rfs_thread_result_t *result = (rfs_thread_result_t *) calloc(1, sizeof(rfs_thread_result_t));
    if (result) {
        result->customer_rfs_succeeded = success;
        result->thread = param->thread;
        result->request_ctx = request_ctx;
        struct event_base *base = edge_server_get_base();
        if (!msg_api_send_message(base, result, rfs_reset_factory_settings_response_cb)) {
            tr_err("Cannot send the RFS response message!");
            free(result);
        }
    } else {
        tr_err("rfs_thread: cannot allocate message for sending the RFS result! thread leak!");
    }
    free(param);
    return NULL;
}

EDGE_LOCAL void rfs_reset_factory_settings_response_cb(void *arg)
{
    rfs_thread_result_t *rfs_thread_result = (rfs_thread_result_t *) arg;
    edgeclient_request_context_t *request_ctx = rfs_thread_result->request_ctx;
    // Note request_ctx can be NULL if initiated via local GPIO
    if (request_ctx) {
        tr_debug("Sending response to Cloud");
        if (rfs_thread_result->customer_rfs_succeeded) {
            edgecore_async_cb_success(request_ctx);
        } else {
            edgecore_async_cb_failure(request_ctx);
        }
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
EDGE_LOCAL void rfs_reset_factory_settings_request_cb(void *arg)
{
    tr_debug("rfs_reset_factory_settings_request_cb");
    pthread_t *rfs_thread_p = (pthread_t *) calloc(1, sizeof(pthread_t));
    if (rfs_thread_p == NULL) {
        tr_err("Cannot allocate memory for the rfs thread struct");
        free(arg);
        return;
    }

    rfs_request_message_t *message = (rfs_request_message_t *) arg;
    rfs_thread_param_t *param = (rfs_thread_param_t *) calloc(1, sizeof(rfs_thread_param_t));
    if (param == NULL) {
        free(rfs_thread_p);
        free(arg);
        tr_err("Cannot allocate memory for the rfs thread struct parameters");
        return;
    }

    param->thread = rfs_thread_p;
    param->ctx = (edgeclient_request_context_t *) message->request_ctx;
    if (!rfs_thread_p || pthread_create(rfs_thread_p, NULL, rfs_thread, (void *) param)) {
        tr_err("Cannot create the rfs thread");
        free(rfs_thread_p);
    }
    free(arg);
}

#ifdef RFS_GPIO

#ifndef RFS_GPIO_FLAGS
#define RFS_GPIO_FLAGS 0
#endif

#ifndef RFS_GPIO_HOLD_TIME
#define RFS_GPIO_HOLD_TIME 10
#endif

static void *rfs_gpio_thread(void *arg)
{
    struct gpiod_line *line = arg;
    struct gpiod_line_event last_event = { 0 };
    last_event.event_type = GPIOD_LINE_EVENT_FALLING_EDGE;

    for (;;) {
        struct gpiod_line_event event;
        // Wait for and read an event
        if (gpiod_line_event_read(line, &event)) {
            tr_err("gpiod_line_event_read error");
            break;
        }
        // If unknown event, ignore
        if (event.event_type != GPIOD_LINE_EVENT_FALLING_EDGE && event.event_type != GPIOD_LINE_EVENT_RISING_EDGE) {
            continue;
        }
        tr_info("rfs button %s", event.event_type == GPIOD_LINE_EVENT_RISING_EDGE ? "pressed" : "released");
        // Look for release after press
        if (last_event.event_type == GPIOD_LINE_EVENT_RISING_EDGE && event.event_type == GPIOD_LINE_EVENT_FALLING_EDGE) {
            // Check if it was pressed for at least RFS_GPIO_HOLD_TIME seconds
            long long secs = event.ts.tv_sec - last_event.ts.tv_sec;
            if (event.ts.tv_nsec < last_event.ts.tv_nsec) {
                secs--;
            }
            // If so, request the reset, and exit the GPIO handler
            if (secs >= RFS_GPIO_HOLD_TIME) {
                rfs_reset_factory_settings_requested(NULL);
                break;
            }
        }
        last_event = event;
    }

    gpiod_line_close_chip(line);
    return NULL;
}

static void rfs_configure_factory_reset_gpio()
{
    // Support (chip name + offset) or (chip name + line name) or (line name)
    struct gpiod_line *line = NULL;
#ifdef RFS_GPIO_CHIP
    struct gpiod_chip *chip = gpiod_chip_open_lookup(RFS_GPIO_CHIP);
    if (chip) {
#ifdef RFS_GPIO_OFFSET
        line = gpiod_chip_get_line(chip, RFS_GPIO_OFFSET);
#else
        line = gpiod_chip_find_line(chip, RFS_GPIO_NAME);
#endif
        if (!line) {
            gpiod_chip_close(chip);
        }
    }
#else
    line = gpiod_line_find(RFS_GPIO_NAME);
#endif
    if (!line) {
        tr_err("Cannot locate rfs gpio line");
        return;
    }
    if (gpiod_line_request_both_edges_events_flags(line, "edgeclient rfs", RFS_GPIO_FLAGS)) {
        tr_err("Cannot request rfs gpio events");
        gpiod_line_close_chip(line);
        return;
    }
    pthread_t gpio_thread;
    if (pthread_create(&gpio_thread, NULL, rfs_gpio_thread, line)) {
        tr_err("Cannot create the rfs gpio thread");
        gpiod_line_close_chip(line);
        return;
    }
}
#endif

void rfs_add_factory_reset_resource()
{
    edgeclient_set_resource_value(NULL,
                                  EDGE_DEVICE_OBJECT_ID,
                                  0,
                                  EDGE_FACTORY_RESET_RESOURCE_ID,
                                  "",
                                  (uint8_t *) NULL,
                                  0,
                                  LWM2M_OPAQUE,
                                  OPERATION_EXECUTE,
                                  /* userdata */ NULL);

#ifdef RFS_GPIO
    rfs_configure_factory_reset_gpio();
#endif
}


