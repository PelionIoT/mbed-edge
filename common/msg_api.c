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

#define TRACE_GROUP "edgemsgapi"
#include <event2/event.h>
#include "common/msg_api.h"
#include "common/msg_api_internal.h"
#include "mbed-trace/mbed_trace.h"
#include "common/test_support.h"
#include <stdlib.h>
#include <assert.h>

static bool msg_api_add_event_from_thread(struct event *ev)
{
    int ev_add_result = event_add(ev, NULL);
    if (ev_add_result != 0) {
        tr_err("event_add returned %d", ev_add_result);
        return false;
    }
    event_active(ev, 0, 0);
    return true;
}

static bool msg_api_add_event_from_thread_with_timeout_in_ms(struct event *ev, int32_t timeout_in_ms)
{
    struct timeval duration;
    duration.tv_sec = timeout_in_ms / 1000;
    duration.tv_usec = (timeout_in_ms % 1000) * 1000;
    int ev_add_result = event_add(ev, &duration);
    if (ev_add_result != 0) {
        tr_err("event_add returned %d", ev_add_result);
        return false;
    }
    return true;
}

EDGE_LOCAL void event_cb(evutil_socket_t fd, short what, void *arg)
{
    event_message_t *message = (event_message_t *) arg;
    (*message->callback)(message->data);
    free(message->ev);
    free(message);
}

static event_message_t *msg_api_allocate_and_init_message(void *data, event_loop_callback_t callback)
{
    event_message_t *message = (event_message_t *) calloc(1, sizeof(event_message_t));
    struct event *ev = calloc(1, event_get_struct_event_size());
    if (ev == NULL || message == NULL) {
        free(message);
        free(ev);
        tr_err("msg_api_allocate_and_init_message cannot allocate memory!");
        return NULL;
    }
    message->ev = ev;
    message->callback = callback;
    message->data = data;
    return message;
}

bool msg_api_send_message(struct event_base *base, void *data, event_loop_callback_t callback)
{
    event_message_t *message = msg_api_allocate_and_init_message(data, callback);
    if (!message) {
        tr_err("Cannot allocate memory for MSG API message");
        return false;
    }
    assert(callback != NULL);
    if (event_assign(message->ev, base, -1, 0, event_cb, message) == 0) {
        return msg_api_add_event_from_thread(message->ev);
    } else {
        free(message->ev);
        free(message);
        tr_err("Cannot assign event in msg_api_send_message");
        return false;
    }
}

bool msg_api_send_message_after_timeout_in_ms(struct event_base *base,
                                              void *data,
                                              event_loop_callback_t callback,
                                              int32_t timeout_in_ms)
{
    event_message_t *message = msg_api_allocate_and_init_message(data, callback);
    if (!message) {
        tr_err("Cannot allocate memory for MSG API timed message");
        return false;
    }
    assert(callback != NULL);
    if (event_assign(message->ev, base, -1, 0, event_cb, message) == 0) {
        return msg_api_add_event_from_thread_with_timeout_in_ms(message->ev, timeout_in_ms);
    } else {
        tr_err("Cannot assign event in msg_api_send_message_after_timeout_in_ms");
        return false;
    }
}

