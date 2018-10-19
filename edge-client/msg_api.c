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
#include "edge-client/msg_api.h"
#include "mbed-trace/mbed_trace.h"
#include "edge-core/edge_server.h"
#include <stdlib.h>

static void msg_api_add_event_from_thread(struct event *ev)
{
    /* 1 microsecond timer is needed, because if we just pass NULL timeval, the message will not be received */
    const struct timeval micro_sec = {0, 1};
    int ev_add_result = event_add(ev, &micro_sec);
    (void) ev_add_result;
    tr_debug("event_add returned %d", ev_add_result);
}


event_message_t *msg_api_allocate_and_init_message(size_t msg_size)
{
    event_message_t *message = (event_message_t *) calloc(1, msg_size);
    struct event *ev = calloc(1, event_get_struct_event_size());
    if (ev == NULL || message == NULL) {
        free(message);
        free(ev);
        tr_err("msg_api_allocate_and_init_message cannot allocate memory!");
        return NULL;
    }
    message->ev = ev;
    return message;
}

void msg_api_free_message(event_message_t *message)
{
    if (message) {
        free(message->ev);
        free(message);
    }
}

void msg_api_send_message(event_message_t *message, event_callback_fn event_cb)
{
    struct event_base *base = edge_server_get_base();
    if (event_assign(message->ev, base, -1, 0, event_cb, message) == 0) {
        msg_api_add_event_from_thread(message->ev);
    } else {
        tr_err("Cannot assign event in msg_api_send_message");
    }
}

