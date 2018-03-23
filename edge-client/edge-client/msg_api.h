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

#ifndef MSG_API_H
#define MSG_API_H

#include <stddef.h>
#include <event2/event.h>

// this needs the be at the beginning of the event message
#define EVENT_MESSAGE_BASE struct event *ev

typedef struct x_event_message {
    EVENT_MESSAGE_BASE;
} event_message_t;

event_message_t *msg_api_allocate_and_init_message(size_t msg_size);
void msg_api_free_message(event_message_t *message);
void msg_api_send_message(event_message_t *message, event_callback_fn event_cb);

#endif
