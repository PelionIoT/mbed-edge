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
#include "CppUTestExt/MockSupport.h"
#include "test-lib/msg_api_mocks.h"
extern "C" {
#include "common/msg_api.h"
#include "ns_list.h"
}

static event_loop_messages_t event_loop_messages;

void mock_msg_api_wipeout_messages()
{
    ns_list_foreach_safe(event_loop_message_t, cur, &event_loop_messages)
    {
        ns_list_remove(&event_loop_messages, cur);
        free(cur);
    }
}

void mock_msg_api_messages_init()
{
    ns_list_init(&event_loop_messages);
}

int32_t mock_msg_api_messages_in_queue()
{
    return ns_list_count(&event_loop_messages);
}

event_loop_message_t *mock_msg_api_pop_message()
{
    event_loop_message_t *msg = ns_list_get_first(&event_loop_messages);
    if (msg) {
        ns_list_remove(&event_loop_messages, msg);
    }
    return msg;
}

bool msg_api_send_message(struct event_base *base, void *data, event_loop_callback_t callback)
{
    (void) base;
    bool ret_val = mock().actualCall("msg_api_send_message").returnBoolValue();
    if (ret_val) {
        event_loop_message_t *message = (event_loop_message_t *) calloc(1, sizeof(event_loop_message_t));
        message->data = data;
        message->timeout_in_ms = -1;
        message->callback = callback;
        ns_list_add_to_end(&event_loop_messages, message);
    }

    return ret_val;
}

bool msg_api_send_message_after_timeout_in_ms(struct event_base *base,
                                              void *data,
                                              event_loop_callback_t callback,
                                              int32_t timeout_in_ms)
{

    event_loop_message_t *message = (event_loop_message_t *) calloc(1, sizeof(event_loop_message_t));
    message->data = data;
    message->timeout_in_ms = timeout_in_ms;
    message->callback = callback;
    ns_list_add_to_end(&event_loop_messages, message);
    return mock().actualCall("msg_api_send_message_after_timeout_in_ms").returnBoolValue();
}
