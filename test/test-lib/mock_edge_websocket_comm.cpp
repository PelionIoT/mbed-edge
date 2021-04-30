
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

extern "C" {
#include "common/websocket_comm.h"
}

void websocket_message_t_destroy(websocket_message_t *message)
{
    mock().actualCall("websocket_message_t_destroy");
}

int create_websocket_context(struct lws_context *lwsc)
{
    return mock().actualCall("create_websocket_context")
        .returnIntValueOrDefault(0);
}

int send_to_websocket(uint8_t *bytes, size_t len, websocket_connection_t *websocket_conn)
{
    return mock().actualCall("send_to_websocket")
        .returnIntValueOrDefault(0);
}

void websocket_close_connection_trigger(struct websocket_connection *websocket_conn)
{
    mock().actualCall("websocket_close_connection_trigger");
}

const char *websocket_lws_callback_reason(enum lws_callback_reasons reason)
{
    return mock().actualCall("websocket_lws_callback_reason")
        .returnStringValue();
}

void websocket_set_log_emit_function(int level, const char *line)
{
    mock().actualCall("websocket_set_log_emit_function");
}

void websocket_set_log_level_and_emit_function()
{
    mock().actualCall("websocket_set_log_level_and_emit_function");
}

int websocket_add_msg_fragment(websocket_connection_t *websocket_conn, uint8_t *fragment, size_t len)
{
    return mock().actualCall("websocket_add_msg_fragment")
        .returnIntValueOrDefault(0);
}

void websocket_reset_message(websocket_connection_t *websocket_conn)
{
    mock().actualCall("websocket_reset_message");
}
