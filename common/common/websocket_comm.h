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

#ifndef INCLUDE_WEBSOCKET_COMMON_H_
#define INCLUDE_WEBSOCKET_COMMON_H_

#include "libwebsockets.h"
#include "ns_list.h"

struct connection;

typedef struct websocket_message {
    ns_list_link_t link;
    uint8_t *bytes;
    size_t len;
} websocket_message_t;

typedef NS_LIST_HEAD(websocket_message_t, link) websocket_message_list_t;

typedef struct websocket_connection {
    ns_list_link_t link;
    websocket_message_list_t *sent;
    struct lws *wsi;
    struct lws_context *lws_context;
    struct connection *conn;
    size_t msg_len;
    uint8_t *msg;
    bool to_close;
} websocket_connection_t;

typedef NS_LIST_HEAD(websocket_connection_t, link) websocket_connection_list_t;

void websocket_message_t_destroy(websocket_message_t *message);

int create_websocket_context(struct lws_context *lwsc);

int send_to_websocket(uint8_t *bytes, size_t len, websocket_connection_t *websocket_conn);

void websocket_close_connection_trigger(struct websocket_connection *websocket_conn);

const char *websocket_lws_callback_reason(enum lws_callback_reasons reason);

void websocket_set_log_emit_function(int level, const char *line);

void websocket_set_log_level_and_emit_function();

int websocket_add_msg_fragment(websocket_connection_t *websocket_conn, uint8_t *fragment, size_t len);

void websocket_reset_message(websocket_connection_t *websocket_conn);
#endif
