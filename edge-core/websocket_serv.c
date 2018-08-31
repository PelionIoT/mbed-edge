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

#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "libwebsockets.h"
#include "common/websocket_comm.h"
#include "edge-core/websocket_serv.h"
#include "ns_list.h"
#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP "webs"

websocket_connection_t *websocket_server_connection_initialize(websocket_connection_t *websocket_connection)
{
    websocket_message_list_t* sent =
        (websocket_message_list_t*) malloc(sizeof(websocket_message_list_t));
    if (!sent) {
        tr_err("Could not allocate sent or received websocket message list.");
        free(sent);
        free(websocket_connection);
        return NULL;
    }

    ns_list_init(sent);
    websocket_connection->to_close = false;
    websocket_connection->sent = sent;
    websocket_connection->msg_len = 0;
    websocket_connection->msg = NULL;
    return websocket_connection;
}

void websocket_server_connection_destroy(websocket_connection_t *wct)
{
    if (wct) {
        ns_list_foreach_safe(websocket_message_t, cur, wct->sent) {
            free(cur->bytes);
            ns_list_remove(wct->sent, cur);
            free(cur);
        }
        free(wct->sent);
    }
}

