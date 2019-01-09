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
#include "ns_list.h"
#include "mbed-trace/mbed_trace.h"
#include <string.h>
#define TRACE_GROUP "webs"

typedef struct {
    enum lws_callback_reasons reason;
    const char *desc;
} lws_callback_reason_desc;

typedef struct {
    enum lws_log_levels lws_level;
    uint32_t mbed_level;
} lws_to_mbed;

static lws_to_mbed trace_conversion[] = {{LLL_ERR, TRACE_LEVEL_ERROR},
                                         {LLL_WARN, TRACE_LEVEL_WARN},
                                         {LLL_NOTICE, TRACE_LEVEL_CMD},
                                         {LLL_INFO, TRACE_LEVEL_INFO},
                                         {LLL_DEBUG, TRACE_LEVEL_DEBUG},
                                         {0, 0}};

lws_callback_reason_desc lws_reason_descriptions[] =
        {{LWS_CALLBACK_ESTABLISHED, "LWS_CALLBACK_ESTABLISHED"},
         {LWS_CALLBACK_CLIENT_CONNECTION_ERROR, "LWS_CALLBACK_CLIENT_CONNECTION_ERROR"},
         {LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH, "LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH"},
         {LWS_CALLBACK_CLIENT_ESTABLISHED, "LWS_CALLBACK_CLIENT_ESTABLISHED"},
         {LWS_CALLBACK_CLOSED, "LWS_CALLBACK_CLOSED"},
         {LWS_CALLBACK_CLOSED_HTTP, "LWS_CALLBACK_CLOSED_HTTP"},
         {LWS_CALLBACK_RECEIVE, "LWS_CALLBACK_RECEIVE"},
         {LWS_CALLBACK_RECEIVE_PONG, "LWS_CALLBACK_RECEIVE_PONG"},
         {LWS_CALLBACK_CLIENT_RECEIVE, "LWS_CALLBACK_CLIENT_RECEIVE"},
         {LWS_CALLBACK_CLIENT_RECEIVE_PONG, "LWS_CALLBACK_CLIENT_RECEIVE_PONG"},
         {LWS_CALLBACK_CLIENT_WRITEABLE, "LWS_CALLBACK_CLIENT_WRITEABLE"},
         {LWS_CALLBACK_SERVER_WRITEABLE, "LWS_CALLBACK_SERVER_WRITEABLE"},
         {LWS_CALLBACK_HTTP, "LWS_CALLBACK_HTTP"},
         {LWS_CALLBACK_HTTP_BODY, "LWS_CALLBACK_HTTP_BODY"},
         {LWS_CALLBACK_HTTP_BODY_COMPLETION, "LWS_CALLBACK_HTTP_BODY_COMPLETION"},
         {LWS_CALLBACK_HTTP_FILE_COMPLETION, "LWS_CALLBACK_HTTP_FILE_COMPLETION"},
         {LWS_CALLBACK_HTTP_WRITEABLE, "LWS_CALLBACK_HTTP_WRITEABLE"},
         {LWS_CALLBACK_FILTER_NETWORK_CONNECTION, "LWS_CALLBACK_FILTER_NETWORK_CONNECTION"},
         {LWS_CALLBACK_FILTER_HTTP_CONNECTION, "LWS_CALLBACK_FILTER_HTTP_CONNECTION"},
         {LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED, "LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED"},
         {LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION, "LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION"},
         {LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS, "LWS_CALLBACK_OPENSSL_LOAD_EXTRA_CLIENT_VERIFY_CERTS"},
         {LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS, "LWS_CALLBACK_OPENSSL_LOAD_EXTRA_SERVER_VERIFY_CERTS"},
         {LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION,
          "LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION"},
         {LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER, "LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER"},
         {LWS_CALLBACK_CONFIRM_EXTENSION_OKAY, "LWS_CALLBACK_CONFIRM_EXTENSION_OKAY"},
         {LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED, "LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED"},
         {LWS_CALLBACK_PROTOCOL_INIT, "LWS_CALLBACK_PROTOCOL_INIT"},
         {LWS_CALLBACK_PROTOCOL_DESTROY, "LWS_CALLBACK_PROTOCOL_DESTROY"},
         {LWS_CALLBACK_WSI_CREATE, "LWS_CALLBACK_WSI_CREATE"},
         {LWS_CALLBACK_WSI_DESTROY, "LWS_CALLBACK_WSI_DESTROY"},
         {LWS_CALLBACK_GET_THREAD_ID, "LWS_CALLBACK_GET_THREAD_ID"},
         {LWS_CALLBACK_ADD_POLL_FD, "LWS_CALLBACK_ADD_POLL_FD"},
         {LWS_CALLBACK_DEL_POLL_FD, "LWS_CALLBACK_DEL_POLL_FD"},
         {LWS_CALLBACK_CHANGE_MODE_POLL_FD, "LWS_CALLBACK_CHANGE_MODE_POLL_FD"},
         {LWS_CALLBACK_LOCK_POLL, "LWS_CALLBACK_LOCK_POLL"},
         {LWS_CALLBACK_UNLOCK_POLL, "LWS_CALLBACK_UNLOCK_POLL"},
         {LWS_CALLBACK_OPENSSL_CONTEXT_REQUIRES_PRIVATE_KEY, "LWS_CALLBACK_OPENSSL_CONTEXT_REQUIRES_PRIVATE_KEY"},
         {LWS_CALLBACK_WS_PEER_INITIATED_CLOSE, "LWS_CALLBACK_WS_PEER_INITIATED_CLOSE"},
         {LWS_CALLBACK_WS_EXT_DEFAULTS, "LWS_CALLBACK_WS_EXT_DEFAULTS"},
         {LWS_CALLBACK_CGI, "LWS_CALLBACK_CGI"},
         {LWS_CALLBACK_CGI_TERMINATED, "LWS_CALLBACK_CGI_TERMINATED"},
         {LWS_CALLBACK_CGI_STDIN_DATA, "LWS_CALLBACK_CGI_STDIN_DATA"},
         {LWS_CALLBACK_CGI_STDIN_COMPLETED, "LWS_CALLBACK_CGI_STDIN_COMPLETED"},
         {LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP, "LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP"},
         {LWS_CALLBACK_CLOSED_CLIENT_HTTP, "LWS_CALLBACK_CLOSED_CLIENT_HTTP"},
         {LWS_CALLBACK_RECEIVE_CLIENT_HTTP, "LWS_CALLBACK_RECEIVE_CLIENT_HTTP"},
         {LWS_CALLBACK_COMPLETED_CLIENT_HTTP, "LWS_CALLBACK_COMPLETED_CLIENT_HTTP"},
         {LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ, "LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ"},
         {LWS_CALLBACK_HTTP_BIND_PROTOCOL, "LWS_CALLBACK_HTTP_BIND_PROTOCOL"},
         {LWS_CALLBACK_HTTP_DROP_PROTOCOL, "LWS_CALLBACK_HTTP_DROP_PROTOCOL"},
         {LWS_CALLBACK_CHECK_ACCESS_RIGHTS, "LWS_CALLBACK_CHECK_ACCESS_RIGHTS"},
         {LWS_CALLBACK_PROCESS_HTML, "LWS_CALLBACK_PROCESS_HTML"},
         {LWS_CALLBACK_ADD_HEADERS, "LWS_CALLBACK_ADD_HEADERS"},
         {LWS_CALLBACK_SESSION_INFO, "LWS_CALLBACK_SESSION_INFO"},
         {LWS_CALLBACK_GS_EVENT, "LWS_CALLBACK_GS_EVENT"},
         {LWS_CALLBACK_HTTP_PMO, "LWS_CALLBACK_HTTP_PMO"},
         {LWS_CALLBACK_CLIENT_HTTP_WRITEABLE, "LWS_CALLBACK_CLIENT_HTTP_WRITEABLE"},
         {LWS_CALLBACK_OPENSSL_PERFORM_SERVER_CERT_VERIFICATION,
          "LWS_CALLBACK_OPENSSL_PERFORM_SERVER_CERT_VERIFICATION"},
         {LWS_CALLBACK_RAW_RX, "LWS_CALLBACK_RAW_RX"},
         {LWS_CALLBACK_RAW_CLOSE, "LWS_CALLBACK_RAW_CLOSE"},
         {LWS_CALLBACK_RAW_WRITEABLE, "LWS_CALLBACK_RAW_WRITEABLE"},
         {LWS_CALLBACK_RAW_ADOPT, "LWS_CALLBACK_RAW_ADOPT"},
         {LWS_CALLBACK_RAW_ADOPT_FILE, "LWS_CALLBACK_RAW_ADOPT_FILE"},
         {LWS_CALLBACK_RAW_RX_FILE, "LWS_CALLBACK_RAW_RX_FILE"},
         {LWS_CALLBACK_RAW_WRITEABLE_FILE, "LWS_CALLBACK_RAW_WRITEABLE_FILE"},
         {LWS_CALLBACK_RAW_CLOSE_FILE, "LWS_CALLBACK_RAW_CLOSE_FILE"},
         {LWS_CALLBACK_SSL_INFO, "LWS_CALLBACK_SSL_INFO"},
         {LWS_CALLBACK_CHILD_WRITE_VIA_PARENT, "LWS_CALLBACK_CHILD_WRITE_VIA_PARENT"},
         {LWS_CALLBACK_CHILD_CLOSING, "LWS_CALLBACK_CHILD_CLOSING"},
         {LWS_CALLBACK_CGI_PROCESS_ATTACH, "LWS_CALLBACK_CGI_PROCESS_ATTACH"},
         {LWS_CALLBACK_USER, "LWS_CALLBACK_USER"},
         {0, NULL}};

void websocket_message_t_destroy(websocket_message_t *message)
{
    free(message->bytes);
    free(message);
}

/**
 * \brief send passed data to websocket connection and writes to socket.
 * Note: Guard the call to this function by checking that the connection is available.
 */
int send_to_websocket(uint8_t *bytes, size_t len, websocket_connection_t *websocket_conn)
{
    websocket_message_t *message = (websocket_message_t *) calloc(1, sizeof(websocket_message_t));
    message->bytes = bytes;
    message->len = len;
    ns_list_add_to_end(websocket_conn->sent, message);
    int ret = lws_callback_on_writable(websocket_conn->wsi);
    if (1 != ret) {
        tr_err("lws_callback_on_writable returned %d", ret);
        return -1;
    }
    return 0;
}

void websocket_close_connection_trigger(websocket_connection_t *websocket_conn)
{
    websocket_conn->to_close = true;
    lws_callback_on_writable(websocket_conn->wsi);
}

const char *websocket_lws_callback_reason(enum lws_callback_reasons reason)
{
    int32_t i = 0;
    while (lws_reason_descriptions[i].desc != NULL) {
        if (lws_reason_descriptions[i].reason == reason) {
            return lws_reason_descriptions[i].desc;
        }
        i++;
    }
    return NULL;
}

void websocket_set_log_emit_function(int level, const char *line)
{
    int32_t i = 0;

    while (trace_conversion[i].mbed_level != 0) {
        if (trace_conversion[i].lws_level == level) {
            // libwebsocket log line contains \n, remove it.
            char *c = (char *) line;
            while (*c && *c != '\n' && *c != '\r') {
                c++;
            }
            *c = 0;
            mbed_tracef(trace_conversion[i].mbed_level, "lws", "%s", line);
            break;
        }
        i++;
    }
}

void websocket_set_log_level_and_emit_function()
{
    int level = 0;
#if MBED_TRACE_MAX_LEVEL >= TRACE_LEVEL_DEBUG
    level |= LLL_DEBUG;
#endif
#if MBED_TRACE_MAX_LEVEL >= TRACE_LEVEL_INFO
    level |= LLL_INFO;
#endif
#if MBED_TRACE_MAX_LEVEL >= TRACE_LEVEL_WARN
    level |= LLL_WARN | LLL_NOTICE;
#endif
#if MBED_TRACE_MAX_LEVEL >= TRACE_LEVEL_ERROR
    level |= LLL_ERR;
#endif

    lws_set_log_level(level, websocket_set_log_emit_function);
}

int websocket_add_msg_fragment(websocket_connection_t *websocket_conn, uint8_t *fragment, size_t len)
{
    uint8_t *msg;
    if (!websocket_conn->msg) {
        msg = malloc(len);
    } else {
        msg = realloc(websocket_conn->msg, websocket_conn->msg_len + len);
    }

    if (!msg) {
        tr_err("Could not malloc/realloc memory for fragmented message.");
        free(websocket_conn->msg);
        return 1;
    }
    memcpy(msg + websocket_conn->msg_len, fragment, len);
    websocket_conn->msg = msg;
    websocket_conn->msg_len += len;
    return 0;
}

void websocket_reset_message(websocket_connection_t *websocket_conn)
{
    free(websocket_conn->msg);
    websocket_conn->msg = NULL;
    websocket_conn->msg_len = 0;
}
