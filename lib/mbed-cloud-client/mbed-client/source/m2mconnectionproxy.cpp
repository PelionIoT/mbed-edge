/*
 * Copyright (c) 2020-2021 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "mbed-client/m2mconnectionproxy.h"
#include "mbed-trace/mbed_trace.h"

#include <cstdio>
#include <stdlib.h>

#define TRACE_GROUP "mClt"

M2MConnectionProxy::M2MConnectionProxy()
{
}

M2MConnectionProxy::~M2MConnectionProxy()
{
}

M2MConnectionProxy::ProxyError
M2MConnectionProxy::establish_tunnel(palSocket_t socket, String host, uint16_t port, String auth_type, String credentials)
{
    int n;
    char buffer[256];

    if (host.length() == 0) {
        return ERROR_GENERIC;
    }

    tr_debug("Sending proxy CONNECT directive...\n");

    snprintf(buffer, sizeof(buffer), "CONNECT %s:%d HTTP/1.0\r\n", host.c_str(), port);
    if (credentials.length() > 0) {
        // only Basic auth is supported
        char tmp[256], proxy_auth[256];
        snprintf(tmp, sizeof(tmp), "%s", credentials.c_str());
        base64_encode(proxy_auth, sizeof(proxy_auth), tmp, strlen(tmp));
        snprintf(buffer + strlen(buffer), sizeof(buffer) - strlen(buffer), "Proxy-Authorization: Basic %s\r\n", proxy_auth);
    }
    strcat(buffer, "\r\n");

    size_t sentDataSize;
    n = pal_send(socket, buffer, strlen(buffer), &sentDataSize);
    if (n != PAL_SUCCESS) {
        tr_error("ERROR writing to socket: %d", n);
        return ERROR_SOCKET_WRITE;
    }

    return ERROR_NONE;
}

M2MConnectionProxy::ProxyError M2MConnectionProxy::receive_handler(palSocket_t socket)
{
    size_t n;
    char buffer[256];
    palStatus_t rt;

    memset(buffer, 0, sizeof(buffer));

    // receive answer from proxy
    rt = pal_recv(socket, buffer, sizeof(buffer) - 1, &n);
    if (rt != PAL_SUCCESS) {
        tr_error("ERROR reading from socket: %d", rt - PAL_ERR_SOCKET_ERROR_BASE);
        return ERROR_SOCKET_READ;
    }

    int http_ver, http_code;
    sscanf(buffer, "HTTP/1.%d %d", &http_ver, &http_code);
// possible proxy answers:
//  HTTP/1.0 500 Unable to connect
//  HTTP/1.0 407 Proxy Authentication Required
//  HTTP/1.0 401 Unauthorized
//  HTTP/1.0 200 Connection established
    if (http_code != 200) {
        tr_error("Failed to connect to proxy: HTTP %d", http_code);
        return ERROR_GENERIC;
    }

    tr_info("Proxy response: HTTP/1.%d %d", http_ver, http_code);

// TODO: read until \n\n
// tr_debug("%s\n",buffer);

    return ERROR_NONE;
}

// buffer_out length needs to be at least 4/3*len(buffer_in)
void M2MConnectionProxy::base64_encode(char *buffer_out, int len_out, const char *buffer_in, int len_in)
{
    unsigned int val = 0;
    int i_in, i_out = 0, bits = -6;
    const char *charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    memset(buffer_out, 0, len_out);
    for (i_in = 0; i_in < len_in; i_in++) {
        val = (val << 8) + buffer_in[i_in];
        bits += 8;
        while (bits >= 0) {
            buffer_out[i_out++] = charset[(val >> bits) & 0x3F];
            bits -= 6;
        }
    }
    if (bits > -6)
        buffer_out[i_out++] = charset[((val << 8) >> (bits + 8)) & 0x3F];
    while (i_out % 4) buffer_out[i_out++] = '=';
}
