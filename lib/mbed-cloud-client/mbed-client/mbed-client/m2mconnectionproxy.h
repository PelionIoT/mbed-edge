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
#ifndef M2M_CONNECTION_PROXY_H
#define M2M_CONNECTION_PROXY_H

#include "mbed-client/m2mconfig.h"
#include "pal.h"
#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/uio.h>
#include <unistd.h>

/**
 * The purpose of this class is to abstract the message protocol sent to/from
 * a proxy server in order to request that the proxy establish a tunnel to a
 * destination server.  The class requires an open socket already connected to
 * the proxy server, for example after a successful pal_connect(), through which
 * it sends command codes to the proxy server. Responses from the proxy server
 * must be provided to this class's receive_handler.  When the receive handler
 * returns success, the socket is considered to be connected to the destination
 * server and this class's work is complete. The socket may then be used as
 * normal to send and receive messages to/from the destination server.
 */
class  M2MConnectionProxy {

public:
    typedef enum {
        ERROR_NONE = 0,
        ERROR_GENERIC = -1,
        ERROR_SOCKET_READ = -7,
        ERROR_SOCKET_WRITE = -8,
        ERROR_UNHANDLED_PROXY_PROTOCOL = -11, // proxy server sent a message we couldn't understand
        ERROR_PROXY_AUTH_REQUIRED = -13, // http error code 407
        ERROR_BAD_GATEWAY = -14 // http error code 502
    } ProxyError;

    /**
     * @brief Constructor
     */
    M2MConnectionProxy();

    /**
     * @brief Destructor
     */
    virtual ~M2MConnectionProxy();

    /**
     * @brief calls pal_send to send the "CONNECT" command to the proxy server
     * pre-condition: socket is already connected to the proxy server, for example after successful pal_connect()
     * @param socket an open socket to the proxy server
     * @param host destination hostname
     * @param port destination port
     * @param auth_type type of authentication required by the proxy server, if any
     *     Empty string for no authentication
     *     "Basic" for https://tools.ietf.org/html/rfc7617
     *     "Bearer" for https://tools.ietf.org/html/rfc6750 section 2.1
     * @param credentials the credentials to supply to the proxy server, formatted for auth_type
     * @return ProxyError
     */
    ProxyError establish_tunnel(palSocket_t socket, String host, uint16_t port, String auth_type, String credentials);

    /**
     * @brief processes the CONNECT response received from the proxy server.
     * calls pal_recv to read "Connection established" or "200 OK", or other error response from Proxy server
     * @return: ProxyError::ERROR_NONE if the proxy server reported success and the proxy tunnel is established
     */
    ProxyError receive_handler(palSocket_t socket);

    /**
     */
    void base64_encode(char *buffer_out, int len_out, const char *buffer_in, int len_in);
};
#endif // M2M_CONNECTION_PROXY_H
