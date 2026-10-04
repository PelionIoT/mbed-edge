/* SPDX-License-Identifier: Apache-2.0 */
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif
#include <stdio.h>
#include <event2/http.h>
#include <event2/util.h>
#include "edge-core/listener_status.h"

bool edge_listener_http_address(struct evhttp_bound_socket *socket, char *address, size_t capacity)
{
    struct sockaddr_storage bound;
    ev_socklen_t length = sizeof(bound);
    char host[64];
    unsigned port;
    if (!socket || !address || !capacity) return false;
    address[0] = 0;
    if (getsockname(evhttp_bound_socket_get_fd(socket), (struct sockaddr *)&bound, &length)) return false;
    if (bound.ss_family == AF_INET) {
        struct sockaddr_in *v4 = (struct sockaddr_in *)&bound;
        if (!evutil_inet_ntop(AF_INET, &v4->sin_addr, host, sizeof(host))) return false;
        port = ntohs(v4->sin_port);
    } else if (bound.ss_family == AF_INET6) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&bound;
        if (!evutil_inet_ntop(AF_INET6, &v6->sin6_addr, host, sizeof(host))) return false;
        port = ntohs(v6->sin6_port);
    } else return false;
    int written = bound.ss_family == AF_INET6 ? snprintf(address, capacity, "[%s]:%u", host, port) :
                                               snprintf(address, capacity, "%s:%u", host, port);
    return written >= 0 && (size_t)written < capacity;
}
