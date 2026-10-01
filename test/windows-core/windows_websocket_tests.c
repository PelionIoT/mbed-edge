/* SPDX-License-Identifier: Apache-2.0 */
#include <winsock2.h>
#include <windows.h>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <event2/event.h>
#include <event2/thread.h>
#include "libwebsockets.h"

#define CHECK(expression) do { if (!(expression)) { \
    fprintf(stderr, "%s:%d: %s failed (WSA=%d)\n", __FILE__, __LINE__, #expression, WSAGetLastError()); \
    exit(1); } } while (0)

struct session { unsigned char buffer[LWS_PRE + 64]; size_t length; };

static int echo(struct lws *wsi, enum lws_callback_reasons reason,
                void *user, void *input, size_t length)
{
    struct session *session = user;
    if (reason == LWS_CALLBACK_RECEIVE) {
        CHECK(length <= 64);
        memcpy(session->buffer + LWS_PRE, input, length);
        session->length = length;
        lws_callback_on_writable(wsi);
    } else if (reason == LWS_CALLBACK_SERVER_WRITEABLE && session->length) {
        CHECK(lws_write(wsi, session->buffer + LWS_PRE, session->length,
                        LWS_WRITE_TEXT) == (int)session->length);
        session->length = 0;
    }
    return 0;
}

static unsigned __stdcall dispatch(void *base)
{
    CHECK(event_base_dispatch(base) == 0);
    return 0;
}

static void receive_exact(SOCKET socket, unsigned char *buffer, int length)
{
    int received = 0;
    while (received < length) {
        int count = recv(socket, (char *)buffer + received, length - received, 0);
        CHECK(count > 0);
        received += count;
    }
}

int main(void)
{
    WSADATA startup;
    CHECK(WSAStartup(MAKEWORD(2, 2), &startup) == 0);
    CHECK(evthread_use_windows_threads() == 0);
    struct event_base *base = event_base_new();
    CHECK(base != NULL);
    void *loops[] = {base};
    struct lws_protocols protocols[] = {
        {"edge_protocol_translator", echo, sizeof(struct session), 64, 0, NULL, 0},
        {NULL, NULL, 0, 0, 0, NULL, 0}
    };
    struct lws_context_creation_info info = {0};
    info.port = 0; /* The OS chooses a free port. */
    info.iface = "127.0.0.1";
    info.protocols = protocols;
    info.options = LWS_SERVER_OPTION_LIBEVENT | LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
    info.foreign_loops = loops;
    info.gid = info.uid = -1;
    lws_set_log_level(LLL_ERR | LLL_WARN, NULL);
    struct lws_context *context = lws_create_context(&info);
    CHECK(context != NULL);
    struct lws_vhost *vhost = lws_create_vhost(context, &info);
    CHECK(vhost != NULL);
    int port = lws_get_vhost_listen_port(vhost);
    CHECK(port > 0 && port <= 65535);
    HANDLE worker = (HANDLE)_beginthreadex(NULL, 0, dispatch, base, 0, NULL);
    CHECK(worker != NULL);

    SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECK(client != INVALID_SOCKET);
    DWORD timeout = 5000;
    CHECK(setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) == 0);
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((u_short)port);
    CHECK(connect(client, (struct sockaddr *)&address, sizeof(address)) == 0);
    const char request[] = "GET /1/pt HTTP/1.1\r\nHost: localhost\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Protocol: edge_protocol_translator\r\n\r\n";
    CHECK(send(client, request, (int)sizeof(request) - 1, 0) == (int)sizeof(request) - 1);
    char header[1024] = {0};
    size_t used = 0;
    do {
        CHECK(used + 1 < sizeof(header));
        receive_exact(client, (unsigned char *)header + used++, 1);
    } while (!strstr(header, "\r\n\r\n"));
    CHECK(strstr(header, "101 Switching Protocols") != NULL);
    CHECK(strstr(header, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") != NULL);

    /* Client-to-server frames must be masked (RFC 6455). */
    unsigned char frame[] = {0x81, 0x86, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0};
    const char payload[] = "native";
    for (int i = 0; i < 6; ++i) frame[6 + i] = (unsigned char)payload[i] ^ frame[2 + i % 4];
    CHECK(send(client, (char *)frame, (int)sizeof(frame), 0) == (int)sizeof(frame));
    unsigned char response[8];
    receive_exact(client, response, sizeof(response));
    CHECK(response[0] == 0x81 && response[1] == 6);
    CHECK(memcmp(response + 2, payload, 6) == 0);
    CHECK(closesocket(client) == 0);
    CHECK(event_base_loopbreak(base) == 0);
    CHECK(WaitForSingleObject(worker, 5000) == WAIT_OBJECT_0);
    CloseHandle(worker);
    lws_context_destroy(context);
    event_base_free(base);
    CHECK(WSACleanup() == 0);
    puts("PASS native Windows libevent/WebSocket handshake, masked receive and echo");
    return 0;
}
