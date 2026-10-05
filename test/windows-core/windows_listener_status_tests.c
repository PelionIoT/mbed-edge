/* SPDX-License-Identifier: Apache-2.0 */
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <event2/event.h>
#include <event2/http.h>
#include "edge-core/listener_status.h"
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "Listener status line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
int main(void)
{
    WSADATA startup; CHECK(WSAStartup(MAKEWORD(2,2), &startup) == 0);
    struct event_base *base = event_base_new(); CHECK(base);
    struct evhttp *http = evhttp_new(base); CHECK(http);
    struct evhttp_bound_socket *bound = evhttp_bind_socket_with_handle(http, "127.0.0.1", 0); CHECK(bound);
    char address[96]; CHECK(edge_listener_http_address(bound, address, sizeof(address)));
    CHECK(!strncmp(address, "127.0.0.1:", 10) && atoi(address + 10) > 0);
    edge_listener_status state = {0}; state.started_ms = 1000;
    state.http = (edge_listener_entry){true, true, true, address};
    state.af_unix = (edge_listener_entry){true, true, true, "/tmp/edge.sock"};
    json_t *result = edge_listener_status_json(&state, 65000, 42, 2, 7); CHECK(result);
    CHECK(json_integer_value(json_object_get(result, "uptimeSeconds")) == 64);
    json_t *entries = json_object_get(result, "listeners");
    CHECK(!strcmp(json_string_value(json_object_get(json_object_get(entries, "http"), "address")), address));
    CHECK(json_is_false(json_object_get(json_object_get(entries, "namedPipe"), "available")));
    CHECK(json_is_false(json_object_get(json_object_get(entries, "statusPipe"), "available")));
    CHECK(json_is_true(json_object_get(json_object_get(entries, "afUnix"), "listening")));
    json_decref(result);
    state.tcp = (edge_listener_entry){true, false, false, "127.0.0.1:7681"};
    state.named_pipe = (edge_listener_entry){true, true, true, "\\\\.\\pipe\\EdgePT"};
    state.status_pipe = (edge_listener_entry){true, true, true, "\\\\.\\pipe\\IzumaEdgeCoreStatus"};
    state.pipe_max_clients = 16; state.pipe_connected_clients = 2; state.pipe_client_sid_count = 1;
    result = edge_listener_status_json(&state, 0, 1, 2, 0); CHECK(result);
    entries = json_object_get(result, "listeners");
    CHECK(json_is_false(json_object_get(json_object_get(entries, "tcp"), "listening")));
    CHECK(json_is_true(json_object_get(json_object_get(entries, "statusPipe"), "listening")));
    json_t *pipe = json_object_get(entries, "namedPipe");
    CHECK(json_integer_value(json_object_get(pipe, "connectedClients")) == 2);
    CHECK(json_is_false(json_object_get(pipe, "remoteClientsAllowed")) && !json_object_get(pipe, "clientSids"));
    CHECK(json_integer_value(json_object_get(result, "uptimeSeconds")) == 0);
    json_decref(result);
    evhttp_free(http); event_base_free(base); WSACleanup();
    puts("PASS bound HTTP address/ephemeral port, Linux and Windows listener snapshots, TCP disable and pipe counts");
    return 0;
}
