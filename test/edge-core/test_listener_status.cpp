// SPDX-License-Identifier: Apache-2.0
#include "CppUTest/TestHarness.h"
extern "C" {
#include "edge-core/listener_status.h"
}
TEST_GROUP(listener_status) {};

TEST(listener_status, linux_http_and_unix_socket_snapshot)
{
    edge_listener_status state = {};
    state.started_ms = 1000;
    state.http = {true, true, true, "127.0.0.1:8080"};
    state.af_unix = {true, true, true, "/tmp/edge.sock"};
    json_t *result = edge_listener_status_json(&state, 65000, 42, 2, 7);
    CHECK(result);
    LONGS_EQUAL(64, json_integer_value(json_object_get(result, "uptimeSeconds")));
    LONGS_EQUAL(2, json_integer_value(json_object_get(result, "registeredPtCount")));
    LONGS_EQUAL(7, json_integer_value(json_object_get(result, "registeredDeviceCount")));
    json_t *entries = json_object_get(result, "listeners");
    CHECK(json_is_true(json_object_get(json_object_get(entries, "afUnix"), "listening")));
    STRCMP_EQUAL("/tmp/edge.sock", json_string_value(json_object_get(json_object_get(entries, "afUnix"), "address")));
    CHECK(json_is_false(json_object_get(json_object_get(entries, "tcp"), "available")));
    CHECK(json_is_false(json_object_get(json_object_get(entries, "namedPipe"), "available")));
    json_decref(result);
}

TEST(listener_status, windows_pipe_only_and_disabled_socket_snapshot)
{
    edge_listener_status state = {};
    state.tcp = {true, false, false, "127.0.0.1:7681"};
    state.af_unix = {true, false, false, "C:/IPC/pt.sock"};
    state.named_pipe = {true, true, true, "\\\\.\\pipe\\EdgePT"};
    state.pipe_max_clients = 16; state.pipe_connected_clients = 2; state.pipe_client_sid_count = 1;
    json_t *result = edge_listener_status_json(&state, 0, 1, 2, 0);
    json_t *entries = json_object_get(result, "listeners");
    CHECK(json_is_false(json_object_get(json_object_get(entries, "tcp"), "listening")));
    json_t *pipe = json_object_get(entries, "namedPipe");
    LONGS_EQUAL(2, json_integer_value(json_object_get(pipe, "connectedClients")));
    CHECK(json_is_false(json_object_get(pipe, "remoteClientsAllowed")));
    CHECK(!json_object_get(pipe, "clientSids"));
    json_decref(result);
    POINTERS_EQUAL(NULL, edge_listener_status_json(NULL, 0, 1, 0, 0));
}
