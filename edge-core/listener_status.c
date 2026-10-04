/* SPDX-License-Identifier: Apache-2.0 */
#include "edge-core/listener_status.h"

static json_t *listener_json(const edge_listener_entry *listener, const char *protocol)
{
    return json_pack("{s:b,s:b,s:b,s:s,s:s}", "available", listener->available,
        "enabled", listener->enabled, "listening", listener->listening,
        "address", listener->address ? listener->address : "", "protocol", protocol);
}

json_t *edge_listener_status_json(const edge_listener_status *state, uint64_t now_ms,
    uint32_t process_id, unsigned registered_pts, unsigned registered_devices)
{
    if (!state) return NULL;
    json_t *listeners = json_object();
    json_object_set_new(listeners, "http", listener_json(&state->http, "http"));
    json_object_set_new(listeners, "tcp", listener_json(&state->tcp, "ws"));
    json_object_set_new(listeners, "afUnix", listener_json(&state->af_unix, "ws"));
    json_t *pipe = listener_json(&state->named_pipe, "edge-pt-v1");
    json_object_set_new(pipe, "maxClients", json_integer(state->pipe_max_clients));
    json_object_set_new(pipe, "connectedClients", json_integer(state->pipe_connected_clients));
    json_object_set_new(pipe, "allowedClientSidCount", json_integer(state->pipe_client_sid_count));
    json_object_set_new(pipe, "remoteClientsAllowed", json_false());
    json_object_set_new(pipe, "maxFrameBytes", json_integer(65536));
    json_object_set_new(listeners, "namedPipe", pipe);
    return json_pack("{s:i,s:I,s:I,s:i,s:i,s:o}", "schemaVersion", 1,
        "processId", (json_int_t)process_id,
        "uptimeSeconds", (json_int_t)(now_ms >= state->started_ms ? (now_ms - state->started_ms) / 1000 : 0),
        "registeredPtCount", (int)registered_pts, "registeredDeviceCount", (int)registered_devices,
        "listeners", listeners);
}
