/* SPDX-License-Identifier: Apache-2.0 */
#include <winsock2.h>
#include <windows.h>
#include <event2/event.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../edge-core/windows/edge_status_pipe.h"

static char *snapshot(void *context)
{
    (void)context;
    const char body[] = "{\"status\":\"connecting\"}";
    char *copy = malloc(sizeof(body));
    if (copy) memcpy(copy, body, sizeof(body));
    return copy;
}

struct loop_context { struct event_base *base; volatile LONG stop; };

static DWORD WINAPI run_loop(void *context)
{
    struct loop_context *loop = context;
    while (!InterlockedCompareExchange(&loop->stop, 0, 0)) {
        event_base_loop(loop->base, EVLOOP_NONBLOCK);
        Sleep(5);
    }
    return 0;
}

static int read_all(HANDLE pipe, unsigned char *bytes, DWORD length)
{
    DWORD used = 0;
    while (used < length) {
        DWORD count = 0;
        if (!ReadFile(pipe, bytes + used, length - used, &count, NULL) || !count) return 0;
        used += count;
    }
    return 1;
}

int main(void)
{
    char public_uri[128];
    if (!edge_status_public_uri("coaps+tcp://user:secret@cloud.example:5684/path?token=x#frag",
                                public_uri, sizeof(public_uri)) ||
        strcmp(public_uri, "coaps+tcp://cloud.example:5684")) return 1;
    if (edge_status_public_uri("invalid-uri", public_uri, sizeof(public_uri)) || public_uri[0]) return 1;
    int ok = 0;
    const char *stage = "setup";
    WSADATA winsock;
    if (WSAStartup(MAKEWORD(2, 2), &winsock)) return 1;
    HANDLE thread = NULL;
    HANDLE client = INVALID_HANDLE_VALUE;
    struct event_base *base = event_base_new();
    struct loop_context loop = {base, 0};
    struct edge_status_pipe *server = base ? edge_status_pipe_start(base, snapshot, NULL) : NULL;
    if (!server) goto done;
    stage = "duplicate";
    struct edge_status_pipe *duplicate = edge_status_pipe_start(base, snapshot, NULL);
    if (duplicate) { edge_status_pipe_stop(duplicate); goto done; } /* first-instance protection */
    thread = CreateThread(NULL, 0, run_loop, &loop, 0, NULL);
    stage = "thread";
    if (!thread) goto done;
    stage = "wait";
    if (!WaitNamedPipeW(EDGE_STATUS_PIPE_NAME_W, 3000)) goto done;
    stage = "open";
    client = CreateFileW(EDGE_STATUS_PIPE_NAME_W,
        (FILE_GENERIC_READ | FILE_GENERIC_WRITE) & ~FILE_CREATE_PIPE_INSTANCE,
        0, NULL, OPEN_EXISTING, 0, NULL);
    if (client == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Status pipe client open failed: %lu\n", GetLastError());
        goto done;
    }
    stage = "pid";
    ULONG server_pid = 0;
    if (!GetNamedPipeServerProcessId(client, &server_pid) || server_pid != GetCurrentProcessId()) goto done;
    unsigned char header[4];
    stage = "header";
    if (!read_all(client, header, sizeof(header))) goto done;
    uint32_t length = ((uint32_t)header[0] << 24) | ((uint32_t)header[1] << 16) |
                      ((uint32_t)header[2] << 8) | header[3];
    if (length != strlen("{\"status\":\"connecting\"}")) goto done;
    unsigned char body[64] = {0};
    stage = "body";
    if (!read_all(client, body, length) || strcmp((char *)body, "{\"status\":\"connecting\"}")) goto done;
    unsigned char ack = 6;
    DWORD written = 0;
    stage = "ack";
    if (!WriteFile(client, &ack, 1, &written, NULL) || written != 1) goto done;
    ok = 1;
done:
    if (client != INVALID_HANDLE_VALUE) CloseHandle(client);
    InterlockedExchange(&loop.stop, 1);
    if (thread) { WaitForSingleObject(thread, 3000); CloseHandle(thread); }
    edge_status_pipe_stop(server);
    if (base) event_base_free(base);
    if (!ok) fprintf(stderr, "Windows status pipe failed at %s: %lu\n", stage, GetLastError());
    WSACleanup();
    return ok ? 0 : 1;
}
