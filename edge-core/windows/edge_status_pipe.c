/* SPDX-License-Identifier: Apache-2.0 */
#include <windows.h>
#include <sddl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <event2/event.h>
#include "edge_status_pipe.h"

#define STATUS_CLIENT_ACCESS ((FILE_GENERIC_READ | FILE_GENERIC_WRITE) & ~FILE_CREATE_PIPE_INSTANCE)
#define STATUS_MAX_JSON 65536u
#define STATUS_CLIENTS 4u
#define STATUS_TIMEOUT_MS 5000u

typedef enum { accepting, connected, writing, awaiting_ack } status_state;

struct status_peer {
    HANDLE pipe;
    OVERLAPPED operation;
    status_state state;
    bool pending;
    ULONGLONG deadline;
    unsigned char *reply;
    DWORD reply_length;
    unsigned char ack;
};

struct edge_status_pipe {
    struct event *poll;
    struct status_peer peers[STATUS_CLIENTS];
    unsigned count;
    edge_status_snapshot_fn snapshot;
    void *context;
};

bool edge_status_public_uri(const char *uri, char *result, size_t capacity)
{
    if (!result || !capacity) return false;
    result[0] = '\0';
    if (!uri) return false;
    const char *scheme_end = strstr(uri, "://");
    if (!scheme_end || scheme_end == uri) return false;
    for (const char *part = uri; part < scheme_end; ++part) {
        char c = *part;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (part != uri && ((c >= '0' && c <= '9') || c == '+' || c == '.' || c == '-'))))
            return false;
    }
    const char *authority = scheme_end + 3;
    const char *end = authority + strcspn(authority, "/?#");
    const char *host = authority;
    for (const char *part = authority; part < end; ++part) {
        if (*part == '@') host = part + 1;
    }
    size_t prefix = (size_t)(authority - uri);
    size_t host_length = (size_t)(end - host);
    if (!host_length || prefix + host_length >= capacity) return false;
    memcpy(result, uri, prefix);
    memcpy(result + prefix, host, host_length);
    result[prefix + host_length] = '\0';
    return true;
}

static void *token_information(HANDLE token, TOKEN_INFORMATION_CLASS kind)
{
    DWORD size = 0;
    GetTokenInformation(token, kind, NULL, 0, &size);
    void *value = size ? malloc(size) : NULL;
    if (value && !GetTokenInformation(token, kind, value, size, &size)) {
        free(value);
        value = NULL;
    }
    return value;
}

static PSECURITY_DESCRIPTOR status_security(void)
{
    HANDLE token = NULL;
    TOKEN_USER *user = NULL;
    TOKEN_GROUPS *groups = NULL;
    wchar_t *server_text = NULL;
    PSECURITY_DESCRIPTOR security = NULL;
    wchar_t sddl[512];
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) goto done;
    user = token_information(token, TokenUser);
    groups = token_information(token, TokenGroups);
    if (!user || !groups) goto done;
    PSID server = user->User.Sid;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    for (DWORD i = 0; i < groups->GroupCount; ++i) {
        PSID sid = groups->Groups[i].Sid;
        if ((groups->Groups[i].Attributes & SE_GROUP_ENABLED) &&
            *GetSidSubAuthorityCount(sid) == 6 && *GetSidSubAuthority(sid, 0) == 80 &&
            !memcmp(GetSidIdentifierAuthority(sid), &nt, sizeof(nt))) {
            server = sid;
            break;
        }
    }
    if (!ConvertSidToStringSidW(server, &server_text)) goto done;
    /* Interactive users can read status, but cannot create another instance.
     * Restricted LocalService needs its actual service SID for server access. */
    if (swprintf_s(sddl, sizeof(sddl) / sizeof(*sddl),
        L"D:P(A;;RC;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;%ls)(A;;0x%08lx;;;IU)",
        server_text, (DWORD)STATUS_CLIENT_ACCESS) < 0) goto done;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1,
                                                               &security, NULL)) security = NULL;
done:
    LocalFree(server_text);
    free(groups);
    free(user);
    if (token) CloseHandle(token);
    return security;
}

static void prepare_operation(struct status_peer *peer)
{
    HANDLE event = peer->operation.hEvent;
    memset(&peer->operation, 0, sizeof(peer->operation));
    peer->operation.hEvent = event;
    ResetEvent(event);
    peer->pending = false;
}

static bool arm_accept(struct status_peer *peer)
{
    prepare_operation(peer);
    peer->state = accepting;
    peer->deadline = 0;
    if (ConnectNamedPipe(peer->pipe, &peer->operation) || GetLastError() == ERROR_PIPE_CONNECTED) {
        peer->state = connected;
        peer->deadline = GetTickCount64() + STATUS_TIMEOUT_MS;
        return true;
    }
    if (GetLastError() == ERROR_IO_PENDING) {
        peer->pending = true;
        return true;
    }
    return false;
}

static void reset_peer(struct status_peer *peer, bool reuse)
{
    if (peer->pending) {
        DWORD transferred;
        CancelIoEx(peer->pipe, &peer->operation);
        GetOverlappedResult(peer->pipe, &peer->operation, &transferred, TRUE);
        peer->pending = false;
    }
    free(peer->reply);
    peer->reply = NULL;
    peer->reply_length = 0;
    if (peer->pipe != INVALID_HANDLE_VALUE) DisconnectNamedPipe(peer->pipe);
    if (reuse && !arm_accept(peer)) {
        fprintf(stderr, "Status pipe accept rearm failed: %lu\n", GetLastError());
        peer->state = accepting;
    }
}

static bool send_snapshot(struct edge_status_pipe *listener, struct status_peer *peer)
{
    char *json = listener->snapshot(listener->context);
    if (!json) return false;
    size_t length = strlen(json);
    if (!length || length > STATUS_MAX_JSON) { free(json); return false; }
    peer->reply = malloc(length + 4);
    if (!peer->reply) { free(json); return false; }
    peer->reply_length = (DWORD)length + 4;
    peer->reply[0] = (unsigned char)(length >> 24);
    peer->reply[1] = (unsigned char)(length >> 16);
    peer->reply[2] = (unsigned char)(length >> 8);
    peer->reply[3] = (unsigned char)length;
    memcpy(peer->reply + 4, json, length);
    free(json);
    prepare_operation(peer);
    peer->state = writing;
    DWORD written = 0;
    if (WriteFile(peer->pipe, peer->reply, peer->reply_length, &written, &peer->operation))
        return written == peer->reply_length;
    if (GetLastError() == ERROR_IO_PENDING) { peer->pending = true; return true; }
    return false;
}

static bool arm_ack(struct status_peer *peer)
{
    free(peer->reply);
    peer->reply = NULL;
    peer->reply_length = 0;
    peer->ack = 0;
    prepare_operation(peer);
    peer->state = awaiting_ack;
    DWORD received = 0;
    /* A synchronous acknowledgement is already complete; caller rearms. */
    if (ReadFile(peer->pipe, &peer->ack, 1, &received, &peer->operation))
        return false;
    if (GetLastError() == ERROR_IO_PENDING) { peer->pending = true; return true; }
    return false;
}

static void poll_peers(evutil_socket_t fd, short events, void *context)
{
    (void)fd; (void)events;
    struct edge_status_pipe *listener = context;
    ULONGLONG now = GetTickCount64();
    for (unsigned i = 0; i < listener->count; ++i) {
        struct status_peer *peer = &listener->peers[i];
        if (peer->state != accepting && now >= peer->deadline) { reset_peer(peer, true); continue; }
        if (peer->pending) {
            DWORD transferred = 0;
            if (!GetOverlappedResult(peer->pipe, &peer->operation, &transferred, FALSE)) {
                if (GetLastError() == ERROR_IO_INCOMPLETE) continue;
                peer->pending = false;
                reset_peer(peer, true);
                continue;
            }
            peer->pending = false;
            if (peer->state == accepting) {
                peer->state = connected;
                peer->deadline = now + STATUS_TIMEOUT_MS;
            } else if (peer->state == writing) {
                if (transferred != peer->reply_length || !arm_ack(peer)) reset_peer(peer, true);
                continue;
            } else {
                reset_peer(peer, true);
                continue;
            }
        }
        if (peer->state == connected) {
            if (!send_snapshot(listener, peer)) reset_peer(peer, true);
            else if (!peer->pending && !arm_ack(peer)) reset_peer(peer, true);
        }
    }
}

void edge_status_pipe_stop(struct edge_status_pipe *listener)
{
    if (!listener) return;
    if (listener->poll) event_free(listener->poll);
    for (unsigned i = 0; i < listener->count; ++i) {
        struct status_peer *peer = &listener->peers[i];
        reset_peer(peer, false);
        if (peer->pipe != INVALID_HANDLE_VALUE) CloseHandle(peer->pipe);
        if (peer->operation.hEvent) CloseHandle(peer->operation.hEvent);
    }
    free(listener);
}

struct edge_status_pipe *edge_status_pipe_start(struct event_base *base,
    edge_status_snapshot_fn snapshot, void *context)
{
    if (!base || !snapshot) return NULL;
    PSECURITY_DESCRIPTOR security = status_security();
    if (!security) return NULL;
    SECURITY_ATTRIBUTES attributes = {sizeof(attributes), security, FALSE};
    struct edge_status_pipe *listener = calloc(1, sizeof(*listener));
    if (!listener) { LocalFree(security); return NULL; }
    listener->snapshot = snapshot;
    listener->context = context;
    for (unsigned i = 0; i < STATUS_CLIENTS; ++i) {
        struct status_peer *peer = &listener->peers[i];
        peer->pipe = INVALID_HANDLE_VALUE;
        ++listener->count;
        peer->operation.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!peer->operation.hEvent) goto fail;
        peer->pipe = CreateNamedPipeW(EDGE_STATUS_PIPE_NAME_W,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | (i == 0 ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0),
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            STATUS_CLIENTS, 4096, 4096, 1000, &attributes);
        if (peer->pipe == INVALID_HANDLE_VALUE) goto fail;
        if (!arm_accept(peer)) goto fail;
    }
    listener->poll = event_new(base, -1, EV_PERSIST, poll_peers, listener);
    const struct timeval interval = {0, 20000};
    if (!listener->poll || event_add(listener->poll, &interval)) goto fail;
    LocalFree(security);
    return listener;
fail:
    fprintf(stderr, "Status pipe initialization failed: %lu\n", GetLastError());
    LocalFree(security);
    edge_status_pipe_stop(listener);
    return NULL;
}
