/* SPDX-License-Identifier: Apache-2.0 */
#include <winsock2.h>
#include <windows.h>
#include <sddl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <event2/event.h>
#include <jansson.h>
#include "edge_pt_pipe.h"

#define PIPE_CLIENT_ACCESS ((FILE_GENERIC_READ | FILE_GENERIC_WRITE) & ~FILE_CREATE_PIPE_INSTANCE)
#define PIPE_QUEUE_BYTES (4u * EDGE_PT_PIPE_MAX_FRAME)
#define PIPE_QUEUE_FRAMES 32u
#define PIPE_IO_TIMEOUT_MS 5000u

struct pipe_frame {
    struct pipe_frame *next;
    DWORD length, offset;
    unsigned char *bytes;
};

struct edge_pt_pipe_connection {
    struct edge_pt_pipe_listener *listener;
    HANDLE pipe;
    OVERLAPPED accept, read, write;
    bool accept_pending, read_pending, write_pending, connected, closing;
    void *session;
    unsigned char header[4];
    DWORD header_used, body_length, body_used;
    char *body;
    struct pipe_frame *head, *tail;
    unsigned queue_frames;
    size_t queue_bytes;
    ULONGLONG connected_at, read_deadline, write_deadline, close_deadline;
};

struct edge_pt_pipe_listener {
    struct event *poll;
    struct edge_pt_pipe_connection *peers;
    unsigned count, next_peer;
    bool stopping;
    edge_pt_pipe_callbacks callbacks;
    void *context;
};

static void *token_information(HANDLE token, TOKEN_INFORMATION_CLASS kind)
{
    DWORD size = 0;
    GetTokenInformation(token, kind, NULL, 0, &size);
    void *information = size ? malloc(size) : NULL;
    if (information && !GetTokenInformation(token, kind, information, size, &size)) {
        free(information);
        information = NULL;
    }
    return information;
}

static PSECURITY_DESCRIPTOR pipe_security(const edge_runtime_config *config)
{
    HANDLE token = NULL;
    TOKEN_USER *user = NULL;
    TOKEN_GROUPS *groups = NULL;
    wchar_t *server_text = NULL, *sddl = NULL;
    PSECURITY_DESCRIPTOR security = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) goto done;
    user = token_information(token, TokenUser);
    groups = token_information(token, TokenGroups);
    if (!user || !groups) goto done;
    PSID server = user->User.Sid;
    /* A restricted service needs its actual S-1-5-80 service SID in both ACL
     * checks. Do not give every process running as LocalService full control. */
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
    sddl = calloc(8192, sizeof(*sddl));
    if (!sddl || swprintf_s(sddl, 8192, L"D:P(A;;RC;;;OW)(A;;FA;;;%ls)", server_text) < 0) goto done;
    for (unsigned i = 0; i < config->named_pipe_client_sid_count; ++i) {
        wchar_t sid[EDGE_PIPE_SID_CAPACITY], ace[EDGE_PIPE_SID_CAPACITY + 40];
        PSID parsed = NULL;
        if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, config->named_pipe_client_sids[i], -1,
                                 sid, EDGE_PIPE_SID_CAPACITY) || !ConvertStringSidToSidW(sid, &parsed)) goto done;
        LocalFree(parsed);
        if (swprintf_s(ace, sizeof(ace) / sizeof(*ace), L"(A;;0x%08lx;;;%ls)", (DWORD)PIPE_CLIENT_ACCESS, sid) < 0 ||
            wcscat_s(sddl, 8192, ace)) goto done;
    }
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &security, NULL)) security = NULL;
done:
    LocalFree(server_text);
    free(sddl); free(groups); free(user);
    if (token) CloseHandle(token);
    return security;
}

static void prepare_operation(OVERLAPPED *operation)
{
    HANDLE event = operation->hEvent;
    memset(operation, 0, sizeof(*operation));
    operation->hEvent = event;
    ResetEvent(event);
}

static bool arm_accept(struct edge_pt_pipe_connection *peer)
{
    prepare_operation(&peer->accept);
    if (ConnectNamedPipe(peer->pipe, &peer->accept) || GetLastError() == ERROR_PIPE_CONNECTED) {
        peer->connected = true;
        peer->connected_at = GetTickCount64();
        return true;
    }
    if (GetLastError() == ERROR_IO_PENDING) {
        peer->accept_pending = true;
        return true;
    }
    return false;
}

static void cancel_operation(struct edge_pt_pipe_connection *peer, OVERLAPPED *operation, bool pending)
{
    if (pending) {
        DWORD transferred;
        CancelIoEx(peer->pipe, operation);
        /* Cancellation is a request. Keep OVERLAPPED and buffers alive until
         * this native pipe operation has actually completed. No flush waits. */
        GetOverlappedResult(peer->pipe, operation, &transferred, TRUE);
    }
}

static void reset_peer(struct edge_pt_pipe_connection *peer, bool reuse)
{
    peer->closing = true;
    cancel_operation(peer, &peer->accept, peer->accept_pending);
    cancel_operation(peer, &peer->read, peer->read_pending);
    cancel_operation(peer, &peer->write, peer->write_pending);
    peer->accept_pending = peer->read_pending = peer->write_pending = false;
    if (peer->session) {
        void *session = peer->session;
        peer->session = NULL;
        peer->listener->callbacks.closed(session);
    }
    while (peer->head) {
        struct pipe_frame *frame = peer->head;
        peer->head = frame->next;
        free(frame);
    }
    peer->tail = NULL;
    peer->queue_bytes = 0; peer->queue_frames = 0;
    free(peer->body); peer->body = NULL;
    peer->header_used = peer->body_length = peer->body_used = 0;
    if (peer->pipe != INVALID_HANDLE_VALUE) DisconnectNamedPipe(peer->pipe);
    peer->connected = false;
    peer->read_deadline = peer->write_deadline = 0;
    if (reuse) {
        peer->closing = false;
        if (!arm_accept(peer)) {
            peer->closing = true;
            fprintf(stderr, "Named-pipe accept rearm failed: %lu\n", GetLastError());
        }
    }
}

void edge_pt_pipe_close(void *transport)
{
    struct edge_pt_pipe_connection *peer = transport;
    if (peer && !peer->closing) {
        peer->closing = true;
        peer->close_deadline = GetTickCount64() + PIPE_IO_TIMEOUT_MS;
    }
}

unsigned edge_pt_pipe_client_count(const struct edge_pt_pipe_listener *listener)
{
    unsigned count = 0;
    if (listener) for (unsigned i = 0; i < listener->count; ++i)
        if (listener->peers[i].connected && listener->peers[i].session && !listener->peers[i].closing) ++count;
    return count;
}

int edge_pt_pipe_send(struct edge_pt_pipe_connection *peer, char *data, size_t length)
{
    if (!peer || !peer->connected || peer->closing || !data || !length || length > EDGE_PT_PIPE_MAX_FRAME ||
        peer->queue_frames >= PIPE_QUEUE_FRAMES || length + 4 > PIPE_QUEUE_BYTES - peer->queue_bytes) {
        free(data);
        if (peer && !peer->closing) {
            edge_pt_pipe_close(peer);
            peer->close_deadline = GetTickCount64();
        }
        return -1;
    }
    struct pipe_frame *frame = malloc(sizeof(*frame) + length + 4);
    if (!frame) {
        free(data);
        edge_pt_pipe_close(peer);
        return -1;
    }
    frame->next = NULL; frame->length = (DWORD)length + 4; frame->offset = 0;
    frame->bytes = (unsigned char *)(frame + 1);
    frame->bytes[0] = (unsigned char)(length >> 24); frame->bytes[1] = (unsigned char)(length >> 16);
    frame->bytes[2] = (unsigned char)(length >> 8); frame->bytes[3] = (unsigned char)length;
    memcpy(frame->bytes + 4, data, length);
    free(data);
    if (peer->tail) peer->tail->next = frame;
    else peer->head = frame;
    peer->tail = frame;
    peer->queue_bytes += frame->length; ++peer->queue_frames;
    return 0;
}

static bool process_body(struct edge_pt_pipe_connection *peer)
{
    if (memchr(peer->body, 0, peer->body_length)) return false;
    peer->body[peer->body_length] = 0;
    if (!peer->session) {
        json_error_t error;
        json_t *hello = json_loadb(peer->body, peer->body_length, JSON_REJECT_DUPLICATES, &error);
        const char *protocol = json_string_value(json_object_get(hello, "protocol"));
        json_t *version = json_object_get(hello, "version");
        bool valid = json_is_object(hello) && json_object_size(hello) == 2 && protocol &&
                     json_string_length(json_object_get(hello, "protocol")) == 7 && !strcmp(protocol, "edge-pt") &&
                     json_is_integer(version) && json_integer_value(version) == 1;
        json_decref(hello);
        if (!valid) return false;
        peer->session = peer->listener->callbacks.opened(peer->listener->context, peer);
        if (!peer->session) return false;
        const char *reply = "{\"protocol\":\"edge-pt\",\"version\":1,\"maxFrameSize\":65536}";
        return edge_pt_pipe_send(peer, _strdup(reply), strlen(reply)) == 0;
    }
    peer->listener->callbacks.received(peer->session, peer->body, peer->body_length);
    return true;
}

static bool read_complete(struct edge_pt_pipe_connection *peer, DWORD bytes)
{
    if (!bytes) return false;
    if (!peer->body) {
        peer->header_used += bytes;
        if (!peer->read_deadline) peer->read_deadline = GetTickCount64() + PIPE_IO_TIMEOUT_MS;
        if (peer->header_used == 4) {
            peer->body_length = ((DWORD)peer->header[0] << 24) | ((DWORD)peer->header[1] << 16) |
                                ((DWORD)peer->header[2] << 8) | peer->header[3];
            if (!peer->body_length || peer->body_length > EDGE_PT_PIPE_MAX_FRAME) return false;
            peer->body = malloc((size_t)peer->body_length + 1);
            if (!peer->body) return false;
        }
    } else {
        peer->body_used += bytes;
        if (peer->body_used == peer->body_length) {
            bool ok = process_body(peer);
            free(peer->body); peer->body = NULL;
            peer->header_used = peer->body_length = peer->body_used = 0;
            peer->read_deadline = 0;
            return ok;
        }
    }
    return true;
}

static bool service_read(struct edge_pt_pipe_connection *peer)
{
    for (unsigned work = 0; work < 4 && !peer->closing; ++work) {
        DWORD bytes = 0;
        if (peer->read_pending) {
            if (!GetOverlappedResult(peer->pipe, &peer->read, &bytes, FALSE)) {
                if (GetLastError() == ERROR_IO_INCOMPLETE) return true;
                peer->read_pending = false;
                return false;
            }
            peer->read_pending = false;
            if (!read_complete(peer, bytes)) return false;
        } else {
            void *buffer = peer->body ? (void *)(peer->body + peer->body_used) : peer->header + peer->header_used;
            DWORD length = peer->body ? peer->body_length - peer->body_used : 4 - peer->header_used;
            if (length > 4096) length = 4096;
            prepare_operation(&peer->read);
            if (ReadFile(peer->pipe, buffer, length, &bytes, &peer->read)) {
                if (!read_complete(peer, bytes)) return false;
            } else {
                if (GetLastError() != ERROR_IO_PENDING) return false;
                peer->read_pending = true;
                return true;
            }
        }
    }
    return true;
}

static bool write_complete(struct edge_pt_pipe_connection *peer, DWORD bytes)
{
    struct pipe_frame *frame = peer->head;
    if (!frame || !bytes || bytes > frame->length - frame->offset) return false;
    frame->offset += bytes;
    if (frame->offset == frame->length) {
        peer->head = frame->next;
        if (!peer->head) peer->tail = NULL;
        peer->queue_bytes -= frame->length; --peer->queue_frames;
        free(frame);
        peer->write_deadline = 0;
    }
    return true;
}

static bool service_write(struct edge_pt_pipe_connection *peer)
{
    for (unsigned work = 0; work < 4 && peer->head; ++work) {
        DWORD bytes = 0;
        if (peer->write_pending) {
            if (!GetOverlappedResult(peer->pipe, &peer->write, &bytes, FALSE)) {
                if (GetLastError() == ERROR_IO_INCOMPLETE) return true;
                peer->write_pending = false;
                return false;
            }
            peer->write_pending = false;
            if (!write_complete(peer, bytes)) return false;
        } else {
            struct pipe_frame *frame = peer->head;
            prepare_operation(&peer->write);
            if (!peer->write_deadline) peer->write_deadline = GetTickCount64() + PIPE_IO_TIMEOUT_MS;
            if (WriteFile(peer->pipe, frame->bytes + frame->offset, frame->length - frame->offset, &bytes, &peer->write)) {
                if (!write_complete(peer, bytes)) return false;
            } else {
                if (GetLastError() != ERROR_IO_PENDING) return false;
                peer->write_pending = true;
                return true;
            }
        }
    }
    return true;
}

static void poll_connections(evutil_socket_t socket, short events, void *context)
{
    struct edge_pt_pipe_listener *listener = context;
    (void)socket; (void)events;
    ULONGLONG now = GetTickCount64();
    for (unsigned work = 0; work < listener->count; ++work) {
        unsigned index = (listener->next_peer + work) % listener->count;
        struct edge_pt_pipe_connection *peer = &listener->peers[index];
        if (peer->accept_pending) {
            DWORD bytes;
            if (GetOverlappedResult(peer->pipe, &peer->accept, &bytes, FALSE)) {
                peer->accept_pending = false;
                peer->connected = true;
                peer->connected_at = now;
            } else if (GetLastError() != ERROR_IO_INCOMPLETE) {
                peer->accept_pending = false;
                reset_peer(peer, true);
            }
        }
        if (!peer->connected) continue;
        bool expired = (!peer->session && now - peer->connected_at >= PIPE_IO_TIMEOUT_MS) ||
                       (peer->read_deadline && now >= peer->read_deadline) ||
                       (peer->write_deadline && now >= peer->write_deadline);
        if (expired || (peer->closing && now >= peer->close_deadline) ||
            (!peer->closing && !service_read(peer)) || !service_write(peer) ||
            (peer->closing && !peer->head)) reset_peer(peer, true);
    }
    listener->next_peer = (listener->next_peer + 1) % listener->count;
}

void edge_pt_pipe_stop(struct edge_pt_pipe_listener *listener)
{
    if (!listener) return;
    listener->stopping = true;
    if (listener->poll) event_free(listener->poll);
    for (unsigned i = 0; i < listener->count; ++i) {
        struct edge_pt_pipe_connection *peer = &listener->peers[i];
        reset_peer(peer, false);
        if (peer->pipe != INVALID_HANDLE_VALUE) CloseHandle(peer->pipe);
        if (peer->accept.hEvent) CloseHandle(peer->accept.hEvent);
        if (peer->read.hEvent) CloseHandle(peer->read.hEvent);
        if (peer->write.hEvent) CloseHandle(peer->write.hEvent);
    }
    free(listener->peers); free(listener);
}

struct edge_pt_pipe_listener *edge_pt_pipe_start(struct event_base *base,
    const edge_runtime_config *config, const edge_pt_pipe_callbacks *callbacks, void *context)
{
    struct edge_pt_pipe_listener *listener = NULL;
    PSECURITY_DESCRIPTOR security = NULL;
    wchar_t name[EDGE_PIPE_NAME_CAPACITY];
    if (!base || !config || !callbacks || !callbacks->opened || !callbacks->received || !callbacks->closed ||
        !edge_runtime_pipe_name_valid(config->named_pipe_name) || config->named_pipe_max_clients < 1 ||
        config->named_pipe_max_clients > 32 || config->named_pipe_client_sid_count > EDGE_PIPE_MAX_CLIENT_SIDS) return NULL;
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, config->named_pipe_name, -1, name, EDGE_PIPE_NAME_CAPACITY)) return NULL;
    security = pipe_security(config);
    if (!security) goto fail;
    SECURITY_ATTRIBUTES attributes = {sizeof(attributes), security, FALSE};
    listener = calloc(1, sizeof(*listener));
    if (!listener) goto fail;
    listener->callbacks = *callbacks; listener->context = context;
    listener->peers = calloc(config->named_pipe_max_clients, sizeof(*listener->peers));
    if (!listener->peers) goto fail;
    for (unsigned i = 0; i < config->named_pipe_max_clients; ++i) {
        struct edge_pt_pipe_connection *peer = &listener->peers[i];
        peer->listener = listener;
        peer->pipe = INVALID_HANDLE_VALUE;
        ++listener->count;
        peer->accept.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        peer->read.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        peer->write.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!peer->accept.hEvent || !peer->read.hEvent || !peer->write.hEvent) goto fail;
        peer->pipe = CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED |
            (i == 0 ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0),
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            config->named_pipe_max_clients, 4096, 4096, 1000, &attributes);
        if (peer->pipe == INVALID_HANDLE_VALUE || !arm_accept(peer)) goto fail;
    }
    /* Native HANDLE readiness is not Winsock readiness. Poll only completion
     * state at a bounded 10-ms interval; all RPC work stays on the Edge thread. */
    listener->poll = event_new(base, -1, EV_PERSIST, poll_connections, listener);
    const struct timeval interval = {0, 10000};
    if (!listener->poll || event_add(listener->poll, &interval)) goto fail;
    LocalFree(security);
    printf("Named-pipe PT listener: %s (max clients %u)\n", config->named_pipe_name, listener->count);
    return listener;
fail:
    fprintf(stderr, "Named-pipe PT listener initialization failed: %lu\n", GetLastError());
    LocalFree(security);
    edge_pt_pipe_stop(listener);
    return NULL;
}
