/* SPDX-License-Identifier: Apache-2.0 */
#include <winsock2.h>
#include <windows.h>
#include <afunix.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <event2/event.h>
#include "libwebsockets.h"
#include "edge_pt_unix.h"

struct edge_pt_unix_listener {
    SOCKET socket;
    HANDLE lock;
    HANDLE socket_file;
    struct event *accept_event;
    struct lws_context *context;
};

static bool canonical_path(const char *path, wchar_t *wide, char *utf8)
{
    wchar_t input[UNIX_PATH_MAX];
    if (!path || strlen(path) < 4 || strlen(path) >= UNIX_PATH_MAX ||
        !((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) ||
        path[1] != ':' || (path[2] != '\\' && path[2] != '/')) return false;
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, input, UNIX_PATH_MAX)) return false;
    DWORD length = GetFullPathNameW(input, UNIX_PATH_MAX, wide, NULL);
    if (!length || length >= UNIX_PATH_MAX || wide[length - 1] == L'\\' ||
        wcschr(wide + 2, L':')) return false;
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, -1,
                              utf8, UNIX_PATH_MAX, NULL, NULL) != 0;
}

bool edge_pt_unix_path_valid(const char *path)
{
    wchar_t wide[UNIX_PATH_MAX]; char utf8[UNIX_PATH_MAX];
    return canonical_path(path, wide, utf8);
}

static bool is_unix_socket_file(HANDLE file)
{
    BYTE buffer[MAXIMUM_REPARSE_DATA_BUFFER_SIZE];
    DWORD bytes = 0, tag = 0;
    if (!DeviceIoControl(file, FSCTL_GET_REPARSE_POINT, NULL, 0, buffer,
                         sizeof(buffer), &bytes, NULL) || bytes < sizeof(tag)) return false;
    memcpy(&tag, buffer, sizeof(tag));
    return tag == IO_REPARSE_TAG_AF_UNIX;
}

static void accept_connection(evutil_socket_t socket, short events, void *arg)
{
    struct edge_pt_unix_listener *listener = arg;
    (void)events;
    /* Bound each callback so a busy listener cannot starve cloud/shutdown work. */
    for (unsigned count = 0; count < 16; ++count) {
        SOCKET accepted = accept(socket, NULL, NULL);
        if (accepted == INVALID_SOCKET) {
            int error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK) fprintf(stderr, "AF_UNIX accept failed: %d\n", error);
            return;
        }
        u_long nonblocking = 1;
        if (ioctlsocket(accepted, FIONBIO, &nonblocking) == SOCKET_ERROR) {
            closesocket(accepted);
            continue;
        }
        /* Adoption owns the socket, including closing it on failure. */
        if (!lws_adopt_socket(listener->context, accepted))
            fprintf(stderr, "AF_UNIX WebSocket adoption failed.\n");
    }
}

void edge_pt_unix_stop(struct edge_pt_unix_listener *listener)
{
    if (!listener) return;
    if (listener->accept_event) event_free(listener->accept_event);
    if (listener->socket != INVALID_SOCKET) closesocket(listener->socket);
    if (listener->socket_file != INVALID_HANDLE_VALUE) {
        FILE_DISPOSITION_INFO remove = {TRUE};
        if (!SetFileInformationByHandle(listener->socket_file, FileDispositionInfo, &remove, sizeof(remove)))
            fprintf(stderr, "AF_UNIX socket cleanup failed: %lu\n", GetLastError());
        CloseHandle(listener->socket_file);
    }
    if (listener->lock != INVALID_HANDLE_VALUE) CloseHandle(listener->lock);
    /* Retain the lock file so closing/deleting it cannot race a new owner. */
    free(listener);
}

struct edge_pt_unix_listener *edge_pt_unix_start(struct event_base *base,
                                               struct lws_context *context,
                                               const char *path)
{
    wchar_t wide[UNIX_PATH_MAX], lock_path[UNIX_PATH_MAX + 6];
    char utf8[UNIX_PATH_MAX];
    struct edge_pt_unix_listener *listener = NULL;
    SOCKADDR_UN address = {0};
    if (!base || !context || !canonical_path(path, wide, utf8)) {
        fprintf(stderr, "AF_UNIX requires an absolute local path shorter than 108 UTF-8 bytes.\n");
        return NULL;
    }
    listener = calloc(1, sizeof(*listener));
    if (!listener) return NULL;
    listener->socket = INVALID_SOCKET;
    listener->lock = listener->socket_file = INVALID_HANDLE_VALUE;
    listener->context = context;
    swprintf_s(lock_path, UNIX_PATH_MAX + 6, L"%ls.lock", wide);
    listener->lock = CreateFileW(lock_path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS,
                                 FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (listener->lock == INVALID_HANDLE_VALUE) goto fail;
    BY_HANDLE_FILE_INFORMATION lock_info;
    if (!GetFileInformationByHandle(listener->lock, &lock_info) ||
        (lock_info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))) goto fail;
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, utf8, strlen(utf8) + 1);
    DWORD attributes = GetFileAttributesW(wide);
    if (attributes != INVALID_FILE_ATTRIBUTES) {
        /* Never remove regular files, directories, other reparse points, or live sockets. */
        HANDLE stale = CreateFileW(wide, GENERIC_READ | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
        if (stale == INVALID_HANDLE_VALUE) goto fail;
        bool removable = is_unix_socket_file(stale);
        SOCKET probe = socket(AF_UNIX, SOCK_STREAM, 0);
        if (probe == INVALID_SOCKET) removable = false;
        else {
            u_long nonblocking = 1;
            if (ioctlsocket(probe, FIONBIO, &nonblocking) == SOCKET_ERROR) removable = false;
            else if (connect(probe, (struct sockaddr *)&address, sizeof(address)) == 0 ||
                     WSAGetLastError() != WSAECONNREFUSED) removable = false;
            closesocket(probe);
        }
        FILE_DISPOSITION_INFO remove = {TRUE};
        if (removable) removable = SetFileInformationByHandle(stale, FileDispositionInfo, &remove, sizeof(remove)) != 0;
        CloseHandle(stale);
        if (!removable) {
            fprintf(stderr, "AF_UNIX endpoint already exists; refusing to replace it.\n");
            goto fail;
        }
    } else if (GetLastError() != ERROR_FILE_NOT_FOUND) goto fail;
    listener->socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener->socket == INVALID_SOCKET) goto fail;
    if (bind(listener->socket, (struct sockaddr *)&address, sizeof(address)) == SOCKET_ERROR) goto fail;
    listener->socket_file = CreateFileW(wide, GENERIC_READ | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                       NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (listener->socket_file == INVALID_HANDLE_VALUE) goto fail;
    if (!is_unix_socket_file(listener->socket_file)) {
        CloseHandle(listener->socket_file);
        listener->socket_file = INVALID_HANDLE_VALUE;
        goto fail;
    }
    u_long nonblocking = 1;
    if (ioctlsocket(listener->socket, FIONBIO, &nonblocking) == SOCKET_ERROR ||
        listen(listener->socket, SOMAXCONN) == SOCKET_ERROR) goto fail;
    listener->accept_event = event_new(base, listener->socket, EV_READ | EV_PERSIST, accept_connection, listener);
    if (!listener->accept_event || event_add(listener->accept_event, NULL)) goto fail;
    fprintf(stdout, "AF_UNIX protocol listener: %s\n", utf8);
    return listener;
fail:
    fprintf(stderr, "AF_UNIX listener initialization failed (Windows=%lu, Winsock=%d).\n",
            GetLastError(), WSAGetLastError());
    edge_pt_unix_stop(listener);
    return NULL;
}
