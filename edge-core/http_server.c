/*
 * ----------------------------------------------------------------------------
 * Copyright 2018 ARM Ltd.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ----------------------------------------------------------------------------
 */

#include "event2/http.h"
#include "event2/buffer.h"

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "edge-core/http_server.h"
#ifdef __APPLE__
#include "edge-core/status_public.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <sys/acl.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#endif

#include "mbed-trace/mbed_trace.h"
#define TRACE_GROUP "serv"

EDGE_LOCAL void add_ok_response_headers(struct evhttp_request *req)
{
    evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "application/json");
    evhttp_add_header(evhttp_request_get_output_headers(req), "Charset", "utf-8");
}

#ifdef __APPLE__
static int bounded_json(const char *data, size_t size, void *argument)
{
    struct evbuffer *buffer = argument;
    size_t current = evbuffer_get_length(buffer);
    if (current > EDGE_STATUS_MAX_JSON || size > EDGE_STATUS_MAX_JSON - current) return -1;
    return evbuffer_add(buffer, data, size);
}

static void macos_response_headers(struct evhttp_request *request)
{
    evhttp_add_header(evhttp_request_get_output_headers(request), "Connection", "close");
    evhttp_add_header(evhttp_request_get_output_headers(request), "Cache-Control", "no-store");
}
#endif

EDGE_LOCAL void reply_ok_and_status(struct context *ctx, struct evhttp_request *req, struct evbuffer *buf)
{
    json_t *obj = NULL;
#ifndef __APPLE__
    char *reply = NULL;
#endif

    add_ok_response_headers(req);

    obj = http_state_in_json(ctx);
#ifdef __APPLE__
    if (!obj) {
        evhttp_send_error(req, HTTP_INTERNAL, "Status unavailable");
        return;
    }
    if (ctx->ctx_data->status_unix_server &&
        evhttp_request_get_connection(req) &&
        evhttp_connection_get_server(evhttp_request_get_connection(req)) == ctx->ctx_data->status_unix_server->http) {
        const char *uri = json_string_value(json_object_get(obj, "lwm2m-server-uri"));
        char public_uri[1025];
        if (!edge_status_public_uri(uri, public_uri, sizeof(public_uri))) public_uri[0] = '\0';
        json_object_set_new(obj, "lwm2m-server-uri", json_string(public_uri));
    }
    if (json_dump_callback(obj, bounded_json, buf, JSON_COMPACT) != 0) {
        evbuffer_drain(buf, evbuffer_get_length(buf));
        evhttp_send_error(req, HTTP_INTERNAL, "Status unavailable");
    } else {
        evhttp_send_reply(req, 200, "OK", buf);
    }
    json_decref(obj);
#else
    reply = json_dumps(obj, ctx->json_flags);
    evbuffer_add(buf, reply, strlen(reply));
    evhttp_send_reply(req, 200, "OK", buf);

    /* Cleanup */
    json_decref(obj);
    obj = NULL;
    free(reply);
    reply = NULL;
#endif
}

/* Callback used for the /status URI.
 * For every non-GET request:
 * returns error code 505 */
EDGE_LOCAL void status_request_cb(struct evhttp_request *req, void *arg)
{
    struct context *ctx = (struct context *) (arg);
    const char *uri = evhttp_request_get_uri(req);
    struct evhttp_uri *decoded_uri = NULL;
    const char *query = NULL;
    struct evbuffer *buf = evbuffer_new();
#ifdef __APPLE__
    macos_response_headers(req);
    if (!buf) { evhttp_send_error(req, HTTP_INTERNAL, "Status unavailable"); return; }
#endif

    decoded_uri = evhttp_uri_parse(uri);
    if (!decoded_uri) {
        tr_warn("It's not a good URI");
        evhttp_send_reply(req, HTTP_BADREQUEST, "Bad request", buf);
        goto cleanup;
    }

    query = evhttp_uri_get_query(decoded_uri);
    evhttp_uri_free(decoded_uri);
    decoded_uri = NULL;

    if (query) {
        tr_warn("No query is yet supported");
        evhttp_send_reply(req, HTTP_BADREQUEST, "Bad request", buf);
        goto cleanup;
    }
    if (evhttp_request_get_command(req) != EVHTTP_REQ_GET) {
        tr_warn("Request type is not get");
#ifdef __APPLE__
        evhttp_add_header(evhttp_request_get_output_headers(req), "Allow", "GET");
        evhttp_send_reply(req, HTTP_BADMETHOD, "Method not allowed", buf);
#else
        evhttp_send_reply(req, HTTP_BADMETHOD, "Method not allowed", buf);
        evhttp_add_header(evhttp_request_get_output_headers(req), "Allow", "GET");
#endif
        goto cleanup;
    }

    reply_ok_and_status(ctx, req, buf);

    cleanup: evbuffer_free(buf);
}

EDGE_LOCAL void generic_request_cb(struct evhttp_request *req, void *arg)
{
    struct evbuffer *buf = evbuffer_new();
    (void) arg;
#ifdef __APPLE__
    macos_response_headers(req);
    if (!buf) { evhttp_send_error(req, HTTP_INTERNAL, "Status unavailable"); return; }
#endif
    evhttp_send_reply(req, HTTP_NOTFOUND, "Not found", buf);
    evbuffer_free(buf);
    buf = NULL;
}

#ifdef __APPLE__
static bool macos_configure_http(struct http_server *server, struct context *ctx)
{
    server->status_directory = server->status_lock = -1;
    server->http = evhttp_new(ctx->ev_base);
    if (!server->http || evhttp_set_cb(server->http, "/status", status_request_cb, ctx) != 0) return false;
    evhttp_set_gencb(server->http, generic_request_cb, NULL);
    evhttp_set_max_headers_size(server->http, 8192);
    evhttp_set_max_body_size(server->http, 1024);
    evhttp_set_timeout(server->http, 5);
    return true;
}

/* POSIX mode bits alone do not exclude extended ACL write grants. */
static bool directory_acl_safe(int fd)
{
    acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
    if (!acl) return errno == ENOENT;
    acl_entry_t entry;
    int next = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
    bool safe = true;
    while (next == 0) {
        acl_tag_t tag;
        acl_permset_t permissions;
        if (acl_get_tag_type(entry, &tag) != 0 || acl_get_permset(entry, &permissions) != 0) { safe = false; break; }
        if (tag == ACL_EXTENDED_ALLOW &&
            (acl_get_perm_np(permissions, ACL_ADD_FILE) || acl_get_perm_np(permissions, ACL_ADD_SUBDIRECTORY) ||
             acl_get_perm_np(permissions, ACL_DELETE_CHILD) || acl_get_perm_np(permissions, ACL_WRITE_SECURITY) ||
             acl_get_perm_np(permissions, ACL_CHANGE_OWNER) || acl_get_perm_np(permissions, ACL_DELETE) ||
             acl_get_perm_np(permissions, ACL_WRITE_ATTRIBUTES) || acl_get_perm_np(permissions, ACL_WRITE_EXTATTRIBUTES))) {
            safe = false;
            break;
        }
        next = acl_get_entry(acl, ACL_NEXT_ENTRY, &entry);
    }
    if (next != 0 && errno != EINVAL && next != 1) safe = false;
    acl_free(acl);
    return safe;
}

/* Walk from the root without following symlinks. Only the final directory
 * may be created; installed parent directories are owned by the installer. */
static int status_directory_open(char *path)
{
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return -1;
    char *component = path + 1;
    for (;;) {
        char *slash = strchr(component, '/');
        if (slash) *slash = '\0';
        if (!*component || !strcmp(component, ".") || !strcmp(component, "..")) { close(fd); return -1; }
        int child = openat(fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (child < 0 && errno == ENOENT && !slash && mkdirat(fd, component, 0750) == 0) {
            child = openat(fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        }
        close(fd);
        if (child < 0) return -1;
        struct stat info;
        if (fstat(child, &info) != 0 ||
            (info.st_uid != geteuid() && info.st_uid != 0) ||
            ((info.st_mode & 0022) && !(info.st_uid == 0 && (info.st_mode & S_ISVTX))) ||
            !directory_acl_safe(child) ||
            (!slash && (info.st_uid != geteuid() || (info.st_mode & 0027) || !(info.st_mode & S_IWUSR)))) {
            close(child);
            return -1;
        }
        fd = child;
        if (!slash) return fd;
        *slash = '/';
        component = slash + 1;
    }
}

static bool same_socket(struct http_server *server)
{
    struct stat info;
    return server->socket_inode && server->status_directory >= 0 &&
        fstatat(server->status_directory, server->status_name, &info, AT_SYMLINK_NOFOLLOW) == 0 &&
        S_ISSOCK(info.st_mode) && info.st_uid == geteuid() &&
        (unsigned long long)info.st_dev == server->socket_device &&
        (unsigned long long)info.st_ino == server->socket_inode;
}

static bool remove_stale_socket(struct http_server *server, const struct sockaddr_un *address)
{
    struct stat before, after;
    if (fstatat(server->status_directory, server->status_name, &before, AT_SYMLINK_NOFOLLOW) != 0) return errno == ENOENT;
    if (!S_ISSOCK(before.st_mode) || before.st_uid != geteuid() || before.st_nlink != 1) return false;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return false;
    if (evutil_make_socket_nonblocking(fd) != 0 || evutil_make_socket_closeonexec(fd) != 0) { close(fd); return false; }
    int result = connect(fd, (const struct sockaddr *)address, address->sun_len);
    int error = errno;
    close(fd);
    if (result == 0 || error != ECONNREFUSED) return false;
    if (fstatat(server->status_directory, server->status_name, &after, AT_SYMLINK_NOFOLLOW) != 0 ||
        before.st_dev != after.st_dev || before.st_ino != after.st_ino) return false;
    return unlinkat(server->status_directory, server->status_name, 0) == 0;
}

bool http_server_init_unix(struct context *ctx, const char *path)
{
    if (!path || !*path || ctx->ctx_data->status_unix_server) return false;
    struct http_server *server = calloc(1, sizeof(*server));
    if (!server) return false;
    ctx->ctx_data->status_unix_server = server;
    int fd = -1;
    if (!macos_configure_http(server, ctx)) goto fail;
    if (path[0] == '/') {
        if (strlen(path) >= sizeof(server->status_path)) goto fail;
        strcpy(server->status_path, path);
    } else {
        char cwd[PATH_MAX];
        if (!getcwd(cwd, sizeof(cwd))) goto fail;
        int length = snprintf(server->status_path, sizeof(server->status_path), "%s/%s", cwd, path);
        if (length < 0 || (size_t)length >= sizeof(server->status_path)) goto fail;
    }
    char parent[104];
    strcpy(parent, server->status_path);
    char *separator = strrchr(parent, '/');
    if (!separator || separator == parent || !separator[1]) goto fail;
    strcpy(server->status_name, separator + 1);
    *separator = '\0';
    server->status_directory = status_directory_open(parent);
    if (server->status_directory < 0) goto fail;
    char lock_name[110];
    snprintf(lock_name, sizeof(lock_name), "%s.lock", server->status_name);
    server->status_lock = openat(server->status_directory, lock_name, O_CREAT | O_RDWR | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC, 0600);
    struct stat lock_info, directory_info;
    if (server->status_lock < 0 || fstat(server->status_lock, &lock_info) != 0 ||
        !S_ISREG(lock_info.st_mode) || lock_info.st_uid != geteuid() || lock_info.st_nlink != 1 ||
        (lock_info.st_mode & 0077) || !directory_acl_safe(server->status_lock) ||
        flock(server->status_lock, LOCK_EX | LOCK_NB) != 0 ||
        fstat(server->status_directory, &directory_info) != 0) goto fail;
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, server->status_path);
    address.sun_len = (unsigned char)(offsetof(struct sockaddr_un, sun_path) + strlen(address.sun_path) + 1);
    if (!remove_stale_socket(server, &address)) goto fail;
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0 || evutil_make_socket_nonblocking(fd) != 0 || evutil_make_socket_closeonexec(fd) != 0 ||
        bind(fd, (struct sockaddr *)&address, address.sun_len) != 0) goto fail;
    struct stat socket_info;
    if (fstatat(server->status_directory, server->status_name, &socket_info, AT_SYMLINK_NOFOLLOW) != 0 ||
        !S_ISSOCK(socket_info.st_mode) || socket_info.st_uid != geteuid()) goto fail;
    server->socket_device = (unsigned long long)socket_info.st_dev;
    server->socket_inode = (unsigned long long)socket_info.st_ino;
    if (fchownat(server->status_directory, server->status_name, (uid_t)-1, directory_info.st_gid, AT_SYMLINK_NOFOLLOW) != 0 ||
        fchmodat(server->status_directory, server->status_name, 0660, AT_SYMLINK_NOFOLLOW) != 0 || listen(fd, 8) != 0) goto fail;
    server->bound_socket = evhttp_accept_socket_with_handle(server->http, fd);
    if (!server->bound_socket) goto fail;
    fd = -1;
    tr_info("Listening on Unix status socket %s.", server->status_path);
    return true;
fail:
    if (fd >= 0) close(fd);
    tr_err("Cannot initialize protected Unix status socket.");
    http_server_clean(&ctx->ctx_data->status_unix_server);
    return false;
}
#endif

bool http_server_init(struct context *ctx, int port, char *http_address)
{
    struct evhttp *http = NULL;
#ifndef __APPLE__
    struct evhttp_bound_socket *handle = NULL;
#endif
    bool init_succeeded = false;

    struct ctx_data *ctx_data = ctx->ctx_data;
    ctx_data->http_server = calloc(1, sizeof(struct http_server));
    if (!ctx_data->http_server) return false;
#ifdef __APPLE__
    if (!macos_configure_http(ctx_data->http_server, ctx)) {
        http_server_clean(&ctx_data->http_server);
        return false;
    }
    http = ctx_data->http_server->http;
    ctx_data->http_server->bound_socket = evhttp_bind_socket_with_handle(http, http_address, port);
    init_succeeded = ctx_data->http_server->bound_socket != NULL;
#else
    ctx_data->http_server->http = http = evhttp_new(ctx->ev_base);
    if (!http) {
        tr_err("Couldn't create evhttp.\n");
    } else if (evhttp_set_cb(http, "/status", status_request_cb, ctx)) {
        tr_err("Couldn't set the status request call back.\n");
    } else {
        evhttp_set_gencb(http, generic_request_cb, NULL);
        ctx_data->http_server->bound_socket = handle = evhttp_bind_socket_with_handle(http, http_address, port);
        if (!handle) {
            tr_err("Couldn't bind to port %d.\n", (int) port);
        } else {
            tr_info("Listening %s on http port %d.", http_address, port);
            init_succeeded = true;
        }
    }
#endif
    if (!init_succeeded) {
        http_server_clean(&(ctx_data->http_server));
    }
    return init_succeeded;
}

void http_server_clean(struct http_server **server)
{
    tr_info("Cleaning http server resources");
    if (*server) {
        if ((*server)->bound_socket) {
            evhttp_del_accept_socket((*server)->http, (*server)->bound_socket);
            (*server)->bound_socket = NULL;
        }
        if ((*server)->http) {
            evhttp_free((*server)->http);
            (*server)->http = NULL;
        }
#ifdef __APPLE__
        if (same_socket(*server)) unlinkat((*server)->status_directory, (*server)->status_name, 0);
        if ((*server)->status_directory >= 0) close((*server)->status_directory);
        if ((*server)->status_lock >= 0) close((*server)->status_lock);
#endif
        free(*server);
        *server = NULL;
    }
}
