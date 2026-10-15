/* SPDX-License-Identifier: Apache-2.0 */
#include <errno.h>
#include <fcntl.h>
#include <membership.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <event2/event.h>
#include <event2/thread.h>
#include "edge-core/http_server.h"
#include "edge-core/listener_status.h"
#include "edge-core/status_public.h"

#define CHECK(test) do { if (!(test)) { fprintf(stderr, "%s:%d: %s (errno %d)\n", __FILE__, __LINE__, #test, errno); exit(1); } } while (0)
static atomic_bool oversized;
static atomic_uint heartbeat;

json_t *http_state_in_json(struct context *ctx)
{
    json_t *status = json_pack("{s:s,s:s,s:s,s:s}", "status", "connected", "edge-version", "test",
        "internal-id", "0123456789abcdef0123456789abcdef",
        "lwm2m-server-uri", "coaps+tcp://user:secret@cloud.example:5684/path?token=x#fragment");
    json_object_set_new(status, "connectivity", edge_listener_status_json(ctx->ctx_data->listener_status, 10000,
        (uint32_t)getpid(), 2, 3));
    if (atomic_load(&oversized)) {
        char *large = malloc(70001);
        CHECK(large);
        memset(large, 'x', 70000);
        large[70000] = 0;
        json_object_set_new(status, "large", json_string(large));
        free(large);
    }
    return status;
}

static struct sockaddr_un unix_address(const char *path)
{
    struct sockaddr_un address = {0};
    CHECK(strlen(path) < sizeof(address.sun_path));
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, path);
    address.sun_len = (unsigned char)(offsetof(struct sockaddr_un, sun_path) + strlen(path) + 1);
    return address;
}

static int connect_status(const char *path)
{
    struct sockaddr_un address = unix_address(path);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    const struct timeval timeout = {7, 0};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    int enabled = 1;
    CHECK(setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) == 0);
    CHECK(connect(fd, (struct sockaddr *)&address, address.sun_len) == 0);
    return fd;
}

static void exchange(const char *path, const char *request, int expected, const char *contains)
{
    int fd = connect_status(path);
    uid_t uid; gid_t gid;
    CHECK(getpeereid(fd, &uid, &gid) == 0 && uid == geteuid());
    pid_t pid = 0; socklen_t length = sizeof(pid);
    CHECK(getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &length) == 0 && pid == getpid());
    size_t sent = 0, size = strlen(request);
    while (sent < size) { ssize_t count = send(fd, request + sent, size - sent, 0); CHECK(count > 0); sent += (size_t)count; }
    char reply[70000]; size_t used = 0;
    ssize_t count;
    while ((count = recv(fd, reply + used, sizeof(reply) - used - 1, 0)) > 0) {
        used += (size_t)count;
        CHECK(used < sizeof(reply) - 1);
    }
    CHECK(count == 0);
    reply[used] = 0;
    int code = 0;
    if (sscanf(reply, "HTTP/%*s %d", &code) != 1 || code != expected) {
        fprintf(stderr, "Expected HTTP %d for %.*s; received %.*s\n", expected,
            (int)strcspn(request, "\r\n"), request, (int)strcspn(reply, "\r\n"), reply);
    }
    CHECK(sscanf(reply, "HTTP/%*s %d", &code) == 1 && code == expected);
    if (contains) CHECK(strstr(reply, contains));
    if (expected == 200) {
        char *body = strstr(reply, "\r\n\r\n");
        CHECK(body && strlen(body + 4) <= EDGE_STATUS_MAX_JSON);
        json_error_t error;
        json_t *json = json_loads(body + 4, 0, &error);
        CHECK(json);
        CHECK(!strcmp(json_string_value(json_object_get(json, "lwm2m-server-uri")), "coaps+tcp://cloud.example:5684"));
        CHECK(json_integer_value(json_object_get(json_object_get(json, "connectivity"), "processId")) == getpid());
        json_t *listeners = json_object_get(json_object_get(json, "connectivity"), "listeners");
        CHECK(json_is_true(json_object_get(json_object_get(listeners, "statusUnix"), "listening")));
        CHECK(json_is_false(json_object_get(json_object_get(listeners, "http"), "enabled")));
        CHECK(json_is_true(json_object_get(json_object_get(listeners, "afUnix"), "listening")));
        json_decref(json);
        CHECK(!strstr(reply, "secret") && !strstr(reply, "token="));
    }
    close(fd);
}

static void beat(evutil_socket_t fd, short events, void *argument)
{
    (void)fd; (void)events; (void)argument;
    atomic_fetch_add(&heartbeat, 1);
}
static void *dispatch(void *argument) { event_base_dispatch(argument); return NULL; }

static void socket_permissions(const char *directory, const char *path)
{
    struct stat info, parent;
    CHECK(lstat(path, &info) == 0 && S_ISSOCK(info.st_mode) && (info.st_mode & 0777) == 0660);
    CHECK(lstat(directory, &parent) == 0 && info.st_uid == geteuid() && info.st_gid == parent.st_gid);
    if (geteuid() != 0) {
        CHECK(chmod(path, 0440) == 0);
        struct sockaddr_un address = unix_address(path);
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        CHECK(fd >= 0 && connect(fd, (struct sockaddr *)&address, address.sun_len) != 0 && errno == EACCES);
        close(fd);
        CHECK(chmod(path, 0660) == 0);
    }
}

static void lifecycle_checks(struct context *ctx, const char *directory, const char *path)
{
    CHECK(http_server_init_unix(ctx, path));
    struct http_server *first = ctx->ctx_data->status_unix_server;
    struct ctx_data other_data = {0};
    struct context other = *ctx;
    other.ctx_data = &other_data;
    CHECK(!http_server_init_unix(&other, path) && !other_data.status_unix_server);
    CHECK(ctx->ctx_data->status_unix_server == first);
    http_server_clean(&ctx->ctx_data->status_unix_server);
    CHECK(access(path, F_OK) != 0);
    struct sockaddr_un address = unix_address(path);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(fd >= 0 && bind(fd, (struct sockaddr *)&address, address.sun_len) == 0);
    close(fd);
    CHECK(http_server_init_unix(ctx, path));
    http_server_clean(&ctx->ctx_data->status_unix_server);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(fd >= 0 && bind(fd, (struct sockaddr *)&address, address.sun_len) == 0 && listen(fd, 1) == 0);
    CHECK(!http_server_init_unix(ctx, path));
    CHECK(access(path, F_OK) == 0);
    close(fd); CHECK(unlink(path) == 0);

    fd = open(path, O_CREAT | O_WRONLY | O_EXCL, 0600); CHECK(fd >= 0); close(fd);
    CHECK(!http_server_init_unix(ctx, path) && access(path, F_OK) == 0);
    CHECK(unlink(path) == 0 && symlink("missing", path) == 0);
    CHECK(!http_server_init_unix(ctx, path));
    struct stat info; CHECK(lstat(path, &info) == 0 && S_ISLNK(info.st_mode));
    CHECK(unlink(path) == 0);
    char alias[104]; CHECK(snprintf(alias, sizeof(alias), "%s-alias", directory) > 0);
    CHECK(symlink(directory, alias) == 0);
    char alias_socket[120]; CHECK(snprintf(alias_socket, sizeof(alias_socket), "%s/socket", alias) > 0);
    CHECK(!http_server_init_unix(ctx, alias_socket) && unlink(alias) == 0);
    char lock_name[110]; CHECK(snprintf(lock_name, sizeof(lock_name), "%s.lock", path) > 0);
    CHECK(unlink(lock_name) == 0 && symlink("missing", lock_name) == 0);
    CHECK(!http_server_init_unix(ctx, path) && unlink(lock_name) == 0);
    CHECK(mkfifo(lock_name, 0600) == 0 && !http_server_init_unix(ctx, path) && unlink(lock_name) == 0);
    CHECK(chmod(directory, 0770) == 0 && !http_server_init_unix(ctx, path));
    CHECK(chmod(directory, 0755) == 0 && !http_server_init_unix(ctx, path));
    CHECK(chmod(directory, 0750) == 0);

    fd = open(directory, O_RDONLY | O_DIRECTORY); CHECK(fd >= 0);
    acl_t acl = acl_init(1); acl_entry_t entry; acl_permset_t permissions; uuid_t identity;
    CHECK(acl && mbr_uid_to_uuid(geteuid(), identity) == 0 && acl_create_entry(&acl, &entry) == 0);
    CHECK(acl_set_tag_type(entry, ACL_EXTENDED_ALLOW) == 0 && acl_set_qualifier(entry, identity) == 0);
    CHECK(acl_get_permset(entry, &permissions) == 0 && acl_add_perm(permissions, ACL_ADD_FILE) == 0);
    CHECK(acl_set_fd_np(fd, acl, ACL_TYPE_EXTENDED) == 0);
    CHECK(!http_server_init_unix(ctx, path));
    acl_free(acl); acl = acl_init(0);
    CHECK(acl && acl_set_fd_np(fd, acl, ACL_TYPE_EXTENDED) == 0); acl_free(acl); close(fd);
    char too_long[110]; memset(too_long, 'x', sizeof(too_long)); too_long[0] = '/'; too_long[109] = 0;
    CHECK(!http_server_init_unix(ctx, too_long));

    CHECK(http_server_init_unix(ctx, path));
    CHECK(unlink(path) == 0);
    fd = open(path, O_CREAT | O_WRONLY | O_EXCL, 0600); CHECK(fd >= 0); close(fd);
    http_server_clean(&ctx->ctx_data->status_unix_server);
    CHECK(lstat(path, &info) == 0 && S_ISREG(info.st_mode)); CHECK(unlink(path) == 0);

    pid_t child = fork(); CHECK(child >= 0);
    if (!child) {
        struct ctx_data child_data = {0};
        struct context child_ctx = {0}; child_ctx.ctx_data = &child_data; child_ctx.ev_base = event_base_new();
        _Exit(child_ctx.ev_base && http_server_init_unix(&child_ctx, path) ? 0 : 1);
    }
    int result; CHECK(waitpid(child, &result, 0) == child && WIFEXITED(result) && WEXITSTATUS(result) == 0);
    CHECK(lstat(path, &info) == 0 && S_ISSOCK(info.st_mode));
    CHECK(http_server_init_unix(ctx, path)); http_server_clean(&ctx->ctx_data->status_unix_server);
}

static void tcp_status(struct context *ctx)
{
    struct sockaddr_in address; socklen_t length = sizeof(address);
    int listener = evhttp_bound_socket_get_fd(ctx->ctx_data->http_server->bound_socket);
    CHECK(getsockname(listener, (struct sockaddr *)&address, &length) == 0 && ntohs(address.sin_port) != 0);
    int fd = socket(AF_INET, SOCK_STREAM, 0); CHECK(fd >= 0);
    CHECK(connect(fd, (struct sockaddr *)&address, length) == 0);
    const char request[] = "GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n";
    CHECK(send(fd, request, sizeof(request) - 1, 0) == sizeof(request) - 1);
    char reply[4096]; size_t used = 0; ssize_t count;
    while ((count = recv(fd, reply + used, sizeof(reply) - used - 1, 0)) > 0) used += (size_t)count;
    CHECK(count == 0); reply[used] = 0;
    CHECK(strstr(reply, "200 OK") && strstr(reply, "user:secret@cloud.example"));
    close(fd);
}

int main(int argc, char **argv)
{
    CHECK(argc == 1 || (argc == 3 && !strcmp(argv[1], "--monitor-cli") && argv[2][0] == '/'));
    CHECK(evthread_use_pthreads() == 0);
    CHECK(signal(SIGPIPE, SIG_DFL) != SIG_ERR);
    char root[] = "/private/tmp/edge-status-XXXXXX";
    CHECK(mkdtemp(root));
    char directory[100], path[104], lock_path[110];
    CHECK(snprintf(directory, sizeof(directory), "%s/status", root) > 0);
    CHECK(snprintf(path, sizeof(path), "%s/status.sock", directory) > 0);
    CHECK(snprintf(lock_path, sizeof(lock_path), "%s.lock", path) > 0);
    struct ctx_data data = {0};
    struct context ctx = {0}; ctx.ctx_data = &data; ctx.ev_base = event_base_new(); CHECK(ctx.ev_base);
    lifecycle_checks(&ctx, directory, path);
    CHECK(http_server_init_unix(&ctx, path));
    socket_permissions(directory, path);
    edge_listener_status listeners = {0};
    listeners.status_unix = (edge_listener_entry){true, true, true, path};
    listeners.http = (edge_listener_entry){true, false, false, ""};
    listeners.af_unix = (edge_listener_entry){true, true, true, "/private/tmp/pt.sock"};
    data.listener_status = &listeners;
    struct event *timer = event_new(ctx.ev_base, -1, EV_PERSIST, beat, NULL); CHECK(timer);
    const struct timeval interval = {0, 100000}; CHECK(event_add(timer, &interval) == 0);
    pthread_t thread; CHECK(pthread_create(&thread, NULL, dispatch, ctx.ev_base) == 0);
    if (argc == 3) {
        char uid[32], pid[32];
        CHECK(snprintf(uid, sizeof(uid), "%u", (unsigned)geteuid()) > 0);
        CHECK(snprintf(pid, sizeof(pid), "%u", (unsigned)getpid()) > 0);
        char *arguments[] = {argv[2], "diagnose", "--socket", path, "--uid", uid, "--pid", pid, "--json", NULL};
        extern char **environ;
        pid_t child; int result;
        CHECK(posix_spawn(&child, argv[2], NULL, NULL, arguments, environ) == 0);
        CHECK(waitpid(child, &result, 0) == child && WIFEXITED(result) && WEXITSTATUS(result) == 0);
    }
    exchange(path, "GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n", 200, "Cache-Control: no-store");
    exchange(path, "GET /status?x=1 HTTP/1.1\r\nHost: localhost\r\n\r\n", 400, NULL);
    exchange(path, "POST /status HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n", 405, "Allow: GET");
    exchange(path, "GET /missing HTTP/1.1\r\nHost: localhost\r\n\r\n", 404, NULL);
    char long_request[10000];
    strcpy(long_request, "GET /status HTTP/1.1\r\nHost: localhost\r\nX-Long: ");
    size_t prefix = strlen(long_request); memset(long_request + prefix, 'x', 9000);
    strcpy(long_request + prefix + 9000, "\r\n\r\n");
    exchange(path, long_request, 400, NULL);
    exchange(path, "POST /status HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100000\r\n\r\n", 413, NULL);
    atomic_store(&oversized, true);
    exchange(path, "GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n", 500, NULL);
    atomic_store(&oversized, false);
    for (unsigned i = 0; i < 4; ++i) {
        int abandoned = connect_status(path);
        const char request[] = "GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n";
        CHECK(send(abandoned, request, sizeof(request) - 1, 0) == sizeof(request) - 1);
        close(abandoned);
    }
    usleep(150000);

    int slow[8]; unsigned start = atomic_load(&heartbeat);
    for (size_t i = 0; i < 8; ++i) { slow[i] = connect_status(path); CHECK(send(slow[i], "GET /status HTTP/1.1\r\nX-Slow: ", 30, 0) == 30); }
    usleep(150000);
    int extra = connect_status(path); char byte;
    ssize_t result = recv(extra, &byte, 1, 0);
    CHECK(result == 0 || (result < 0 && errno == ECONNRESET)); close(extra);
    /* Dripping data prevents the ordinary inactivity timeout from firing. */
    for (unsigned i = 0; i < 12; ++i) {
        for (size_t j = 0; j < 8; ++j) send(slow[j], "x", 1, 0);
        usleep(500000);
    }
    CHECK(atomic_load(&heartbeat) > start + 20);
    for (size_t i = 0; i < 8; ++i) {
        result = recv(slow[i], &byte, 1, 0);
        CHECK(result == 0 || (result < 0 && errno == ECONNRESET)); close(slow[i]);
    }
    exchange(path, "GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n", 200, NULL);
    CHECK(event_base_loopbreak(ctx.ev_base) == 0 && pthread_join(thread, NULL) == 0);
    /* The second run exercises simultaneous optional TCP and Unix listeners. */
    CHECK(http_server_init(&ctx, 0, "127.0.0.1"));
    char http_address[96];
    CHECK(edge_listener_http_address(data.http_server->bound_socket, http_address, sizeof(http_address)));
    listeners.http = (edge_listener_entry){true, true, true, http_address};
    CHECK(pthread_create(&thread, NULL, dispatch, ctx.ev_base) == 0);
    tcp_status(&ctx);
    int pending[2] = {connect_status(path), connect_status(path)};
    usleep(150000);
    CHECK(event_base_loopbreak(ctx.ev_base) == 0 && pthread_join(thread, NULL) == 0);
    http_server_clean(&data.http_server);
    event_free(timer); http_server_clean(&data.status_unix_server); event_base_free(ctx.ev_base);
    for (size_t i = 0; i < 2; ++i) { CHECK(recv(pending[i], &byte, 1, 0) == 0); close(pending[i]); }
    CHECK(access(path, F_OK) != 0 && unlink(lock_path) == 0 && rmdir(directory) == 0 && rmdir(root) == 0);
    puts("Unix HTTP status, permissions, lifecycle, redaction and fixed limits passed");
    return 0;
}
