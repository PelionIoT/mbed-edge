/* SPDX-License-Identifier: Apache-2.0 */
#include <winsock2.h>
#include <windows.h>
#include <afunix.h>
#include <wincrypt.h>
#include <process.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <jansson.h>
#include "libwebsockets.h"
#include "edge_pt_unix.h"
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "AF_UNIX test line %d: %s (Win=%lu WSA=%d)\n", __LINE__, #x, GetLastError(), WSAGetLastError()); exit(1); } } while (0)

struct session { unsigned char output[LWS_PRE + 1024]; size_t output_length; char input[2048]; size_t input_length; unsigned phase; };
static LONG successful_runs, closed_sessions, reject_write, rejected_writes, failed_run_cleanup;

static unsigned resource_value(json_t *params)
{
    json_t *object = json_array_get(json_object_get(params, "objects"), 0);
    json_t *instance = json_array_get(json_object_get(object, "objectInstances"), 0);
    json_t *resource = json_array_get(json_object_get(instance, "resources"), 0);
    CHECK(json_integer_value(json_object_get(object, "objectId")) == 3300);
    CHECK(json_integer_value(json_object_get(instance, "objectInstanceId")) == 0);
    CHECK(json_integer_value(json_object_get(resource, "resourceId")) == 5700);
    CHECK(json_integer_value(json_object_get(resource, "operations")) == 1);
    CHECK(!strcmp(json_string_value(json_object_get(resource, "type")), "float"));
    const char *encoded = json_string_value(json_object_get(resource, "value"));
    unsigned char bytes[8]; DWORD size = sizeof(bytes);
    CHECK(encoded && CryptStringToBinaryA(encoded, 0, CRYPT_STRING_BASE64, bytes, &size, NULL, NULL) && size == 8);
    uint64_t bits = 0; double number;
    for (int i = 0; i < 8; ++i) bits = (bits << 8) | bytes[i];
    memcpy(&number, &bits, sizeof(number));
    CHECK(number >= 1001 && number <= 1003);
    return (unsigned)number;
}

static int protocol(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *data, size_t length)
{
    struct session *session = user;
    if (reason == LWS_CALLBACK_RECEIVE) {
        CHECK(length <= sizeof(session->input) - session->input_length);
        memcpy(session->input + session->input_length, data, length); session->input_length += length;
        if (!lws_is_final_fragment(wsi) || lws_remaining_packet_payload(wsi)) return 0;
        json_error_t error;
        json_t *request = json_loadb(session->input, session->input_length, JSON_REJECT_DUPLICATES, &error);
        CHECK(json_is_object(request));
        session->input_length = 0;
        const char *method = json_string_value(json_object_get(request, "method"));
        json_t *params = json_object_get(request, "params");
        CHECK(method && json_is_object(params));
        bool reject = false;
        switch (session->phase++) {
            case 0: CHECK(!strcmp(method, "protocol_translator_register")); CHECK(json_is_string(json_object_get(params, "name"))); break;
            case 1: CHECK(!strcmp(method, "device_register")); CHECK(resource_value(params) == 1001); break;
            case 2:
                CHECK(!strcmp(method, "write")); CHECK(resource_value(params) == 1002);
                reject = InterlockedCompareExchange(&reject_write, 0, 0) != 0;
                if (reject) InterlockedIncrement(&rejected_writes);
                break;
            case 3:
                if (InterlockedCompareExchange(&reject_write, 0, 0)) {
                    CHECK(!strcmp(method, "device_unregister")); InterlockedIncrement(&failed_run_cleanup); break;
                }
                CHECK(!strcmp(method, "write")); CHECK(resource_value(params) == 1003); break;
            case 4: CHECK(!strcmp(method, "device_unregister")); InterlockedIncrement(&successful_runs); break;
            default: CHECK(0);
        }
        json_t *reply = reject ? json_pack("{s:s,s:O,s:{s:i,s:s}}", "jsonrpc", "2.0", "id", json_object_get(request, "id"),
                                            "error", "code", -30000, "message", "Intentional write failure") :
            json_pack("{s:s,s:O,s:s}", "jsonrpc", "2.0", "id", json_object_get(request, "id"), "result", "ok");
        char *encoded = json_dumps(reply, JSON_COMPACT);
        CHECK(encoded && strlen(encoded) < 1024 && session->output_length == 0);
        session->output_length = strlen(encoded);
        memcpy(session->output + LWS_PRE, encoded, session->output_length);
        free(encoded); json_decref(reply); json_decref(request);
        lws_callback_on_writable(wsi);
    } else if (reason == LWS_CALLBACK_SERVER_WRITEABLE && session->output_length) {
        CHECK(lws_write(wsi, session->output + LWS_PRE, session->output_length, LWS_WRITE_TEXT) == (int)session->output_length);
        session->output_length = 0;
    } else if (reason == LWS_CALLBACK_CLOSED) InterlockedIncrement(&closed_sessions);
    return 0;
}

static unsigned __stdcall dispatch(void *base) { CHECK(event_base_dispatch(base) == 0); return 0; }

static void run_pt(const wchar_t *executable, const wchar_t *socket_path, DWORD expected)
{
    wchar_t command[2048];
    swprintf_s(command, 2048, L"\"%ls\" --socket \"%ls\" --auto --interval-ms 0", executable, socket_path);
    STARTUPINFOW startup = {sizeof(startup)}; PROCESS_INFORMATION process;
    CHECK(CreateProcessW(executable, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &startup, &process));
    CHECK(WaitForSingleObject(process.hProcess, 10000) == WAIT_OBJECT_0);
    DWORD status; CHECK(GetExitCodeProcess(process.hProcess, &status) && status == expected);
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
}

int wmain(int argc, wchar_t **argv)
{
    CHECK(argc == 3);
    WSADATA startup; CHECK(WSAStartup(MAKEWORD(2,2), &startup) == 0);
    CHECK(evthread_use_windows_threads() == 0);
    struct event_base *base = event_base_new(); CHECK(base);
    void *loops[] = {base};
    struct lws_protocols protocols[] = {{"edge_protocol_translator", protocol, sizeof(struct session), 1024, 0, NULL, 0}, {NULL, NULL, 0, 0, 0, NULL, 0}};
    struct lws_context_creation_info info = {0};
    info.port = 0; info.iface = "127.0.0.1"; info.protocols = protocols; info.foreign_loops = loops;
    info.options = LWS_SERVER_OPTION_LIBEVENT; info.gid = info.uid = -1;
    lws_set_log_level(LLL_ERR | LLL_WARN, NULL);
    struct lws_context *context = lws_create_context(&info); CHECK(context);
    wchar_t directory[512], path[512], lock[520]; char utf8[1024];
    swprintf_s(directory, 512, L"%ls/af-unix-%lu-\x00e9", argv[2], GetCurrentProcessId());
    CHECK(CreateDirectoryW(directory, NULL));
    swprintf_s(path, 512, L"%ls/pt.sock", directory);
    swprintf_s(lock, 520, L"%ls.lock", path);
    CHECK(WideCharToMultiByte(CP_UTF8, 0, path, -1, utf8, sizeof(utf8), NULL, NULL));
    CHECK(edge_pt_unix_path_valid(utf8));
    CHECK(!edge_pt_unix_path_valid(NULL) && !edge_pt_unix_path_valid("") && !edge_pt_unix_path_valid("C:"));
    CHECK(!edge_pt_unix_path_valid("relative.sock") && !edge_pt_unix_path_valid("C:/x:stream"));
    char too_long[200]; memset(too_long, 'a', sizeof(too_long)); memcpy(too_long, "C:/", 3); too_long[199] = 0;
    CHECK(!edge_pt_unix_path_valid(too_long));
    HANDLE ordinary = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(ordinary != INVALID_HANDLE_VALUE); CloseHandle(ordinary);
    CHECK(edge_pt_unix_start(base, context, utf8) == NULL);
    CHECK(GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES && DeleteFileW(path));
    struct edge_pt_unix_listener *listener = edge_pt_unix_start(base, context, utf8); CHECK(listener);
    CHECK(edge_pt_unix_start(base, context, utf8) == NULL);
    HANDLE worker = (HANDLE)_beginthreadex(NULL, 0, dispatch, base, 0, NULL); CHECK(worker);
    run_pt(argv[1], path, 0);
    CHECK(InterlockedCompareExchange(&successful_runs, 0, 0) == 1);
    InterlockedExchange(&reject_write, 1);
    run_pt(argv[1], path, 1);
    CHECK(InterlockedCompareExchange(&rejected_writes, 0, 0) == 1);
    CHECK(InterlockedCompareExchange(&failed_run_cleanup, 0, 0) == 1);
    CHECK(event_base_loopbreak(base) == 0 && WaitForSingleObject(worker, 5000) == WAIT_OBJECT_0);
    CloseHandle(worker);
    CHECK(InterlockedCompareExchange(&closed_sessions, 0, 0) >= 1);
    edge_pt_unix_stop(listener);
    CHECK(GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES);
    /* An abandoned AF_UNIX file is recovered; regular files were preserved above. */
    SOCKADDR_UN stale_address = {0}; stale_address.sun_family = AF_UNIX;
    CHECK(strlen(utf8) < sizeof(stale_address.sun_path)); strcpy_s(stale_address.sun_path, sizeof(stale_address.sun_path), utf8);
    SOCKET foreign = socket(AF_UNIX, SOCK_STREAM, 0); CHECK(foreign != INVALID_SOCKET);
    CHECK(bind(foreign, (struct sockaddr *)&stale_address, sizeof(stale_address)) == 0 && listen(foreign, 4) == 0);
    CHECK(edge_pt_unix_start(base, context, utf8) == NULL);
    CHECK(GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES);
    closesocket(foreign); CHECK(DeleteFileW(path));
    SOCKET stale = socket(AF_UNIX, SOCK_STREAM, 0); CHECK(stale != INVALID_SOCKET);
    CHECK(bind(stale, (struct sockaddr *)&stale_address, sizeof(stale_address)) == 0); closesocket(stale);
    listener = edge_pt_unix_start(base, context, utf8); CHECK(listener);
    edge_pt_unix_stop(listener);
    CHECK(GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES);
    lws_context_destroy(context); event_base_free(base);
    CHECK(DeleteFileW(lock) && RemoveDirectoryW(directory));
    WSACleanup();
    puts("PASS AF_UNIX PT JSON-RPC, counter encoding, RPC failure, Unicode, ownership and stale cleanup");
    return 0;
}
