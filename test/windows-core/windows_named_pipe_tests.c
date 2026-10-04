/* SPDX-License-Identifier: Apache-2.0 */
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <sddl.h>
#include <aclapi.h>
#include <process.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <jansson.h>
#include "edge_pt_pipe.h"
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "Pipe test line %d: %s (Windows=%lu)\n", __LINE__, #x, GetLastError()); exit(1); } } while (0)
struct session { struct edge_pt_pipe_connection *peer; unsigned phase; };
static LONG opened, closed, successful_runs, reject_write, rejected_writes, failed_cleanup, reverse_replies, queue_limit;

static unsigned counter_value(json_t *params)
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

static void send_json(struct session *session, json_t *document)
{
    CHECK(document);
    char *text = json_dumps(document, JSON_COMPACT);
    CHECK(text);
    size_t length = strlen(text);
    CHECK(edge_pt_pipe_send(session->peer, text, length) == 0);
    json_decref(document);
}

static void *peer_opened(void *context, struct edge_pt_pipe_connection *peer)
{
    (void)context;
    struct session *session = calloc(1, sizeof(*session)); CHECK(session);
    session->peer = peer;
    InterlockedIncrement(&opened);
    return session;
}

static void peer_received(void *context, const char *data, size_t length)
{
    struct session *session = context;
    json_error_t error;
    json_t *request = json_loadb(data, length, JSON_REJECT_DUPLICATES, &error);
    CHECK(json_is_object(request));
    const char *method = json_string_value(json_object_get(request, "method"));
    if (!method) {
        CHECK(!strcmp(json_string_value(json_object_get(request, "id")), "server-probe"));
        CHECK(json_integer_value(json_object_get(json_object_get(request, "error"), "code")) == -32601);
        InterlockedIncrement(&reverse_replies); json_decref(request); return;
    }
    json_t *params = json_object_get(request, "params");
    bool reject = false, registered = false;
    if (!strcmp(method, "stall")) {
        char *text = malloc(EDGE_PT_PIPE_MAX_FRAME); CHECK(text);
        memset(text, 'a', EDGE_PT_PIPE_MAX_FRAME);
        CHECK(edge_pt_pipe_send(session->peer, text, EDGE_PT_PIPE_MAX_FRAME) == 0);
        json_decref(request); return;
    }
    if (!strcmp(method, "flood")) {
        for (unsigned count = 0; count < 5; ++count) {
            char *text = malloc(EDGE_PT_PIPE_MAX_FRAME); CHECK(text);
            memset(text, 'a', EDGE_PT_PIPE_MAX_FRAME);
            if (edge_pt_pipe_send(session->peer, text, EDGE_PT_PIPE_MAX_FRAME)) {
                CHECK(count == 3); InterlockedIncrement(&queue_limit); break;
            }
        }
        json_decref(request); return;
    }
    if (strcmp(method, "echo")) {
        switch (session->phase++) {
            case 0: CHECK(!strcmp(method, "protocol_translator_register")); registered = true; break;
            case 1: CHECK(!strcmp(method, "device_register") && counter_value(params) == 1001); break;
            case 2:
                CHECK(!strcmp(method, "write") && counter_value(params) == 1002);
                reject = InterlockedCompareExchange(&reject_write, 0, 0) != 0;
                if (reject) InterlockedIncrement(&rejected_writes);
                break;
            case 3:
                if (InterlockedCompareExchange(&reject_write, 0, 0)) {
                    CHECK(!strcmp(method, "device_unregister")); InterlockedIncrement(&failed_cleanup); break;
                }
                CHECK(!strcmp(method, "write") && counter_value(params) == 1003); break;
            case 4: CHECK(!strcmp(method, "device_unregister")); InterlockedIncrement(&successful_runs); break;
            default: CHECK(0);
        }
    }
    json_t *response = reject ? json_pack("{s:s,s:O,s:{s:i,s:s}}", "jsonrpc", "2.0", "id", json_object_get(request, "id"),
                                         "error", "code", -30000, "message", "Intentional write failure") :
                              json_pack("{s:s,s:O,s:o}", "jsonrpc", "2.0", "id", json_object_get(request, "id"),
                                        "result", !strcmp(method, "echo") ? json_incref(params) : json_string("ok"));
    send_json(session, response);
    if (registered)
        send_json(session, json_pack("{s:s,s:s,s:s,s:{}}", "jsonrpc", "2.0", "id", "server-probe", "method", "test_server_request", "params"));
    json_decref(request);
}

static void peer_closed(void *session) { free(session); InterlockedIncrement(&closed); }
static unsigned __stdcall dispatch(void *base) { CHECK(event_base_dispatch(base) == 0); return 0; }

static bool transfer(HANDLE pipe, bool writing, void *data, DWORD length, DWORD chunk)
{
    while (length) {
        DWORD amount = length < chunk ? length : chunk, bytes = 0;
        OVERLAPPED operation = {0}; operation.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL); CHECK(operation.hEvent);
        BOOL ok = writing ? WriteFile(pipe, data, amount, &bytes, &operation) : ReadFile(pipe, data, amount, &bytes, &operation);
        if (!ok && GetLastError() == ERROR_IO_PENDING) {
            if (WaitForSingleObject(operation.hEvent, 5000) == WAIT_OBJECT_0)
                ok = GetOverlappedResult(pipe, &operation, &bytes, FALSE);
            else {
                CancelIoEx(pipe, &operation); GetOverlappedResult(pipe, &operation, &bytes, TRUE); ok = FALSE;
            }
        }
        CloseHandle(operation.hEvent);
        if (!ok || !bytes) return false;
        data = (unsigned char *)data + bytes; length -= bytes;
    }
    return true;
}

static DWORD encode(unsigned char *frame, const char *text)
{
    size_t length = strlen(text); CHECK(length && length <= EDGE_PT_PIPE_MAX_FRAME);
    frame[0] = (unsigned char)(length >> 24); frame[1] = (unsigned char)(length >> 16);
    frame[2] = (unsigned char)(length >> 8); frame[3] = (unsigned char)length;
    memcpy(frame + 4, text, length); return (DWORD)length + 4;
}

static void write_frame(HANDLE pipe, const char *text, DWORD chunk)
{
    unsigned char *frame = malloc(strlen(text) + 4); CHECK(frame);
    DWORD length = encode(frame, text); CHECK(transfer(pipe, true, frame, length, chunk)); free(frame);
}

static json_t *read_frame(HANDLE pipe)
{
    unsigned char header[4]; CHECK(transfer(pipe, false, header, 4, 3));
    DWORD length = ((DWORD)header[0] << 24) | ((DWORD)header[1] << 16) | ((DWORD)header[2] << 8) | header[3];
    CHECK(length && length <= EDGE_PT_PIPE_MAX_FRAME);
    char *body = malloc((size_t)length + 1); CHECK(body);
    CHECK(transfer(pipe, false, body, length, 1009)); body[length] = 0;
    json_error_t error; json_t *document = json_loadb(body, length, JSON_REJECT_DUPLICATES, &error); CHECK(document);
    free(body); return document;
}

static HANDLE open_pipe(const wchar_t *name, bool negotiate)
{
    HANDLE pipe = INVALID_HANDLE_VALUE;
    ULONGLONG deadline = GetTickCount64() + 5000;
    do {
        pipe = CreateFileW(name, (FILE_GENERIC_READ | FILE_GENERIC_WRITE) & ~FILE_CREATE_PIPE_INSTANCE,
                           0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
        if (pipe != INVALID_HANDLE_VALUE) break;
        CHECK(GetLastError() == ERROR_PIPE_BUSY || GetLastError() == ERROR_FILE_NOT_FOUND);
        WaitNamedPipeW(name, 50); Sleep(10);
    } while (GetTickCount64() < deadline);
    CHECK(pipe != INVALID_HANDLE_VALUE);
    if (negotiate) {
        write_frame(pipe, "{\"protocol\":\"edge-pt\",\"version\":1}", 1);
        json_t *hello = read_frame(pipe);
        CHECK(!strcmp(json_string_value(json_object_get(hello, "protocol")), "edge-pt"));
        CHECK(json_integer_value(json_object_get(hello, "version")) == 1);
        CHECK(json_integer_value(json_object_get(hello, "maxFrameSize")) == EDGE_PT_PIPE_MAX_FRAME);
        json_decref(hello);
    }
    return pipe;
}

static void expect_closed(HANDLE pipe)
{
    unsigned char byte; CHECK(!transfer(pipe, false, &byte, 1, 1)); CHECK(CloseHandle(pipe));
}

static void wait_closed(LONG count)
{
    ULONGLONG deadline = GetTickCount64() + 5000;
    while (InterlockedCompareExchange(&closed, 0, 0) < count && GetTickCount64() < deadline) Sleep(10);
    CHECK(InterlockedCompareExchange(&closed, 0, 0) >= count);
}

static void run_pt(const wchar_t *executable, const wchar_t *name, DWORD expected)
{
    wchar_t command[2048]; swprintf_s(command, 2048, L"\"%ls\" --pipe \"%ls\" --auto --interval-ms 0", executable, name);
    STARTUPINFOW startup = {sizeof(startup)}; PROCESS_INFORMATION process;
    CHECK(CreateProcessW(executable, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &startup, &process));
    CHECK(WaitForSingleObject(process.hProcess, 10000) == WAIT_OBJECT_0);
    DWORD status; CHECK(GetExitCodeProcess(process.hProcess, &status) && status == expected);
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
}

static HANDLE restricted_client_token(const wchar_t *sid_text)
{
    HANDLE primary, restricted, impersonation;
    PSID sid = NULL;
    CHECK(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &primary));
    CHECK(ConvertStringSidToSidW(sid_text, &sid));
    SID_AND_ATTRIBUTES restriction = {sid, 0};
    CHECK(CreateRestrictedToken(primary, DISABLE_MAX_PRIVILEGE, 0, NULL, 0, NULL, 1, &restriction, &restricted));
    CHECK(DuplicateToken(restricted, SecurityImpersonation, &impersonation));
    CloseHandle(primary); CloseHandle(restricted); LocalFree(sid);
    return impersonation;
}

static void check_client_acl(const wchar_t *name)
{
    LONG previous = InterlockedCompareExchange(&closed, 0, 0);
    HANDLE allowed_token = restricted_client_token(L"S-1-5-11");
    CHECK(ImpersonateLoggedOnUser(allowed_token));
    HANDLE allowed_pipe = CreateFileW(name, (FILE_GENERIC_READ | FILE_GENERIC_WRITE) & ~FILE_CREATE_PIPE_INSTANCE,
                                     0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    CHECK(RevertToSelf()); CHECK(allowed_pipe != INVALID_HANDLE_VALUE);
    write_frame(allowed_pipe, "{\"protocol\":\"edge-pt\",\"version\":1}", 1);
    json_t *hello = read_frame(allowed_pipe); CHECK(json_integer_value(json_object_get(hello, "version")) == 1); json_decref(hello);
    PSECURITY_DESCRIPTOR security = NULL;
    CHECK(GetSecurityInfo(allowed_pipe, SE_KERNEL_OBJECT,
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        NULL, NULL, NULL, NULL, &security) == ERROR_SUCCESS);
    GENERIC_MAPPING mapping = {FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_GENERIC_EXECUTE, FILE_ALL_ACCESS};
    DWORD granted = 0, privilege_size = 2048;
    PRIVILEGE_SET *privileges = malloc(privilege_size); CHECK(privileges);
    BOOL access = TRUE;
    CHECK(AccessCheck(security, allowed_token, FILE_CREATE_PIPE_INSTANCE, &mapping, privileges,
                      &privilege_size, &granted, &access));
    CHECK(!access); /* A PT allowlist grant must not allow another server instance. */
    free(privileges); LocalFree(security); CloseHandle(allowed_token);
    CHECK(CloseHandle(allowed_pipe)); wait_closed(previous + 1);
    HANDLE denied_token = restricted_client_token(L"S-1-5-32-546");
    CHECK(ImpersonateLoggedOnUser(denied_token));
    HANDLE denied_pipe = CreateFileW(name, (FILE_GENERIC_READ | FILE_GENERIC_WRITE) & ~FILE_CREATE_PIPE_INSTANCE,
                                    0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    DWORD denied_error = GetLastError();
    CHECK(RevertToSelf()); CloseHandle(denied_token);
    CHECK(denied_pipe == INVALID_HANDLE_VALUE && denied_error == ERROR_ACCESS_DENIED);
}

int wmain(int argc, wchar_t **argv)
{
    CHECK(argc == 2);
    WSADATA startup; CHECK(WSAStartup(MAKEWORD(2,2), &startup) == 0);
    CHECK(evthread_use_windows_threads() == 0);
    struct event_base *base = event_base_new(); CHECK(base);
    edge_runtime_config config; edge_runtime_config_defaults(&config); config.named_pipe_max_clients = 4;
    /* A restricted client token can reach this explicit allowlist ACE while
     * its restriction prevents use of the server user's full-control ACE. */
    config.named_pipe_client_sid_count = 1;
    strcpy_s(config.named_pipe_client_sids[0], EDGE_PIPE_SID_CAPACITY, "S-1-5-11");
    sprintf_s(config.named_pipe_name, sizeof(config.named_pipe_name), "\\\\.\\pipe\\EdgePTTest-%lu-%llu", GetCurrentProcessId(), GetTickCount64());
    wchar_t name[EDGE_PIPE_NAME_CAPACITY]; CHECK(MultiByteToWideChar(CP_UTF8, 0, config.named_pipe_name, -1, name, EDGE_PIPE_NAME_CAPACITY));
    edge_pt_pipe_callbacks callbacks = {peer_opened, peer_received, peer_closed};
    struct edge_pt_pipe_listener *listener = edge_pt_pipe_start(base, &config, &callbacks, NULL); CHECK(listener);
    CHECK(edge_pt_pipe_start(base, &config, &callbacks, NULL) == NULL);
    HANDLE worker = (HANDLE)_beginthreadex(NULL, 0, dispatch, base, 0, NULL); CHECK(worker);
    run_pt(argv[1], name, 0); wait_closed(1);
    CHECK(successful_runs == 1 && reverse_replies == 1);
    InterlockedExchange(&reject_write, 1);
    run_pt(argv[1], name, 1); wait_closed(2);
    CHECK(rejected_writes == 1 && failed_cleanup == 1 && reverse_replies == 2);
    InterlockedExchange(&reject_write, 0);
    HANDLE first = open_pipe(name, true), second = open_pipe(name, true);
    const char *echo = "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"echo\",\"params\":{\"value\":1002}}";
    unsigned char combined[512]; DWORD length = encode(combined, echo); length += encode(combined + length, echo);
    CHECK(transfer(first, true, combined, length, length)); write_frame(second, echo, 2);
    for (unsigned i = 0; i < 3; ++i) {
        json_t *response = read_frame(i == 2 ? second : first);
        CHECK(json_integer_value(json_object_get(response, "id")) == 7);
        CHECK(json_integer_value(json_object_get(json_object_get(response, "result"), "value")) == 1002);
        json_decref(response);
    }
    char *payload = malloc(63001); CHECK(payload); memset(payload, 'x', 63000); payload[63000] = 0;
    json_t *large = json_pack("{s:s,s:i,s:s,s:{s:s}}", "jsonrpc", "2.0", "id", 8, "method", "echo", "params", "payload", payload);
    char *large_text = json_dumps(large, JSON_COMPACT); CHECK(large_text);
    write_frame(second, large_text, 4096); json_t *large_reply = read_frame(second);
    CHECK(json_string_length(json_object_get(json_object_get(large_reply, "result"), "payload")) == 63000);
    json_decref(large_reply); json_decref(large); free(large_text); free(payload);
    CHECK(CloseHandle(first) && CloseHandle(second)); wait_closed(4);
    const char *invalid_hello[] = {"{\"protocol\":\"edge-pt\",\"version\":2}",
        "{\"protocol\":\"edge-pt\\u0000extra\",\"version\":1}",
        "{\"protocol\":\"edge-pt\",\"version\":1,\"version\":1}"};
    for (unsigned i = 0; i < sizeof(invalid_hello) / sizeof(*invalid_hello); ++i) {
        HANDLE pipe = open_pipe(name, false); write_frame(pipe, invalid_hello[i], 2); expect_closed(pipe);
    }
    const unsigned char invalid_lengths[][4] = {{0,0,0,0}, {0,1,0,1}, {255,255,255,255}};
    for (unsigned i = 0; i < sizeof(invalid_lengths) / sizeof(*invalid_lengths); ++i) {
        HANDLE pipe = open_pipe(name, false);
        CHECK(transfer(pipe, true, (void *)invalid_lengths[i], 4, 1)); expect_closed(pipe);
    }
    HANDLE partial = open_pipe(name, false);
    unsigned char partial_bytes[] = {0,0,0,20,'{','"'};
    CHECK(transfer(partial, true, partial_bytes, sizeof(partial_bytes), 1)); CHECK(CloseHandle(partial));
    HANDLE flood = open_pipe(name, true);
    write_frame(flood, "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"flood\",\"params\":{}}", 1);
    wait_closed(5); CHECK(queue_limit == 1); expect_closed(flood);
    check_client_acl(name);
    LONG previous = InterlockedCompareExchange(&closed, 0, 0);
    HANDLE slow_header = open_pipe(name, true), slow_reader = open_pipe(name, true);
    unsigned char header_byte = 0; CHECK(transfer(slow_header, true, &header_byte, 1, 1));
    write_frame(slow_reader, "{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"stall\",\"params\":{}}", 1);
    ULONGLONG started = GetTickCount64();
    while (InterlockedCompareExchange(&closed, 0, 0) < previous + 2 && GetTickCount64() - started < 7500) Sleep(10);
    CHECK(InterlockedCompareExchange(&closed, 0, 0) >= previous + 2 && GetTickCount64() - started < 7500);
    expect_closed(slow_header); expect_closed(slow_reader);
    HANDLE pending = open_pipe(name, true);
    CHECK(event_base_loopbreak(base) == 0 && WaitForSingleObject(worker, 5000) == WAIT_OBJECT_0); CloseHandle(worker);
    edge_pt_pipe_stop(listener); expect_closed(pending);
    CHECK(opened == closed);
    HANDLE gone = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(gone == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND);
    listener = edge_pt_pipe_start(base, &config, &callbacks, NULL); CHECK(listener); edge_pt_pipe_stop(listener);
    event_base_free(base); WSACleanup();
    puts("PASS native pipe PT counter, RPC errors/reverse requests, framing/version/limits, concurrent clients, SID allow/deny/instance rights, pending-I/O shutdown and ownership");
    return 0;
}
