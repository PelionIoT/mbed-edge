/* SPDX-License-Identifier: Apache-2.0
 * Standalone pipe transport example. This is not the Edge PT RPC server.
 * Records: four-byte big-endian length followed by bounded ASCII command text.
 */
#include <windows.h>
#include <sddl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define MESSAGE_CAPACITY 128
#define IO_TIMEOUT_MS 5000
#define CLIENT_ACCESS ((FILE_GENERIC_READ | FILE_GENERIC_WRITE) & ~FILE_CREATE_PIPE_INSTANCE)
#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s (Windows=%lu)\n", __LINE__, #x, GetLastError()); exit(1); } } while (0)

/* Cancellation does not release the OVERLAPPED or its buffer. Observe completion. */
static BOOL complete(HANDLE pipe, OVERLAPPED *operation, DWORD *bytes, ULONGLONG deadline)
{
    ULONGLONG now = GetTickCount64();
    DWORD wait = WaitForSingleObject(operation->hEvent, now < deadline ? (DWORD)(deadline - now) : 0);
    if (wait == WAIT_OBJECT_0) return GetOverlappedResult(pipe, operation, bytes, FALSE);
    DWORD error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
    CancelIoEx(pipe, operation);
    GetOverlappedResult(pipe, operation, bytes, TRUE);
    SetLastError(error);
    return FALSE;
}

static BOOL transfer(HANDLE pipe, BOOL write, void *buffer, DWORD length, DWORD chunk, ULONGLONG deadline)
{
    BYTE *position = buffer;
    while (length) {
        DWORD amount = length < chunk ? length : chunk;
        DWORD bytes = 0;
        OVERLAPPED operation = {0};
        operation.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!operation.hEvent) return FALSE;
        BOOL ok = write ? WriteFile(pipe, position, amount, &bytes, &operation) :
                          ReadFile(pipe, position, amount, &bytes, &operation);
        if (!ok && GetLastError() == ERROR_IO_PENDING) ok = complete(pipe, &operation, &bytes, deadline);
        DWORD error = GetLastError();
        CloseHandle(operation.hEvent);
        if (!ok || !bytes) { SetLastError(ok ? ERROR_BROKEN_PIPE : error); return FALSE; }
        position += bytes;
        length -= bytes;
        if (GetTickCount64() >= deadline && length) { SetLastError(ERROR_TIMEOUT); return FALSE; }
    }
    return TRUE;
}

static DWORD encode(BYTE *output, const char *text)
{
    size_t size = strlen(text);
    REQUIRE(size > 0 && size < MESSAGE_CAPACITY);
    DWORD length = (DWORD)size;
    output[0] = (BYTE)(length >> 24); output[1] = (BYTE)(length >> 16);
    output[2] = (BYTE)(length >> 8); output[3] = (BYTE)length;
    memcpy(output + 4, text, length);
    return length + 4;
}

static BOOL send_message(HANDLE pipe, const char *text, DWORD chunk)
{
    BYTE frame[MESSAGE_CAPACITY + 4];
    DWORD length = encode(frame, text);
    return transfer(pipe, TRUE, frame, length, chunk, GetTickCount64() + IO_TIMEOUT_MS);
}

static BOOL receive_message(HANDLE pipe, char *text)
{
    BYTE header[4];
    ULONGLONG deadline = GetTickCount64() + IO_TIMEOUT_MS;
    /* Small reads intentionally exercise reassembly even if the kernel coalesces writes. */
    if (!transfer(pipe, FALSE, header, sizeof(header), 3, deadline)) return FALSE;
    DWORD length = ((DWORD)header[0] << 24) | ((DWORD)header[1] << 16) |
                   ((DWORD)header[2] << 8) | header[3];
    if (!length || length >= MESSAGE_CAPACITY) { SetLastError(ERROR_BAD_LENGTH); return FALSE; }
    if (!transfer(pipe, FALSE, text, length, 3, deadline)) return FALSE;
    text[length] = 0;
    if (memchr(text, 0, length)) { SetLastError(ERROR_INVALID_DATA); return FALSE; }
    return TRUE;
}

static BOOL valid_name(const wchar_t *name)
{
    if (!name || wcslen(name) <= 9 || wcslen(name) > 256 || wcsncmp(name, L"\\\\.\\pipe\\", 9)) return FALSE;
    for (const wchar_t *cursor = name + 9; *cursor; ++cursor)
        if (!((*cursor >= L'a' && *cursor <= L'z') || (*cursor >= L'A' && *cursor <= L'Z') ||
              (*cursor >= L'0' && *cursor <= L'9') || *cursor == L'.' || *cursor == L'-' || *cursor == L'_')) return FALSE;
    return TRUE;
}

static PSECURITY_DESCRIPTOR example_security(void)
{
    HANDLE token; DWORD size = 0;
    REQUIRE(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token));
    GetTokenInformation(token, TokenUser, NULL, 0, &size);
    TOKEN_USER *user = malloc(size);
    REQUIRE(user && GetTokenInformation(token, TokenUser, user, size, &size));
    wchar_t *sid = NULL;
    REQUIRE(ConvertSidToStringSidW(user->User.Sid, &sid));
    wchar_t sddl[256];
    REQUIRE(swprintf_s(sddl, 256, L"D:P(A;;0x%08lx;;;%ls)", (DWORD)CLIENT_ACCESS, sid) > 0);
    PSECURITY_DESCRIPTOR security = NULL;
    REQUIRE(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &security, NULL));
    LocalFree(sid); free(user); CloseHandle(token);
    /* Only the invoking user can exchange data. This single-client demo excludes
     * instance creation; a real service needs separate server/client SID grants. */
    return security;
}

static int server(const wchar_t *name)
{
    REQUIRE(valid_name(name));
    SECURITY_ATTRIBUTES attributes = {sizeof(attributes), example_security(), FALSE};
    HANDLE pipe = CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 2, 4096, 4096, 1000, &attributes);
    LocalFree(attributes.lpSecurityDescriptor);
    REQUIRE(pipe != INVALID_HANDLE_VALUE);
    HANDLE duplicate = CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 2, 4096, 4096, 1000, NULL);
    REQUIRE(duplicate == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED);
    HANDLE extra = CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 2, 4096, 4096, 1000, NULL);
    REQUIRE(extra == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED);
    OVERLAPPED connection = {0}; DWORD bytes = 0;
    connection.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    REQUIRE(connection.hEvent);
    BOOL connected = ConnectNamedPipe(pipe, &connection);
    if (!connected) {
        DWORD error = GetLastError();
        if (error == ERROR_PIPE_CONNECTED) connected = TRUE;
        else if (error == ERROR_IO_PENDING) connected = complete(pipe, &connection, &bytes, GetTickCount64() + IO_TIMEOUT_MS);
    }
    REQUIRE(connected);
    CloseHandle(connection.hEvent);
    REQUIRE(send_message(pipe, "ready v1", MESSAGE_CAPACITY));
    unsigned long counter = 0;
    for (;;) {
        char request[MESSAGE_CAPACITY], response[MESSAGE_CAPACITY];
        REQUIRE(receive_message(pipe, request));
        if (!strcmp(request, "stop")) {
            REQUIRE(send_message(pipe, "bye", MESSAGE_CAPACITY));
            BYTE unused;
            REQUIRE(!transfer(pipe, FALSE, &unused, 1, 1, GetTickCount64() + IO_TIMEOUT_MS) &&
                    GetLastError() == ERROR_BROKEN_PIPE);
            break;
        }
        if (!strncmp(request, "set ", 4)) {
            char *end; errno = 0;
            unsigned long value = strtoul(request + 4, &end, 10);
            if (request[4] < '0' || request[4] > '9' || *end || errno || value > 1000000) {
                REQUIRE(send_message(pipe, "error invalid counter", MESSAGE_CAPACITY)); continue;
            }
            counter = value;
        } else if (strcmp(request, "get")) {
            REQUIRE(send_message(pipe, "error unknown command", MESSAGE_CAPACITY)); continue;
        }
        REQUIRE(sprintf_s(response, sizeof(response), "%lu", counter) > 0);
        REQUIRE(send_message(pipe, response, MESSAGE_CAPACITY));
    }
    DisconnectNamedPipe(pipe); CloseHandle(pipe);
    return 0;
}

static void cancel_pending_read(HANDLE pipe)
{
    OVERLAPPED operation = {0}; BYTE byte; DWORD bytes = 0;
    operation.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    REQUIRE(operation.hEvent);
    REQUIRE(!ReadFile(pipe, &byte, 1, &bytes, &operation) && GetLastError() == ERROR_IO_PENDING);
    REQUIRE(CancelIoEx(pipe, &operation));
    REQUIRE(WaitForSingleObject(operation.hEvent, IO_TIMEOUT_MS) == WAIT_OBJECT_0);
    REQUIRE(!GetOverlappedResult(pipe, &operation, &bytes, FALSE) && GetLastError() == ERROR_OPERATION_ABORTED);
    CloseHandle(operation.hEvent);
    puts("PASS pending read cancelled and completion observed");
}

static void expect(HANDLE pipe, const char *value)
{
    char response[MESSAGE_CAPACITY];
    REQUIRE(receive_message(pipe, response) && !strcmp(response, value));
}

static int client(const wchar_t *name, DWORD access)
{
    REQUIRE(valid_name(name));
    ULONGLONG deadline = GetTickCount64() + IO_TIMEOUT_MS;
    while (!WaitNamedPipeW(name, 100)) {
        DWORD error = GetLastError();
        REQUIRE(error == ERROR_FILE_NOT_FOUND || error == ERROR_SEM_TIMEOUT || error == ERROR_PIPE_BUSY);
        REQUIRE(GetTickCount64() < deadline);
        Sleep(10);
    }
    HANDLE pipe = CreateFileW(name, access, 0, NULL, OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL);
    REQUIRE(pipe != INVALID_HANDLE_VALUE);
    puts(access == CLIENT_ACCESS ? "PASS precise C client access accepted" : "PASS generic C client access accepted");
    expect(pipe, "ready v1");
    puts("PASS server-initiated message received");
    cancel_pending_read(pipe);
    for (unsigned long value = 1001; value <= 1003; ++value) {
        char request[32], expected[32];
        REQUIRE(sprintf_s(request, sizeof(request), "set %lu", value) > 0);
        REQUIRE(sprintf_s(expected, sizeof(expected), "%lu", value) > 0);
        if (value == 1001) {
            REQUIRE(send_message(pipe, request, 2)); expect(pipe, expected);
            REQUIRE(send_message(pipe, "get", 2)); expect(pipe, expected);
        } else {
            BYTE combined[2 * (MESSAGE_CAPACITY + 4)];
            DWORD size = encode(combined, request);
            size += encode(combined + size, "get");
            REQUIRE(transfer(pipe, TRUE, combined, size, size, GetTickCount64() + IO_TIMEOUT_MS));
            expect(pipe, expected); expect(pipe, expected);
        }
        printf("COUNTER set/read=%lu\n", value);
    }
    REQUIRE(send_message(pipe, "set invalid", MESSAGE_CAPACITY)); expect(pipe, "error invalid counter");
    REQUIRE(send_message(pipe, "unknown", MESSAGE_CAPACITY)); expect(pipe, "error unknown command");
    REQUIRE(send_message(pipe, "get", MESSAGE_CAPACITY)); expect(pipe, "1003");
    REQUIRE(send_message(pipe, "stop", MESSAGE_CAPACITY)); expect(pipe, "bye");
    CloseHandle(pipe);
    puts("PASS split/coalesced records, counter exchange and clean disconnect");
    return 0;
}

static int self_test(DWORD access)
{
    wchar_t executable[1024], name[256], command[2048];
    DWORD size = GetModuleFileNameW(NULL, executable, 1024);
    REQUIRE(size && size < 1024);
    REQUIRE(swprintf_s(name, 256, L"\\\\.\\pipe\\edge-c-counter-example-%lu-%llu", GetCurrentProcessId(), GetTickCount64()) > 0);
    REQUIRE(swprintf_s(command, 2048, L"\"%ls\" --server \"%ls\"", executable, name) > 0);
    STARTUPINFOW startup = {sizeof(startup)}; PROCESS_INFORMATION process;
    REQUIRE(CreateProcessW(executable, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &startup, &process));
    CloseHandle(process.hThread);
    client(name, access);
    if (WaitForSingleObject(process.hProcess, IO_TIMEOUT_MS) != WAIT_OBJECT_0) {
        TerminateProcess(process.hProcess, 1); WaitForSingleObject(process.hProcess, IO_TIMEOUT_MS);
        CloseHandle(process.hProcess); SetLastError(ERROR_TIMEOUT); REQUIRE(FALSE);
    }
    DWORD status; REQUIRE(GetExitCodeProcess(process.hProcess, &status) && status == 0);
    CloseHandle(process.hProcess);
    HANDLE gone = CreateFileW(name, CLIENT_ACCESS, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    REQUIRE(gone == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND);
    puts("PASS server exited with code 0 and pipe name was reclaimed");
    return 0;
}

int wmain(int argc, wchar_t **argv)
{
    if (argc == 2 && !wcscmp(argv[1], L"--self-test")) return self_test(CLIENT_ACCESS);
    if (argc == 2 && !wcscmp(argv[1], L"--self-test-generic")) return self_test(GENERIC_READ | GENERIC_WRITE);
    if (argc == 3 && !wcscmp(argv[1], L"--server")) return server(argv[2]);
    if (argc == 3 && !wcscmp(argv[1], L"--client")) return client(argv[2], CLIENT_ACCESS);
    fprintf(stderr, "Usage: named-pipe-counter-example --self-test | --self-test-generic | --server <local-pipe-name> | --client <local-pipe-name>\n");
    return 2;
}
