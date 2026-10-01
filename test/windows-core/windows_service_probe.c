/* SPDX-License-Identifier: Apache-2.0
 * Real SCM integration fixture: production adapter and ACL checks without
 * credentials, network dependencies, or destructive writes.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include "edge_service.h"
static HANDLE stop_event;
static bool hang_stop;
bool edge_core_request_stop(void)
{
    return stop_event && (hang_stop || SetEvent(stop_event));
}
static DWORD try_open(const wchar_t *path, DWORD access)
{
    HANDLE file = CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return GetLastError();
    CloseHandle(file); return NO_ERROR;
}
int edge_core_run(int argc, char **argv)
{
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--probe-fail-start")) return 42;
        if (!strcmp(argv[i], "--probe-hang-stop")) hang_stop = true;
    }
    wchar_t binary[MAX_PATH];
    DWORD length = GetModuleFileNameW(NULL, binary, MAX_PATH);
    if (!length || length == MAX_PATH) return 2;
    wchar_t *end = wcsrchr(binary, L'\\');
    if (!end) return 2;
    wcscpy_s(end + 1, MAX_PATH - (size_t)(end + 1 - binary), L"acl-canary.txt");
    DWORD bin_write = try_open(binary, GENERIC_WRITE);
    DWORD config_read = try_open(L"..\\config\\acl-canary.txt", GENERIC_READ);
    DWORD config_write = try_open(L"..\\config\\acl-canary.txt", GENERIC_WRITE);
    DWORD foreign_read = try_open(L"..\\foreign\\acl-canary.txt", GENERIC_READ);
    FILE *marker = NULL;
    char identity[128] = {0};
    if (!fopen_s(&marker, "probe-identity.txt", "r")) {
        if (!fgets(identity, sizeof(identity), marker)) { fclose(marker); return 3; }
        fclose(marker);
    } else {
        if (fopen_s(&marker, "probe-identity.txt", "w")) return 3;
        sprintf_s(identity, sizeof(identity), "%lu-%llu", GetCurrentProcessId(), GetTickCount64());
        fputs(identity, marker); fclose(marker);
    }
    FILE *result = NULL;
    if (fopen_s(&result, "probe.json", "w")) return 3;
    fprintf(result, "{\"binWriteError\":%lu,\"configReadError\":%lu,\"configWriteError\":%lu,"
            "\"foreignReadError\":%lu,\"stateWrite\":true,\"identity\":\"%s\"}",
            bin_write, config_read, config_write, foreign_read, identity);
    fclose(result);
    if (bin_write != ERROR_ACCESS_DENIED || config_read != NO_ERROR ||
        config_write != ERROR_ACCESS_DENIED || foreign_read != ERROR_ACCESS_DENIED) return 4;
    stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!stop_event || !edge_windows_service_ready()) return 5;
    WaitForSingleObject(stop_event, INFINITE);
    CloseHandle(stop_event); stop_event = NULL;
    return 0;
}
