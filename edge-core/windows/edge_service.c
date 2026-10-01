/* SPDX-License-Identifier: Apache-2.0
 * Native SCM adapter. The shared application continues to use the PAL.
 */
#include <windows.h>
#include <shellapi.h>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "edge_service.h"

#define START_WAIT_MS 30000
#define STOP_WAIT_MS 20000
static bool service_mode;
static int core_argc;
static char **core_argv;
static wchar_t *service_name, *data_directory, *log_path;
static HANDLE data_lock = INVALID_HANDLE_VALUE;
static SERVICE_STATUS_HANDLE status_handle;
static SERVICE_STATUS service_status;
static SRWLOCK status_lock = SRWLOCK_INIT;
static ULONGLONG stop_started;
static DWORD stop_control;
static int core_result = EXIT_FAILURE;

bool edge_windows_service_mode(void) { return service_mode; }

/* Serialize status: STOP_PENDING cannot race back to RUNNING. */
static bool report_status_locked(DWORD state, DWORD error, DWORD specific)
{
    service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    service_status.dwCurrentState = state;
    service_status.dwControlsAccepted = state == SERVICE_RUNNING ?
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_PRESHUTDOWN : 0;
    service_status.dwWin32ExitCode = error;
    service_status.dwServiceSpecificExitCode = specific;
    service_status.dwWaitHint = state == SERVICE_START_PENDING ? START_WAIT_MS :
        (state == SERVICE_STOP_PENDING ? STOP_WAIT_MS : 0);
    service_status.dwCheckPoint = state == SERVICE_START_PENDING ?
        service_status.dwCheckPoint + 1 : (state == SERVICE_STOP_PENDING ? 1 : 0);
    return SetServiceStatus(status_handle, &service_status) != 0;
}

void edge_windows_service_checkpoint(void)
{
    if (!service_mode) return;
    AcquireSRWLockExclusive(&status_lock);
    /* Checkpoints reflect actual initialization steps, never a heartbeat. */
    if (service_status.dwCurrentState == SERVICE_START_PENDING)
        report_status_locked(SERVICE_START_PENDING, NO_ERROR, 0);
    ReleaseSRWLockExclusive(&status_lock);
}

bool edge_windows_service_ready(void)
{
    if (!service_mode) return true;
    AcquireSRWLockExclusive(&status_lock);
    bool stopping = service_status.dwCurrentState == SERVICE_STOP_PENDING;
    bool ok = stopping || report_status_locked(SERVICE_RUNNING, NO_ERROR, 0);
    ReleaseSRWLockExclusive(&status_lock);
    if (stopping) edge_core_request_stop();
    return ok;
}

static DWORD WINAPI service_control(DWORD control, DWORD type, void *data, void *context)
{
    (void)type; (void)data; (void)context;
    if (control == SERVICE_CONTROL_INTERROGATE) return NO_ERROR;
    if (control != SERVICE_CONTROL_STOP && control != SERVICE_CONTROL_SHUTDOWN &&
        control != SERVICE_CONTROL_PRESHUTDOWN)
        return ERROR_CALL_NOT_IMPLEMENTED;
    AcquireSRWLockExclusive(&status_lock);
    if (service_status.dwCurrentState == SERVICE_RUNNING) {
        stop_started = GetTickCount64();
        stop_control = control;
        report_status_locked(SERVICE_STOP_PENDING, NO_ERROR, 0);
    }
    ReleaseSRWLockExclusive(&status_lock);
    /* Do not run cloud teardown on the SCM dispatcher thread. */
    edge_core_request_stop();
    return NO_ERROR;
}

static void *token_information(HANDLE token, TOKEN_INFORMATION_CLASS kind)
{
    DWORD size = 0;
    GetTokenInformation(token, kind, NULL, 0, &size);
    if (!size) return NULL;
    void *value = malloc(size);
    if (value && !GetTokenInformation(token, kind, value, size, &size)) {
        free(value); value = NULL;
    }
    return value;
}

static bool contains_sid(const TOKEN_GROUPS *groups, PSID sid, bool require_enabled)
{
    if (!groups) return false;
    for (DWORD i = 0; i < groups->GroupCount; ++i)
        if (EqualSid(groups->Groups[i].Sid, sid) && (!require_enabled ||
            (groups->Groups[i].Attributes & SE_GROUP_ENABLED))) return true;
    return false;
}

/* Fail closed if a service was accidentally configured as administrator or
 * without its restricted SID / minimal privilege allowlist. */
static bool verify_service_identity(void)
{
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_USER *user = token_information(token, TokenUser);
    TOKEN_GROUPS *groups = token_information(token, TokenGroups);
    TOKEN_GROUPS *restricted = token_information(token, TokenRestrictedSids);
    TOKEN_PRIVILEGES *privileges = token_information(token, TokenPrivileges);
    BYTE local_service[SECURITY_MAX_SID_SIZE]; DWORD local_size = sizeof(local_service);
    BYTE sid[SECURITY_MAX_SID_SIZE]; DWORD sid_size = sizeof(sid);
    wchar_t account[256], domain[256]; DWORD domain_size = 256;
    SID_NAME_USE use;
    swprintf_s(account, 256, L"NT SERVICE\\%ls", service_name);
    bool ok = user && privileges &&
        CreateWellKnownSid(WinLocalServiceSid, NULL, local_service, &local_size) &&
        EqualSid(user->User.Sid, local_service) &&
        LookupAccountNameW(NULL, account, sid, &sid_size, domain, &domain_size, &use) &&
        contains_sid(groups, sid, true) && contains_sid(restricted, sid, false);
    LUID traverse;
    if (!LookupPrivilegeValueW(NULL, L"SeChangeNotifyPrivilege", &traverse)) ok = false;
    if (ok) for (DWORD i = 0; i < privileges->PrivilegeCount; ++i) {
        LUID value = privileges->Privileges[i].Luid;
        if (value.LowPart != traverse.LowPart || value.HighPart != traverse.HighPart) {
            ok = false; break;
        }
    }
    free(privileges); free(restricted); free(groups); free(user);
    CloseHandle(token);
    return ok;
}

static bool absolute_local_path(const wchar_t *path)
{
    return path && wcslen(path) >= 3 &&
        ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) &&
        path[1] == L':' && (path[2] == L'\\' || path[2] == L'/');
}

static bool prepare_runtime(void)
{
    if (service_mode && !verify_service_identity()) {
        fprintf(stderr, "Service requires LocalService, its restricted service SID, and only SeChangeNotifyPrivilege.\n");
        SetLastError(ERROR_ACCESS_DENIED); return false;
    }
    if (!data_directory) {
        /* Console mode uses its existing working directory, but participates
         * in the same identity lock even without an explicit --data-dir. */
        DWORD size = GetCurrentDirectoryW(0, NULL);
        data_directory = size ? calloc(size, sizeof(wchar_t)) : NULL;
        if (!data_directory) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return false; }
        if (!GetCurrentDirectoryW(size, data_directory)) return false;
    }
    DWORD attributes = GetFileAttributesW(data_directory);
    if (attributes == INVALID_FILE_ATTRIBUTES) return false;
    if (!(attributes & FILE_ATTRIBUTE_DIRECTORY) || (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        SetLastError(ERROR_INVALID_NAME); return false;
    }
    size_t length = wcslen(data_directory) + 32;
    wchar_t *lock_path = calloc(length, sizeof(wchar_t));
    if (!lock_path) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return false; }
    swprintf_s(lock_path, length, L"%ls\\edge-core.lock", data_directory);
    data_lock = CreateFileW(lock_path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    free(lock_path);
    if (data_lock == INVALID_HANDLE_VALUE) return false;
    if (!SetCurrentDirectoryW(data_directory)) return false;
    /* Existing relative PAL mounts now resolve inside this explicit state dir. */
    if (service_mode) {
        if (!log_path) {
            log_path = calloc(length, sizeof(wchar_t));
            if (!log_path) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return false; }
            swprintf_s(log_path, length, L"%ls\\service.log", data_directory);
        }
        /* MSVC's secure freopen denies sharing when writing. Both streams
         * append to one ACL-protected file, which operators may also tail. */
        if (!_wfreopen(log_path, L"a", stdout) || !_wfreopen(log_path, L"a", stderr)) {
            SetLastError(ERROR_OPEN_FAILED); return false;
        }
        setvbuf(stdout, NULL, _IONBF, 0); setvbuf(stderr, NULL, _IONBF, 0);
    }
    return true;
}

static void report_early_exit(void)
{
    /* Some existing provisioning failures use exit(1) instead of returning. */
    AcquireSRWLockExclusive(&status_lock);
    if (service_status.dwCurrentState != SERVICE_STOPPED)
        report_status_locked(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, EXIT_FAILURE);
    ReleaseSRWLockExclusive(&status_lock);
}

static unsigned __stdcall run_core(void *unused)
{
    (void)unused;
    core_result = edge_core_run(core_argc, core_argv);
    return (unsigned)core_result;
}

static void WINAPI service_main(DWORD argc, wchar_t **argv)
{
    (void)argc; (void)argv; /* Configuration is in SCM's protected ImagePath. */
    status_handle = RegisterServiceCtrlHandlerExW(service_name, service_control, NULL);
    if (!status_handle) return;
    report_status_locked(SERVICE_START_PENDING, NO_ERROR, 0);
    atexit(report_early_exit);
    if (!prepare_runtime()) {
        DWORD error = GetLastError();
        report_status_locked(SERVICE_STOPPED, error ? error : ERROR_ACCESS_DENIED, 0);
        return;
    }
    fprintf(stderr, "Service starting with restricted LocalService identity.\n");
    HANDLE worker = (HANDLE)_beginthreadex(NULL, 0, run_core, NULL, 0, NULL);
    if (!worker) {
        report_status_locked(SERVICE_STOPPED, ERROR_NOT_ENOUGH_MEMORY, 0); return;
    }
    while (WaitForSingleObject(worker, 1000) == WAIT_TIMEOUT) {
        AcquireSRWLockShared(&status_lock);
        ULONGLONG since = stop_started;
        ReleaseSRWLockShared(&status_lock);
        if (since && GetTickCount64() - since >= STOP_WAIT_MS) {
            /* Bounded stop: report failure if graceful cleanup hangs. Never
             * terminate an individual PAL thread or claim false progress. */
            fprintf(stderr, "Graceful service stop exceeded %u ms.\n", STOP_WAIT_MS);
            AcquireSRWLockExclusive(&status_lock);
            report_status_locked(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, ERROR_TIMEOUT);
            ReleaseSRWLockExclusive(&status_lock);
            TerminateProcess(GetCurrentProcess(), ERROR_TIMEOUT);
        }
    }
    CloseHandle(worker);
    if (data_lock != INVALID_HANDLE_VALUE) { CloseHandle(data_lock); data_lock = INVALID_HANDLE_VALUE; }
    AcquireSRWLockShared(&status_lock);
    ULONGLONG since = stop_started;
    DWORD control = stop_control;
    ReleaseSRWLockShared(&status_lock);
    if (since)
        fprintf(stderr, "Service stop control=%lu; elapsed=%llu ms.\n", control, GetTickCount64() - since);
    fprintf(stderr, "Service stopped with application exit code %d.\n", core_result);
    AcquireSRWLockExclusive(&status_lock);
    report_status_locked(SERVICE_STOPPED, core_result ? ERROR_SERVICE_SPECIFIC_ERROR : NO_ERROR,
                         (DWORD)core_result);
    ReleaseSRWLockExclusive(&status_lock);
}

static wchar_t *wide_from_utf8(const char *text)
{
    int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, NULL, 0);
    wchar_t *wide = size ? calloc((size_t)size, sizeof(wchar_t)) : NULL;
    if (wide) MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, wide, size);
    return wide;
}

int main(void)
{
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    /* State/config directories are writable inputs, never DLL search paths. */
    if (!SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32))
        return EXIT_FAILURE;
    int argc = 0;
    wchar_t **wide_argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!wide_argv) return EXIT_FAILURE;
    char **argv = calloc((size_t)argc + 1, sizeof(char *));
    core_argv = calloc((size_t)argc + 1, sizeof(char *));
    if (!argv || !core_argv) return EXIT_FAILURE;
    for (int i = 0; i < argc; ++i) {
        int size = WideCharToMultiByte(CP_UTF8, 0, wide_argv[i], -1, NULL, 0, NULL, NULL);
        argv[i] = size ? malloc((size_t)size) : NULL;
        if (!argv[i]) return EXIT_FAILURE;
        WideCharToMultiByte(CP_UTF8, 0, wide_argv[i], -1, argv[i], size, NULL, NULL);
    }
    LocalFree(wide_argv);
    core_argv[core_argc++] = argv[0];
    bool help = false, version = false;
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--service")) { service_mode = true; continue; }
        wchar_t **target = !strcmp(argv[i], "--service-name") ? &service_name :
            (!strcmp(argv[i], "--data-dir") ? &data_directory :
             (!strcmp(argv[i], "--service-log") ? &log_path : NULL));
        if (target) {
            if (*target || i + 1 == argc || !strncmp(argv[i + 1], "--", 2)) {
                fprintf(stderr, "Missing or duplicate Windows option value.\n"); return EXIT_FAILURE;
            }
            *target = wide_from_utf8(argv[++i]);
            if (!*target) return EXIT_FAILURE;
        } else {
            help |= !strcmp(argv[i], "--help") || !strcmp(argv[i], "-h");
            version |= !strcmp(argv[i], "--version") || !strcmp(argv[i], "-v");
            core_argv[core_argc++] = argv[i];
        }
    }
    if (!service_name) service_name = wide_from_utf8("EdgeCore");
    if (help && !service_mode) {
        puts("Windows options:\n  --service                    Run under Windows SCM.\n"
             "  --service-name <name>        Registered service name [default: EdgeCore].\n"
             "  --data-dir <absolute path>   Existing local state directory; required for service mode.\n"
             "  --service-log <absolute path> Append service output [default: <data-dir>/service.log].\n");
    }
    if ((data_directory && !absolute_local_path(data_directory)) ||
        (log_path && !absolute_local_path(log_path)) ||
        (service_mode && (!data_directory || help || version)) || (!service_mode && log_path)) {
        fprintf(stderr, "Invalid service options; paths must be absolute local drive paths.\n"); return EXIT_FAILURE;
    }
    if (!service_name || !wcslen(service_name) || wcslen(service_name) > 80 ||
        wcsspn(service_name, L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") != wcslen(service_name)) {
        fprintf(stderr, "Invalid service name.\n"); return EXIT_FAILURE;
    }
    int result;
    if (service_mode) {
        SERVICE_TABLE_ENTRYW table[] = {{service_name, service_main}, {NULL, NULL}};
        if (!StartServiceCtrlDispatcherW(table)) {
            fprintf(stderr, "SCM dispatcher failed: %lu. Use console mode outside SCM.\n", GetLastError());
            result = EXIT_FAILURE;
        } else result = core_result;
    } else {
        if (!help && !version && !prepare_runtime()) {
            fprintf(stderr, "Cannot open/lock state directory: Windows error %lu.\n", GetLastError());
            result = EXIT_FAILURE;
        } else result = edge_core_run(core_argc, core_argv);
    }
    if (data_lock != INVALID_HANDLE_VALUE) CloseHandle(data_lock);
    for (int i = 0; i < argc; ++i) free(argv[i]);
    free(argv); free(core_argv); free(service_name); free(data_directory); free(log_path);
    return result;
}
