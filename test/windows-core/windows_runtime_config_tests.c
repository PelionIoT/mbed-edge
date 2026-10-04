/* SPDX-License-Identifier: Apache-2.0 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "edge_runtime_config.h"
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "Runtime config line %d: %s\n", __LINE__, #x); exit(1); } } while (0)

static void write_config(const wchar_t *path, const char *text)
{
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written;
    CHECK(file != INVALID_HANDLE_VALUE);
    CHECK(WriteFile(file, text, (DWORD)strlen(text), &written, NULL) && written == strlen(text));
    CloseHandle(file);
}

int wmain(int argc, wchar_t **argv)
{
    CHECK(argc == 2);
    wchar_t path[512]; char utf8[1024];
    swprintf_s(path, 512, L"%ls/runtime-config-%lu-\x00e9.json", argv[1], GetCurrentProcessId());
    CHECK(WideCharToMultiByte(CP_UTF8, 0, path, -1, utf8, sizeof(utf8), NULL, NULL));
    edge_runtime_config config;
    edge_runtime_config_defaults(&config);
    CHECK(!config.af_unix_enabled && !strcmp(config.tcp_address, "127.0.0.1:7681"));
    write_config(path, "{\"schemaVersion\":1,\"pt\":{\"tcpAddress\":\"127.0.0.1:17777\",\"afUnix\":{\"enabled\":false}}}");
    CHECK(edge_runtime_config_load(&config, utf8));
    CHECK(!config.af_unix_enabled && !strcmp(config.tcp_address, "127.0.0.1:17777"));
    write_config(path, "\xef\xbb\xbf{\"schemaVersion\":1}");
    CHECK(edge_runtime_config_load(&config, utf8));
    const char *invalid[] = {
        "{}", "[]", "{\"schemaVersion\":2}", "{\"schemaVersion\":1,\"unknown\":true}",
        "{\"schemaVersion\":1,\"schemaVersion\":1}",
        "{\"schemaVersion\":1,\"pt\":{\"tcpAddress\":\"0.0.0.0:7681\"}}",
        "{\"schemaVersion\":1,\"pt\":{\"tcpAddress\":\"127.0.0.1:0\"}}",
        "{\"schemaVersion\":1,\"pt\":{\"tcpAddress\":\"127.0.0.1:+7681\"}}",
        "{\"schemaVersion\":1,\"pt\":{\"tcpAddress\":\"127.0.0.1:65536\"}}",
        "{\"schemaVersion\":1,\"pt\":{\"tcpAddress\":\"127.0.0.1:7681\\u0000other\"}}",
        "{\"schemaVersion\":1,\"pt\":{\"afUnix\":{\"enabled\":true}}}",
        "{\"schemaVersion\":1,\"pt\":{\"afUnix\":{\"enabled\":\"true\"}}}",
        "{\"schemaVersion\":1,\"pt\":{\"afUnix\":{\"enabled\":true,\"path\":\"relative.sock\"}}}",
        "{\"schemaVersion\":1,\"pt\":{\"afUnix\":{\"enabled\":true,\"path\":\"C:/pt.sock:stream\"}}}",
        "{\"schemaVersion\":1,\"pt\":{\"afUnix\":{\"enabled\":false,\"path\":42}}}",
        "{\"schemaVersion\":1,\"pt\":{\"afUnix\":{\"enabled\":false,\"paths\":\"C:/pt.sock\"}}}"
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        edge_runtime_config before = config;
        write_config(path, invalid[i]);
        CHECK(!edge_runtime_config_load(&config, utf8));
        CHECK(memcmp(&before, &config, sizeof(config)) == 0);
    }
    write_config(path, "{\"schemaVersion\":1,\"pt\":{\"afUnix\":{\"enabled\":true,\"path\":\"C:/ipc/pt.sock\"}}}");
#ifdef MBED_EDGE_WINDOWS_AF_UNIX
    CHECK(edge_runtime_config_load(&config, utf8));
    CHECK(config.af_unix_enabled && !strcmp(config.af_unix_path, "C:/ipc/pt.sock"));
#else
    CHECK(!edge_runtime_config_load(&config, utf8));
#endif
    CHECK(DeleteFileW(path));
    CHECK(!edge_runtime_config_load(&config, utf8));
    puts("PASS runtime settings, Unicode filename, validation and build capability");
    return 0;
}
