/* SPDX-License-Identifier: Apache-2.0 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "edge_runtime_config.h"

void edge_runtime_config_defaults(edge_runtime_config *config)
{
    memset(config, 0, sizeof(*config));
    strcpy_s(config->tcp_address, sizeof(config->tcp_address), "127.0.0.1:7681");
}

static bool keys_allowed(json_t *object, const char *first, const char *second)
{
    const char *key; json_t *value;
    if (!json_is_object(object)) return false;
    json_object_foreach(object, key, value) {
        if (strcmp(key, first) && (!second || strcmp(key, second))) return false;
    }
    return true;
}

bool edge_runtime_config_load(edge_runtime_config *config, const char *filename)
{
    bool ok = false;
    HANDLE file = INVALID_HANDLE_VALUE;
    wchar_t *wide = NULL;
    char data[32769];
    DWORD bytes = 0;
    LARGE_INTEGER size;
    json_t *root = NULL;
    edge_runtime_config parsed = *config;
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, filename, -1, NULL, 0);
    if (!count || !(wide = calloc((size_t)count, sizeof(*wide)))) goto done;
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, filename, -1, wide, count)) goto done;
    file = CreateFileW(wide, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE || !GetFileSizeEx(file, &size) || size.QuadPart < 1 || size.QuadPart > 32768 ||
        !ReadFile(file, data, (DWORD)size.QuadPart, &bytes, NULL) || bytes != (DWORD)size.QuadPart) goto done;
    json_error_t error;
    size_t bom = bytes >= 3 && (unsigned char)data[0] == 0xef && (unsigned char)data[1] == 0xbb &&
        (unsigned char)data[2] == 0xbf ? 3 : 0;
    root = json_loadb(data + bom, bytes - bom, JSON_REJECT_DUPLICATES, &error);
    if (!root || !keys_allowed(root, "schemaVersion", "pt") ||
        !json_is_integer(json_object_get(root, "schemaVersion")) ||
        json_integer_value(json_object_get(root, "schemaVersion")) != 1) goto done;
    json_t *pt = json_object_get(root, "pt");
    if (pt) {
        if (!keys_allowed(pt, "tcpAddress", "afUnix")) goto done;
        json_t *tcp = json_object_get(pt, "tcpAddress");
        if (tcp) {
            const char *text = json_string_value(tcp); char *end;
            if (!text || json_string_length(tcp) != strlen(text) || strncmp(text, "127.0.0.1:", 10)) goto done;
            const char *digits = text + 10;
            if (!*digits || strspn(digits, "0123456789") != strlen(digits)) goto done;
            unsigned long port = strtoul(digits, &end, 10);
            if (*end || port < 1 || port > 65535 || strlen(text) >= sizeof(parsed.tcp_address)) goto done;
            strcpy_s(parsed.tcp_address, sizeof(parsed.tcp_address), text);
        }
        json_t *unix_config = json_object_get(pt, "afUnix");
        if (unix_config) {
            if (!keys_allowed(unix_config, "enabled", "path")) goto done;
            json_t *enabled = json_object_get(unix_config, "enabled");
            json_t *path = json_object_get(unix_config, "path");
            if (!json_is_boolean(enabled)) goto done;
            parsed.af_unix_enabled = json_is_true(enabled);
            if (path) {
                const char *text = json_string_value(path);
                if (!text || json_string_length(path) != strlen(text) || strlen(text) < 4 || strlen(text) >= sizeof(parsed.af_unix_path) ||
                    !((text[0] >= 'A' && text[0] <= 'Z') || (text[0] >= 'a' && text[0] <= 'z')) ||
                    text[1] != ':' || (text[2] != '/' && text[2] != '\\') || strchr(text + 2, ':')) goto done;
                strcpy_s(parsed.af_unix_path, sizeof(parsed.af_unix_path), text);
            }
            if (parsed.af_unix_enabled && !parsed.af_unix_path[0]) goto done;
#ifndef MBED_EDGE_WINDOWS_AF_UNIX
            if (parsed.af_unix_enabled) {
                fprintf(stderr, "AF_UNIX is unavailable in this Windows target build.\n");
                goto done;
            }
#endif
        }
    }
    *config = parsed;
    ok = true;
done:
    if (!ok) fprintf(stderr, "Invalid or unreadable Edge runtime configuration: %s\n", filename);
    json_decref(root);
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    free(wide);
    return ok;
}
