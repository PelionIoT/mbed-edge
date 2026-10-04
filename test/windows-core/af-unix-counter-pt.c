/* SPDX-License-Identifier: Apache-2.0 */
/* Minimal Windows AF_UNIX PT. WebSocket framing is bounded to 16 KiB. */
#include <winsock2.h>
#include <windows.h>
#include <afunix.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>

#define MESSAGE_LIMIT 16384
static SOCKET connection = INVALID_SOCKET;
static int next_id;
static bool closing;

static bool transfer(char *data, int length, bool writing)
{
    while (length > 0) {
        int count = writing ? send(connection, data, length, 0) : recv(connection, data, length, 0);
        if (count <= 0) { fprintf(stderr, "Socket %s failed: %d\n", writing ? "send" : "receive", WSAGetLastError()); return false; }
        data += count; length -= count;
    }
    return true;
}

static void base64(const unsigned char *bytes, size_t length, char *result)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t out = 0;
    for (size_t offset = 0; offset < length; offset += 3) {
        unsigned bits = (unsigned)bytes[offset] << 16;
        if (offset + 1 < length) bits |= (unsigned)bytes[offset + 1] << 8;
        if (offset + 2 < length) bits |= bytes[offset + 2];
        result[out++] = alphabet[(bits >> 18) & 63];
        result[out++] = alphabet[(bits >> 12) & 63];
        result[out++] = offset + 1 < length ? alphabet[(bits >> 6) & 63] : '=';
        result[out++] = offset + 2 < length ? alphabet[bits & 63] : '=';
    }
    result[out] = 0;
}

static bool header_equals(const char *headers, const char *name, const char *expected)
{
    int matches = 0;
    const char *line = strstr(headers, "\r\n");
    while (line && line[2]) {
        line += 2;
        const char *end = strstr(line, "\r\n");
        if (!end) return false;
        size_t key_length = strlen(name);
        if ((size_t)(end - line) > key_length && !_strnicmp(line, name, key_length) && line[key_length] == ':') {
            const char *value = line + key_length + 1;
            while (value < end && (*value == ' ' || *value == '\t')) ++value;
            while (end > value && (end[-1] == ' ' || end[-1] == '\t')) --end;
            if ((size_t)(end - value) != strlen(expected) || memcmp(value, expected, strlen(expected))) return false;
            ++matches;
        }
        line = strstr(line, "\r\n");
    }
    return matches == 1;
}

static bool handshake(void)
{
    unsigned char nonce[16], digest[20];
    char key[25], expected[29], material[64], request[512], response[4096] = {0};
    HCRYPTPROV provider = 0; HCRYPTHASH hash = 0;
    DWORD digest_length = sizeof(digest);
    bool ok = false;
    if (BCryptGenRandom(NULL, nonce, sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return false;
    base64(nonce, sizeof(nonce), key);
    sprintf_s(material, sizeof(material), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);
    if (CryptAcquireContextW(&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) &&
        CryptCreateHash(provider, CALG_SHA1, 0, 0, &hash) &&
        CryptHashData(hash, (const BYTE *)material, (DWORD)strlen(material), 0) &&
        CryptGetHashParam(hash, HP_HASHVAL, digest, &digest_length, 0)) ok = true;
    if (hash) CryptDestroyHash(hash);
    if (provider) CryptReleaseContext(provider, 0);
    if (!ok) return false;
    base64(digest, sizeof(digest), expected);
    int length = sprintf_s(request, sizeof(request),
        "GET /1/pt HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Protocol: edge_protocol_translator\r\n\r\n", key);
    if (length <= 0 || !transfer(request, length, true)) return false;
    size_t used = 0;
    do {
        if (used + 1 >= sizeof(response) || !transfer(response + used++, 1, false)) return false;
    } while (!strstr(response, "\r\n\r\n"));
    return !strncmp(response, "HTTP/1.1 101 ", 13) &&
        header_equals(response, "Sec-WebSocket-Accept", expected) &&
        header_equals(response, "Sec-WebSocket-Protocol", "edge_protocol_translator");
}

static bool send_frame(unsigned opcode, const char *payload, size_t length)
{
    unsigned char frame[MESSAGE_LIMIT + 8], mask[4];
    size_t offset = 2;
    if (length > MESSAGE_LIMIT || BCryptGenRandom(NULL, mask, sizeof(mask), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return false;
    frame[0] = (unsigned char)(0x80 | opcode);
    if (length < 126) frame[1] = (unsigned char)(0x80 | length);
    else {
        frame[1] = 0x80 | 126; frame[2] = (unsigned char)(length >> 8); frame[3] = (unsigned char)length; offset = 4;
    }
    memcpy(frame + offset, mask, sizeof(mask)); offset += 4;
    for (size_t i = 0; i < length; ++i) frame[offset + i] = (unsigned char)payload[i] ^ mask[i % 4];
    return transfer((char *)frame, (int)(offset + length), true);
}

/* Returns 0 for text, 1 for close, -1 for invalid/failed transport. */
static int receive_message(char *message, size_t *length)
{
    size_t used = 0; bool fragmented = false;
    for (;;) {
        unsigned char header[2];
        if (!transfer((char *)header, 2, false) || (header[0] & 0x70) || (header[1] & 0x80)) return -1;
        unsigned opcode = header[0] & 15;
        bool final = (header[0] & 0x80) != 0;
        uint64_t bytes = header[1] & 127;
        if (bytes >= 126) {
            unsigned char extended[8]; int count = bytes == 126 ? 2 : 8;
            if (!transfer((char *)extended, count, false)) return -1;
            bytes = 0;
            for (int i = 0; i < count; ++i) bytes = (bytes << 8) | extended[i];
        }
        if (opcode >= 8) {
            char control[125];
            if (!final || bytes > sizeof(control) || (opcode != 8 && opcode != 9 && opcode != 10) ||
                !transfer(control, (int)bytes, false)) return -1;
            if (opcode == 9 && !send_frame(10, control, (size_t)bytes)) return -1;
            if (opcode == 8) {
                if (bytes == 1 || (!closing && !send_frame(8, control, (size_t)bytes))) return -1;
                return 1;
            }
            continue;
        }
        if ((opcode != 1 && opcode != 0) || (opcode == 0 && !fragmented) ||
            (opcode == 1 && fragmented) || bytes > MESSAGE_LIMIT - used) return -1;
        if (!transfer(message + used, (int)bytes, false)) return -1;
        used += (size_t)bytes;
        fragmented = !final;
        if (final) { message[used] = 0; *length = used; return 0; }
    }
}

static bool send_json(json_t *document)
{
    char *encoded = document ? json_dumps(document, JSON_COMPACT) : NULL;
    bool ok = encoded && send_frame(1, encoded, strlen(encoded));
    free(encoded);
    return ok;
}

static bool rpc(const char *method, json_t *params)
{
    int id = ++next_id;
    json_t *request = json_pack("{s:s,s:i,s:s,s:o}", "jsonrpc", "2.0", "id", id, "method", method, "params", params);
    bool sent = send_json(request);
    json_decref(request);
    if (!sent) return false;
    char message[MESSAGE_LIMIT + 1]; size_t length;
    for (unsigned count = 0; count < 32; ++count) {
        if (receive_message(message, &length) != 0) return false;
        json_error_t error;
        json_t *response = json_loadb(message, length, JSON_REJECT_DUPLICATES, &error);
        if (!json_is_object(response)) { json_decref(response); return false; }
        if (json_object_get(response, "method")) {
            json_t *incoming_id = json_object_get(response, "id");
            bool ok = true;
            if (incoming_id) {
                json_t *rejection = json_pack("{s:s,s:O,s:{s:i,s:s}}", "jsonrpc", "2.0", "id", incoming_id,
                    "error", "code", -32601, "message", "Read-only counter PT");
                ok = send_json(rejection); json_decref(rejection);
            }
            json_decref(response);
            if (!ok) return false;
            continue;
        }
        const char *result = json_string_value(json_object_get(response, "result"));
        bool ok = json_is_integer(json_object_get(response, "id")) &&
            json_integer_value(json_object_get(response, "id")) == id && result && !strcmp(result, "ok") &&
            !json_object_get(response, "error");
        printf("RPC %s: %s\n", method, message); fflush(stdout);
        json_decref(response);
        return ok;
    }
    return false;
}

static json_t *counter_params(const char *device, unsigned value)
{
    double number = (double)value; uint64_t bits;
    unsigned char binary[8]; char encoded[13];
    memcpy(&bits, &number, sizeof(bits));
    for (int i = 0; i < 8; ++i) binary[i] = (unsigned char)(bits >> (56 - i * 8));
    base64(binary, sizeof(binary), encoded);
    json_t *resource = json_pack("{s:i,s:s,s:i,s:s,s:s}", "resourceId", 5700, "resourceName", "Windows AF_UNIX counter",
                                "operations", 1, "type", "float", "value", encoded);
    json_t *instance = json_pack("{s:i,s:[o]}", "objectInstanceId", 0, "resources", resource);
    json_t *object = json_pack("{s:i,s:[o]}", "objectId", 3300, "objectInstances", instance);
    return json_pack("{s:s,s:[o]}", "deviceId", device, "objects", object);
}

static bool number_option(const wchar_t *text, unsigned *value)
{
    wchar_t *end;
    if (!*text || wcsspn(text, L"0123456789") != wcslen(text)) return false;
    unsigned long parsed = wcstoul(text, &end, 10);
    if (*end || parsed > 1000000) return false;
    *value = (unsigned)parsed;
    return true;
}

int wmain(int argc, wchar_t **argv)
{
    const wchar_t *path = NULL;
    unsigned initial = 1001, steps = 2, interval = 1000;
    bool automatic = false, registered = false, ok = false;
    WSADATA startup;
    SOCKADDR_UN address = {0};
    char device[64], translator[64];
    for (int i = 1; i < argc; ++i) {
        if (!wcscmp(argv[i], L"--help")) {
            puts("af-unix-counter-pt --socket <absolute path> [--initial <integer>] [--auto --steps <count> --interval-ms <ms>]\n"
                 "Without --auto, press Enter to increment or enter q to unregister and stop.");
            return 0;
        }
        if (!wcscmp(argv[i], L"--auto")) { automatic = true; continue; }
        if (i + 1 == argc) return 2;
        if (!wcscmp(argv[i], L"--socket") && !path) path = argv[++i];
        else {
            unsigned *target = !wcscmp(argv[i], L"--initial") ? &initial : !wcscmp(argv[i], L"--steps") ? &steps :
                !wcscmp(argv[i], L"--interval-ms") ? &interval : NULL;
            if (!target || !number_option(argv[++i], target)) return 2;
        }
    }
    if (!path || steps > 1000 || interval > 60000 || initial + steps > 1000000 ||
        wcslen(path) < 4 || !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) ||
        path[1] != L':' || (path[2] != L'\\' && path[2] != L'/') || wcschr(path + 2, L':') ||
        !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path, -1, address.sun_path, sizeof(address.sun_path), NULL, NULL)) {
        fprintf(stderr, "Supply an absolute local --socket path fitting 108 UTF-8 bytes.\n"); return 2;
    }
    if (WSAStartup(MAKEWORD(2, 2), &startup)) return 1;
    connection = socket(AF_UNIX, SOCK_STREAM, 0);
    address.sun_family = AF_UNIX;
    DWORD timeout = 5000;
    if (connection == INVALID_SOCKET ||
        setsockopt(connection, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) ||
        setsockopt(connection, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout)) ||
        connect(connection, (struct sockaddr *)&address, sizeof(address)) || !handshake()) goto done;
    sprintf_s(device, sizeof(device), "windows-af-unix-counter-%lu-%llu", GetCurrentProcessId(), GetTickCount64());
    sprintf_s(translator, sizeof(translator), "af-unix-counter-%lu-%llu", GetCurrentProcessId(), GetTickCount64());
    if (!rpc("protocol_translator_register", json_pack("{s:s}", "name", translator)) ||
        !rpc("device_register", counter_params(device, initial))) goto done;
    registered = true;
    printf("READY device=%s path=/d/%s/3300/0/5700 value=%u\n", device, device, initial); fflush(stdout);
    unsigned value = initial;
    for (unsigned step = 0;; ++step) {
        if (automatic) { if (step == steps) break; Sleep(interval); }
        else {
            char command[32];
            puts("Press Enter to increment; q then Enter to stop."); fflush(stdout);
            if (!fgets(command, sizeof(command), stdin)) goto done;
            if (command[0] == 'q') break;
            if (command[0] != '\n' && command[0] != '\r') { puts("Unrecognized command."); continue; }
        }
        if (value == 1000000 || !rpc("write", counter_params(device, ++value))) goto done;
        printf("COUNTER value=%u path=/d/%s/3300/0/5700\n", value, device); fflush(stdout);
    }
    ok = true;
done:
    if (registered && !rpc("device_unregister", json_pack("{s:s}", "deviceId", device))) ok = false;
    if (connection != INVALID_SOCKET) {
        if (ok) {
            char message[MESSAGE_LIMIT + 1]; size_t length;
            const unsigned char normal_close[] = {3, 232};
            closing = true;
            if (!send_frame(8, (const char *)normal_close, sizeof(normal_close)) || receive_message(message, &length) != 1) ok = false;
        }
        closesocket(connection);
    }
    WSACleanup();
    puts(ok ? "PASS PT registration, counter writes, unregister and WebSocket close" : "FAIL AF_UNIX PT run");
    return ok ? 0 : 1;
}
