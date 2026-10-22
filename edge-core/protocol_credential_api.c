/* SPDX-License-Identifier: Apache-2.0 */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "common/edge_platform.h"
#include "edge-core/protocol_api_internal.h"
#include "edge-core/protocol_credential_api.h"
#include "edge-core/edge_server.h"
#include "common/apr_base64.h"
#include "key_config_manager.h"
#include "cs_pal_crypto.h"
#include "eventOS_event.h"
#include "eventOS_scheduler.h"
#include "jsonrpc/jsonrpc.h"
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_USE_OPENSSL
#include <openssl/evp.h>
#else
#include <mbedtls/gcm.h>
#endif

#define VALUE_LIMIT 4096
#define PACKET_LIMIT 6144
#define DENIED -32040
#define STORAGE_ERROR -32043
static int8_t tasklet = -1;
static palMutexID_t pending_mutex;
static unsigned pending;

typedef struct {
    bool counted;
    connection_id_t connection;
    char *id;
    char scope[33];
    uint8_t challenge[32];
    uint64_t sequence;
    uint8_t packet[PACKET_LIMIT];
    size_t length;
} credential_request;

static void erase(void *data, size_t length)
{
    volatile unsigned char *p = data;
    while (length--) *p++ = 0;
}

static json_t *bounded_json(const uint8_t *data, size_t length)
{
    unsigned depth = 0;
    bool quoted = false, escaped = false;
    for (size_t i = 0; i < length; ++i) {
        uint8_t c = data[i];
        if (quoted) {
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"') quoted = false;
        } else if (c == '"') quoted = true;
        else if (c == '{' || c == '[') { if (++depth > 8) return NULL; }
        else if (c == '}' || c == ']') { if (!depth) return NULL; --depth; }
    }
    if (quoted || depth) return NULL;
    return json_loadb((const char *)data, length, JSON_REJECT_DUPLICATES, NULL);
}

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#endif

#ifdef _WIN32
static bool private_acl(HANDLE file)
{
    HANDLE token = NULL;
    PSECURITY_DESCRIPTOR security = NULL;
    PSID owner = NULL, system = NULL, administrators = NULL, owner_rights = NULL;
    PACL acl = NULL;
    TOKEN_USER *user = NULL; TOKEN_GROUPS *groups = NULL; DWORD size = 0;
    bool ok = false;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) goto end;
    GetTokenInformation(token, TokenUser, NULL, 0, &size);
    user = size ? malloc(size) : NULL;
    if (!user || !GetTokenInformation(token, TokenUser, user, size, &size) ||
        !ConvertStringSidToSidW(L"S-1-5-18", &system) || !ConvertStringSidToSidW(L"S-1-5-32-544", &administrators) ||
        !ConvertStringSidToSidW(L"S-1-3-4", &owner_rights) ||
        GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                         &owner, NULL, &acl, NULL, &security) != ERROR_SUCCESS || !acl || !owner) goto end;
    GetTokenInformation(token, TokenGroups, NULL, 0, &size);
    groups = size ? malloc(size) : NULL;
    if (!groups || !GetTokenInformation(token, TokenGroups, groups, size, &size)) goto end;
    PSID service = NULL;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    for (DWORD i = 0; i < groups->GroupCount; ++i) {
        PSID sid = groups->Groups[i].Sid;
        if ((groups->Groups[i].Attributes & SE_GROUP_ENABLED) && *GetSidSubAuthorityCount(sid) == 6 &&
            *GetSidSubAuthority(sid, 0) == 80 && !memcmp(GetSidIdentifierAuthority(sid), &nt, sizeof(nt))) {
            service = sid; break;
        }
    }
    if (!EqualSid(owner, user->User.Sid) && !EqualSid(owner, system) && !EqualSid(owner, administrators) &&
        (!service || !EqualSid(owner, service))) goto end;
    for (DWORD i = 0; i < acl->AceCount; ++i) {
        ACCESS_ALLOWED_ACE *ace = NULL;
        if (!GetAce(acl, i, (void **)&ace)) goto end;
        if (ace->Header.AceFlags & INHERIT_ONLY_ACE) continue;
        if (ace->Header.AceType == ACCESS_DENIED_ACE_TYPE) continue;
        if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE) goto end;
        PSID sid = (PSID)&ace->SidStart;
        if (!EqualSid(sid, owner_rights) && !EqualSid(sid, user->User.Sid) && !EqualSid(sid, system) && !EqualSid(sid, administrators) &&
            (!service || !EqualSid(sid, service))) goto end;
    }
    ok = true;
end:
    free(groups); free(user); LocalFree(owner_rights); LocalFree(system); LocalFree(administrators); LocalFree(security);
    if (token) CloseHandle(token);
    return ok;
}
static HANDLE private_open(const char *path, bool directory)
{
    wchar_t wide[32768]; BY_HANDLE_FILE_INFORMATION info;
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide, 32768)) return INVALID_HANDLE_VALUE;
    HANDLE file = CreateFileW(wide, GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | (directory ? FILE_FLAG_BACKUP_SEMANTICS : 0), NULL);
    if (file == INVALID_HANDLE_VALUE) return file;
    if (!GetFileInformationByHandle(file, &info) || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT ||
        !!(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != directory ||
        (!directory && info.nNumberOfLinks != 1) || !private_acl(file)) {
        CloseHandle(file); return INVALID_HANDLE_VALUE;
    }
    return file;
}
#else
static int private_open(const char *path, bool directory)
{
    int file = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | (directory ? O_DIRECTORY : 0));
    struct stat info;
    if (file < 0) return file;
    if (fstat(file, &info) || (directory ? !S_ISDIR(info.st_mode) : !S_ISREG(info.st_mode) || info.st_nlink != 1) ||
        (info.st_uid != geteuid() && info.st_uid != 0) || (info.st_mode & 0077)) {
        close(file); return -1;
    }
    return file;
}
#endif

static bool private_storage(void)
{
    char path[PAL_MAX_FILE_AND_FOLDER_LENGTH];
    pal_fsStorageID_t partitions[] = {PAL_FS_PARTITION_PRIMARY, PAL_FS_PARTITION_SECONDARY};
    for (size_t i = 0; i < 2; ++i) {
        if (pal_fsGetMountPoint(partitions[i], sizeof(path), path) != PAL_SUCCESS) return false;
#ifdef _WIN32
        HANDLE file = private_open(path, true);
        if (file == INVALID_HANDLE_VALUE) return false;
        CloseHandle(file);
#else
        int file = private_open(path, true);
        if (file < 0) return false;
        close(file);
#endif
    }
    return true;
}

static json_t *read_private(const char *path)
{
    uint8_t *data = NULL; size_t length = 0;
    json_t *result = NULL;
#ifdef _WIN32
    HANDLE file = private_open(path, false);
    LARGE_INTEGER size; DWORD bytes = 0;
    if (file == INVALID_HANDLE_VALUE || !GetFileSizeEx(file, &size) || size.QuadPart < 1 || size.QuadPart > 65536) goto end;
    length = (size_t)size.QuadPart;
    data = malloc(length);
    if (!data || !ReadFile(file, data, (DWORD)length, &bytes, NULL) || bytes != length) goto end;
#else
    int file = private_open(path, false);
    struct stat info;
    if (file < 0 || fstat(file, &info) || info.st_size < 1 || info.st_size > 65536) goto end;
    length = (size_t)info.st_size;
    data = malloc(length);
    if (!data) goto end;
    size_t offset = 0;
    while (offset < length) {
        ssize_t n = read(file, data + offset, length - offset);
        if (n <= 0) goto end;
        offset += (size_t)n;
    }
#endif
    size_t bom = length >= 3 && data[0] == 0xef && data[1] == 0xbb && data[2] == 0xbf ? 3 : 0;
    result = bounded_json(data + bom, length - bom);
end:
    if (data) { erase(data, length); free(data); }
#ifdef _WIN32
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
#else
    if (file >= 0) close(file);
#endif
    return result;
}

static void clear_field(json_t *object, const char *field)
{
    json_t *value = json_object_get(object, field);
    const char *text = json_string_value(value);
    if (text) erase((void *)text, json_string_length(value));
}

static bool identifier(const char *value)
{
    size_t n = value ? strlen(value) : 0;
    return n > 0 && n <= 32 &&
        strspn(value, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-") == n &&
        ((value[0] >= 'a' && value[0] <= 'z') || (value[0] >= 'A' && value[0] <= 'Z'));
}

static const char *string_field(json_t *object, const char *key)
{
    json_t *value = json_object_get(object, key);
    const char *text = json_string_value(value);
    return text && strlen(text) == json_string_length(value) ? text : NULL;
}

static bool fields(json_t *object, const char *allowed)
{
    const char *key; json_t *value;
    if (!json_is_object(object)) return false;
    json_object_foreach(object, key, value) {
        char match[80];
        if (strlen(key) > 64 || strchr(key, '|')) return false;
        snprintf(match, sizeof(match), "|%s|", key);
        if (!strstr(allowed, match)) return false;
    }
    return true;
}

static json_t *encode(const uint8_t *data, size_t size)
{
    char *text = malloc((size_t)apr_base64_encode_len((int)size));
    if (!text) return NULL;
    apr_base64_encode_binary(text, data, (int)size);
    json_t *value = json_string(text);
    erase(text, strlen(text)); free(text);
    return value;
}

static bool decode(const char *text, uint8_t *output, size_t capacity, size_t *size)
{
    if (!text || strlen(text) > ((capacity + 2) / 3) * 4 || strlen(text) % 4) return false;
    size_t n = strlen(text);
    for (size_t i = 0; i < n; ++i)
        if (!strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", text[i])) return false;
    /* The decoder may write up to three bytes per quartet, including padding. */
    uint8_t buffer[PACKET_LIMIT + 3];
    if (n > ((sizeof(buffer) - 2) / 3) * 4) return false;
    int length = apr_base64_decode_binary(buffer, text);
    bool ok = length >= 0 && (size_t)length <= capacity;
    json_t *canonical = ok ? encode(buffer, (size_t)length) : NULL;
    ok = ok && canonical && !strcmp(text, json_string_value(canonical));
    if (ok) { memcpy(output, buffer, (size_t)length); *size = (size_t)length; }
    json_decref(canonical); erase(buffer, sizeof(buffer));
    return ok;
}

static bool aead(bool encrypt, const uint8_t key[32], const uint8_t nonce[12],
                 const uint8_t *aad, size_t aad_size, uint8_t *data, size_t size, uint8_t tag[16])
{
#ifdef MBED_CONF_MBED_CLOUD_CLIENT_USE_OPENSSL
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int length = 0, final = 0;
    bool ok = ctx && EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL, encrypt) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
        EVP_CipherInit_ex(ctx, NULL, NULL, key, nonce, encrypt) == 1 &&
        EVP_CipherUpdate(ctx, NULL, &length, aad, (int)aad_size) == 1 &&
        EVP_CipherUpdate(ctx, data, &length, data, (int)size) == 1;
    if (ok && !encrypt) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) == 1;
    if (ok) ok = EVP_CipherFinal_ex(ctx, data + length, &final) == 1;
    if (ok && encrypt) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1;
    EVP_CIPHER_CTX_free(ctx);
#else
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    uint8_t *output = malloc(size ? size : 1);
    int status = output ? mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256) : -1;
    if (!status) {
        if (encrypt) status = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, size, nonce, 12,
                                                      aad, aad_size, data, output, 16, tag);
        else status = mbedtls_gcm_auth_decrypt(&ctx, size, nonce, 12, aad, aad_size, tag, 16, data, output);
    }
    if (!status) memcpy(data, output, size);
    if (output) { erase(output, size); free(output); }
    mbedtls_gcm_free(&ctx);
    bool ok = status == 0;
#endif
    return ok;
}

static size_t associated(const credential_request *ctx, bool response, uint8_t output[128])
{
    const char *domain = response ? "edge-credential-v1:response" : "edge-credential-v1:request";
    size_t n = strlen(domain) + 1;
    memcpy(output, domain, n);
    memcpy(output + n, ctx->scope, strlen(ctx->scope) + 1); n += strlen(ctx->scope) + 1;
    memcpy(output + n, ctx->challenge, 32); n += 32;
    for (unsigned i = 0; i < 8; ++i) output[n++] = (uint8_t)(ctx->sequence >> (56 - i * 8));
    return n;
}

static int failure(json_t **result, int code)
{
    *result = jsonrpc_error_object(code, code == DENIED ? "Credential access denied" : "Credential request failed", NULL);
    return JSONRPC_RETURN_CODE_ERROR;
}

static bool load(const char *name, uint8_t *buffer, size_t capacity, size_t *size, bool *missing)
{
    *missing = false;
    kcm_status_e status = kcm_item_get_data_size((const uint8_t *)name, strlen(name), KCM_CONFIG_ITEM, size);
    if (status == KCM_STATUS_ITEM_NOT_FOUND) { *missing = true; *size = 0; return true; }
    if (status != KCM_STATUS_SUCCESS || *size > capacity) return false;
    return kcm_item_get_data((const uint8_t *)name, strlen(name), KCM_CONFIG_ITEM, buffer, capacity, size) == KCM_STATUS_SUCCESS;
}

static bool policy_valid(json_t *policy)
{
    uint8_t key[32]; size_t size = 0;
    if (!fields(policy, "|namespace||key||items|") || !identifier(string_field(policy, "namespace")) ||
        !decode(string_field(policy, "key"), key, sizeof(key), &size) || size != sizeof(key)) {
        erase(key, sizeof(key)); return false;
    }
    erase(key, sizeof(key));
    json_t *items = json_object_get(policy, "items");
    if (!json_is_array(items) || json_array_size(items) < 1 || json_array_size(items) > 32) return false;
    for (size_t i = 0; i < json_array_size(items); ++i) {
        json_t *item = json_array_get(items, i);
        const char *name = json_string_value(item);
        if (!identifier(name) || strlen(name) != json_string_length(item)) return false;
        for (size_t j = 0; j < i; ++j) if (!strcmp(name, json_string_value(json_array_get(items, j)))) return false;
    }
    return true;
}

/* Local enrollment is create-only. Repeating identical input is harmless. */
bool credential_api_provision(const char *path)
{
    json_t *root = read_private(path);
    if (!root) fprintf(stderr, "Credential enrollment input is not private or valid JSON.\n");
    bool protected_storage = private_storage();
    if (!protected_storage) fprintf(stderr, "Credential enrollment requires private PAL storage directories.\n");
    bool ok = protected_storage && fields(root, "|namespaces|");
    json_t *policies = json_object_get(root, "namespaces");
    ok = ok && json_is_array(policies) && json_array_size(policies) > 0 && json_array_size(policies) <= 16;
    for (size_t i = 0; ok && i < json_array_size(policies); ++i) {
        ok = policy_valid(json_array_get(policies, i));
        for (size_t j = 0; ok && j < i; ++j)
            if (!strcmp(string_field(json_array_get(policies, i), "namespace"), string_field(json_array_get(policies, j), "namespace"))) ok = false;
    }
    for (size_t i = 0; ok && i < json_array_size(policies); ++i) {
        json_t *policy = json_array_get(policies, i);
        char name[64]; snprintf(name, sizeof(name), "ptc.auth.%s", string_field(policy, "namespace"));
        char *text = json_dumps(policy, JSON_COMPACT | JSON_SORT_KEYS);
        uint8_t previous[4096]; size_t size = 0; bool missing = false;
        ok = text && strlen(text) <= sizeof(previous) && load(name, previous, sizeof(previous), &size, &missing);
        if (ok && missing) ok = kcm_item_store((const uint8_t *)name, strlen(name), KCM_CONFIG_ITEM, false,
                                                (const uint8_t *)text, strlen(text), NULL) == KCM_STATUS_SUCCESS;
        else if (ok) ok = size == strlen(text) && !memcmp(previous, text, size);
        if (text) { erase(text, strlen(text)); free(text); }
        erase(previous, sizeof(previous));
    }
    if (json_is_array(policies)) for (size_t i = 0; i < json_array_size(policies); ++i)
        clear_field(json_array_get(policies, i), "key");
    json_decref(root); return ok;
}

static uint64_t revision(const uint8_t *data)
{
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value = (value << 8) | data[i];
    return value;
}

static json_t *operate(json_t *body, json_t *policy, const char *scope)
{
    const char *op = string_field(body, "op"), *item = string_field(body, "name");
    if (!fields(body, "|op||name||expected_revision||value|") || !op || !identifier(item)) return NULL;
    bool allowed = false;
    json_t *items = json_object_get(policy, "items");
    for (size_t i = 0; i < json_array_size(items); ++i)
        if (!strcmp(item, json_string_value(json_array_get(items, i)))) allowed = true;
    if (!allowed) return json_pack("{s:s}", "status", "denied");
    bool write = !strcmp(op, "compare_exchange");
    if (!write && strcmp(op, "get")) return NULL;
    if ((!write && json_object_size(body) != 2) || (write && json_object_size(body) != 4)) return NULL;
    uint8_t slots[2][VALUE_LIMIT + 9]; size_t sizes[2] = {0}; bool missing[2];
    uint64_t versions[2] = {0}; char names[2][100];
    json_t *result = NULL;
    for (unsigned i = 0; i < 2; ++i) {
        snprintf(names[i], sizeof(names[i]), "ptc.data.%02u.%s.%s.%u", (unsigned)strlen(scope), scope, item, i);
        if (!load(names[i], slots[i], sizeof(slots[i]), &sizes[i], &missing[i])) goto done;
        if (!missing[i]) {
            if (sizes[i] < 9 || slots[i][8] > 1 || (slots[i][8] == 1 && sizes[i] != 9)) goto done;
            versions[i] = revision(slots[i]);
            if (!versions[i] || versions[i] > INT64_MAX) goto done;
        }
    }
    if (versions[0] && versions[0] == versions[1]) goto done;
    unsigned current = versions[1] > versions[0] ? 1 : 0, target = 1 - current;
    uint64_t version = versions[current];
    if (write) {
        json_t *expected = json_object_get(body, "expected_revision"), *value = json_object_get(body, "value");
        if (!json_is_integer(expected) || json_integer_value(expected) < 0) goto done;
        if ((uint64_t)json_integer_value(expected) != version) {
            result = json_pack("{s:s,s:I}", "status", "conflict", "revision", (json_int_t)version); goto done;
        }
        if (version == INT64_MAX) goto done;
        size_t length = 0;
        if (!json_is_null(value) && !decode(string_field(body, "value"), slots[target] + 9, VALUE_LIMIT, &length)) goto done;
        uint64_t next = version + 1;
        for (unsigned i = 0; i < 8; ++i) slots[target][i] = (uint8_t)(next >> (56 - i * 8));
        slots[target][8] = json_is_null(value) ? 1 : 0;
        if (!missing[target] && kcm_item_delete((const uint8_t *)names[target], strlen(names[target]), KCM_CONFIG_ITEM) != KCM_STATUS_SUCCESS) goto done;
        if (kcm_item_store((const uint8_t *)names[target], strlen(names[target]), KCM_CONFIG_ITEM, false,
                           slots[target], length + 9, NULL) != KCM_STATUS_SUCCESS) goto done;
        result = json_pack("{s:s,s:I}", "status", "ok", "revision", (json_int_t)next);
    } else {
        result = json_pack("{s:s,s:I}", "status", "ok", "revision", (json_int_t)version);
        if (result) json_object_set_new(result, "value", !version || slots[current][8] ? json_null() : encode(slots[current] + 9, sizes[current] - 9));
    }
done:
    erase(slots, sizeof(slots));
    return result;
}

static void release(rpc_request_context_t *data)
{
    credential_request *ctx = (credential_request *)data;
    if (ctx->counted) {
        pal_osMutexWait(pending_mutex, PAL_RTOS_WAIT_FOREVER);
        --pending;
        pal_osMutexRelease(pending_mutex);
    }
    free(ctx->id); erase(ctx, sizeof(*ctx)); free(ctx);
}

static void execute(arm_event_t *event)
{
    if (!event->data_ptr) return;
    credential_request *ctx = event->data_ptr;
    uint8_t policy_data[4096], key[32], aad[128], packet[PACKET_LIMIT];
    size_t size = 0, key_size = 0; bool missing = false;
    char name[64]; snprintf(name, sizeof(name), "ptc.auth.%s", ctx->scope);
    json_t *policy = NULL, *body = NULL, *answer = NULL;
    json_t *response = pt_api_allocate_response_common(ctx->id);
    int code = DENIED;
    if (!response) goto done;
    if (!private_storage()) goto send;
    if (!load(name, policy_data, sizeof(policy_data), &size, &missing) || missing) goto send;
    policy = bounded_json(policy_data, size);
    if (!policy_valid(policy) || strcmp(string_field(policy, "namespace"), ctx->scope) ||
        !decode(string_field(policy, "key"), key, sizeof(key), &key_size) || key_size != 32) goto send;
    size_t aad_size = associated(ctx, false, aad), plain_size = ctx->length - 28;
    if (!aead(false, key, ctx->packet, aad, aad_size, ctx->packet + 12, plain_size, ctx->packet + ctx->length - 16)) goto send;
    body = bounded_json(ctx->packet + 12, plain_size);
    answer = operate(body, policy, ctx->scope);
    code = STORAGE_ERROR;
    if (!answer) goto send;
    char *plain = json_dumps(answer, JSON_COMPACT);
    if (!plain) goto send;
    size = strlen(plain);
    if (size > sizeof(packet) - 28 || pal_osRandomBuffer(packet, 12) != PAL_SUCCESS) {
        erase(plain, size); free(plain); goto send;
    }
    memcpy(packet + 12, plain, size); erase(plain, size); free(plain);
    aad_size = associated(ctx, true, aad);
    if (!aead(true, key, packet, aad, aad_size, packet + 12, size, packet + 12 + size)) goto send;
    json_object_set_new(response, "result", json_pack("{s:o}", "envelope", encode(packet, size + 28)));
    code = 0;
send:
    if (code) json_object_set_new(response, "error", jsonrpc_error_object(code,
                 code == DENIED ? "Credential access denied" : "Credential request failed", NULL));
done:
    clear_field(policy, "key"); clear_field(body, "value"); clear_field(answer, "value");
    json_decref(policy); json_decref(body); json_decref(answer);
    erase(policy_data, sizeof(policy_data)); erase(key, sizeof(key)); erase(packet, sizeof(packet));
    if (response) edge_server_construct_and_send_response_safe(ctx->connection, response, release, (rpc_request_context_t *)ctx);
    else release((rpc_request_context_t *)ctx);
}

void credential_api_protocol_init(void)
{
    if (tasklet < 0) {
        if (!pending_mutex && pal_osMutexCreate(&pending_mutex) != PAL_SUCCESS) return;
        eventOS_scheduler_mutex_wait();
        tasklet = eventOS_event_handler_create(execute, 0);
        eventOS_scheduler_mutex_release();
    }
}

static bool preflight(json_t **result, void *userdata)
{
    if (!pt_api_check_service_availability(result)) return false;
    struct json_message_t *message = userdata;
    if (!message || !pt_api_check_request_id(message)) {
        *result = jsonrpc_error_object_predefined(JSONRPC_INVALID_PARAMS, NULL);
        return false;
    }
    return true;
}

static struct connection *caller(void *userdata)
{
    struct json_message_t *message = userdata;
    struct connection *connection = message ? message->connection : NULL;
    return connection && connection->client_data && connection->client_data->name &&
        connection->client_data->registered && connection->client_data->method_table == method_table ? connection : NULL;
}

int credential_api_open(json_t *request, json_t *params, json_t **result, void *userdata)
{
    (void)request;
    if (!preflight(result, userdata)) return JSONRPC_RETURN_CODE_ERROR;
    struct connection *connection = caller(userdata);
    if (!connection || !json_is_object(params) || json_object_size(params) != 0) return failure(result, DENIED);
    connection->credential_active = false;
    credential_api_protocol_init();
    if (tasklet < 0) return failure(result, STORAGE_ERROR);
    if (pal_osRandomBuffer(connection->credential_challenge, 32) != PAL_SUCCESS) return failure(result, STORAGE_ERROR);
    connection->credential_sequence = 0;
    connection->credential_active = true;
    *result = json_pack("{s:i,s:o}", "version", 1, "challenge", encode(connection->credential_challenge, 32));
    return JSONRPC_RETURN_CODE_SUCCESS;
}

int credential_api_request(json_t *request, json_t *params, json_t **result, void *userdata)
{
    if (!preflight(result, userdata)) return JSONRPC_RETURN_CODE_ERROR;
    struct connection *connection = caller(userdata);
    json_t *sequence = json_object_get(params, "sequence");
    const char *scope = string_field(params, "namespace");
    if (!connection || !connection->credential_active || !fields(params, "|namespace||sequence||envelope|") ||
        json_object_size(params) != 3 || !identifier(scope) || !json_is_integer(sequence) ||
        json_integer_value(sequence) < 0 || (uint64_t)json_integer_value(sequence) != connection->credential_sequence ||
        connection->credential_sequence == INT64_MAX || tasklet < 0) return failure(result, DENIED);
    credential_request *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return failure(result, STORAGE_ERROR);
    pal_osMutexWait(pending_mutex, PAL_RTOS_WAIT_FOREVER);
    if (pending < 32) { ++pending; ctx->counted = true; }
    pal_osMutexRelease(pending_mutex);
    if (!ctx->counted) { free(ctx); return failure(result, STORAGE_ERROR); }
    if (!decode(string_field(params, "envelope"), ctx->packet, sizeof(ctx->packet), &ctx->length) || ctx->length < 28) {
        release((rpc_request_context_t *)ctx); return failure(result, DENIED);
    }
    ctx->connection = connection->id;
    ctx->id = json_dumps(json_object_get(request, "id"), JSON_COMPACT | JSON_ENCODE_ANY);
    strcpy(ctx->scope, scope);
    memcpy(ctx->challenge, connection->credential_challenge, 32);
    ctx->sequence = connection->credential_sequence++;
    arm_event_t event = {0}; event.receiver = tasklet; event.data_ptr = ctx;
    if (!ctx->id || eventOS_event_send(&event)) { release((rpc_request_context_t *)ctx); return failure(result, STORAGE_ERROR); }
    return JSONRPC_RETURN_CODE_NO_RESPONSE;
}
