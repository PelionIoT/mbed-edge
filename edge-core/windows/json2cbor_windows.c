/* SPDX-License-Identifier: Apache-2.0
 * Windows JSON provisioning adapter for the existing FCC bundle schema.
 */
#include <windows.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <jansson.h>
#include "tinycbor.h"
#include "common/json2cbor.h"
#include "common/read_file.h"
#include "mbed-trace/mbed_trace.h"

#define TRACE_GROUP "winbyoc"
#define MAX_JSON_BYTES (1024u * 1024u)
#define MAX_BUNDLE_BYTES (16u * 1024u * 1024u)
typedef struct { uint8_t *data; size_t length; char *path; } der_blob;
typedef struct { json_t *array; der_blob *blobs; size_t count; } credential_group;

static const char *string_field(json_t *object, const char *name)
{
    json_t *value = json_object_get(object, name);
    const char *text = json_string_value(value);
    return text && *text && strlen(text) == json_string_length(value) ? text : NULL;
}

static char *absolute_path(const char *path)
{
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, NULL, 0);
    wchar_t *wide = count ? calloc((size_t)count, sizeof(wchar_t)) : NULL;
    wchar_t *full = NULL;
    char *result = NULL;
    if (!wide) return NULL;
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wide, count)) goto done;
    DWORD size = GetFullPathNameW(wide, 0, NULL, NULL);
    full = size ? calloc(size, sizeof(wchar_t)) : NULL;
    if (!full || !GetFullPathNameW(wide, size, full, NULL)) goto done;
    count = WideCharToMultiByte(CP_UTF8, 0, full, -1, NULL, 0, NULL, NULL);
    result = count ? malloc((size_t)count) : NULL;
    if (result) WideCharToMultiByte(CP_UTF8, 0, full, -1, result, count, NULL, NULL);
done:
    free(full); free(wide);
    return result;
}

static char *der_path(const char *json_path, const char *reference)
{
    if (!reference || !*reference) return NULL;
    if (strlen(reference) >= 3 && reference[1] == ':' &&
        (reference[2] == '/' || reference[2] == '\\')) return absolute_path(reference);
    /* Reject drive-relative and remote paths; factory bundles use local files. */
    if (strchr(reference, ':') || reference[0] == '/' || reference[0] == '\\') return NULL;
    const char *slash = strrchr(json_path, '\\');
    if (!slash) return NULL;
    size_t prefix = (size_t)(slash + 1 - json_path);
    char *joined = malloc(prefix + strlen(reference) + 1);
    if (!joined) return NULL;
    memcpy(joined, json_path, prefix);
    strcpy(joined + prefix, reference);
    char *full = absolute_path(joined);
    free(joined);
    return full;
}

static void free_group(credential_group *group)
{
    if (group->blobs) for (size_t i = 0; i < group->count; ++i) {
        if (group->blobs[i].data) SecureZeroMemory(group->blobs[i].data, group->blobs[i].length);
        free(group->blobs[i].data); free(group->blobs[i].path);
    }
    free(group->blobs);
}

static int load_group(json_t *root, const char *name, bool keys, const char *json_path,
                      credential_group *group, size_t *capacity)
{
    group->array = json_object_get(root, name);
    if (!group->array) return 0;
    if (!json_is_array(group->array)) return 1;
    group->count = json_array_size(group->array);
    if (group->count > 512) return 1;
    group->blobs = calloc(group->count ? group->count : 1, sizeof(der_blob));
    if (!group->blobs) return 1;
    for (size_t i = 0; i < group->count; ++i) {
        json_t *item = json_array_get(group->array, i);
        const char *format = string_field(item, "Format");
        if (!json_is_object(item) || !string_field(item, "Name") || !format || strcmp(format,"der") ||
            (keys && !string_field(item,"Type")) || json_object_size(item) != (keys ? 4u : 3u)) return 1;
        der_blob *blob = &group->blobs[i];
        blob->path = der_path(json_path, string_field(item,"Data"));
        if (!blob->path) return 1;
#ifndef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_CERTIFICATE_STORE_SUPPORT
        if (edge_read_file(blob->path, &blob->data, &blob->length) || !blob->length ||
            blob->length > MAX_BUNDLE_BYTES - *capacity) return 1;
        *capacity += blob->length;
#else
        size_t length = strlen(blob->path);
        if (length > MAX_BUNDLE_BYTES - *capacity) return 1;
        *capacity += length;
#endif
    }
    return 0;
}

#define ENCODE(operation) do { CborError error = (operation); if (error != CborNoError) return error; } while (0)
static CborError encode_group(CborEncoder *map, const char *name, const credential_group *group, bool keys)
{
    if (!group->array) return CborNoError;
    CborEncoder array;
    ENCODE(cbor_encode_text_stringz(map,name));
    ENCODE(cbor_encoder_create_array(map,&array,group->count));
    for (size_t i = 0; i < group->count; ++i) {
        CborEncoder item;
        json_t *source = json_array_get(group->array,i);
        ENCODE(cbor_encoder_create_map(&array,&item,keys ? 4 : 3));
        ENCODE(cbor_encode_text_stringz(&item,"Data"));
#ifndef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_CERTIFICATE_STORE_SUPPORT
        ENCODE(cbor_encode_byte_string(&item,group->blobs[i].data,group->blobs[i].length));
#else
        ENCODE(cbor_encode_text_stringz(&item,group->blobs[i].path));
#endif
        ENCODE(cbor_encode_text_stringz(&item,"Name"));
        ENCODE(cbor_encode_text_stringz(&item,string_field(source,"Name")));
        ENCODE(cbor_encode_text_stringz(&item,"Format"));
        ENCODE(cbor_encode_text_stringz(&item,string_field(source,"Format")));
        if (keys) {
            ENCODE(cbor_encode_text_stringz(&item,"Type"));
            ENCODE(cbor_encode_text_stringz(&item,string_field(source,"Type")));
        }
        ENCODE(cbor_encoder_close_container(&array,&item));
    }
    ENCODE(cbor_encoder_close_container(map,&array));
    return CborNoError;
}

static CborError encode_config(CborEncoder *map, json_t *config)
{
    if (!config) return CborNoError;
    CborEncoder array;
    if (!json_is_array(config)) return CborErrorIllegalType;
    ENCODE(cbor_encode_text_stringz(map,"ConfigParams"));
    ENCODE(cbor_encoder_create_array(map,&array,json_array_size(config)));
    for (size_t i = 0; i < json_array_size(config); ++i) {
        json_t *source = json_array_get(config,i);
        const char *name = string_field(source,"Name");
        json_t *data = json_object_get(source,"Data");
        CborEncoder item;
        if (!name || json_object_size(source) != 2 || (!json_is_integer(data) && !json_is_string(data)))
            return CborErrorIllegalType;
        ENCODE(cbor_encoder_create_map(&array,&item,2));
        ENCODE(cbor_encode_text_stringz(&item,"Name"));
        ENCODE(cbor_encode_text_stringz(&item,name));
        ENCODE(cbor_encode_text_stringz(&item,"Data"));
        if (json_is_integer(data)) {
            ENCODE(cbor_encode_int(&item,(int64_t)json_integer_value(data)));
        } else if (!strcmp(name,"mbed.VendorId") || !strcmp(name,"mbed.ClassId")) {
            const char *text = json_string_value(data);
            uint8_t bytes[16];
            if (json_string_length(data) != 32) return CborErrorIllegalType;
            for (size_t j = 0; j < 16; ++j) {
                unsigned int value;
                char hex[3] = {text[j * 2],text[j * 2 + 1],0};
                if (strspn(hex,"0123456789abcdefABCDEF") != 2 || sscanf(hex,"%2x",&value) != 1)
                    return CborErrorIllegalType;
                bytes[j] = (uint8_t)value;
            }
            ENCODE(cbor_encode_byte_string(&item,bytes,sizeof(bytes)));
        } else {
            ENCODE(cbor_encode_text_string(&item,json_string_value(data),json_string_length(data)));
        }
        ENCODE(cbor_encoder_close_container(&array,&item));
    }
    ENCODE(cbor_encoder_close_container(map,&array));
    return CborNoError;
}

int json_to_cbor(const char *input_path, uint8_t **out_buf, size_t *buf_size)
{
    uint8_t *json_data = NULL, *buffer = NULL;
    size_t json_size = 0, capacity = 0;
    json_t *root = NULL;
    char *full_path = NULL;
    credential_group certs = {0}, keys = {0};
    int result = 1;
    if (!input_path || !out_buf || !buf_size) return 1;
    *out_buf = NULL; *buf_size = 0;
    if (edge_read_file(input_path,&json_data,&json_size) || json_size > MAX_JSON_BYTES) goto done;
    json_error_t parse_error;
    root = json_loadb((const char *)json_data,json_size,JSON_REJECT_DUPLICATES,&parse_error);
    if (!json_is_object(root) || !string_field(root,"SchemeVersion") ||
        strcmp(string_field(root,"SchemeVersion"),"0.0.1")) goto done;
    const char *name;
    json_t *value;
    json_object_foreach(root,name,value) {
        if (strcmp(name,"Certificates") && strcmp(name,"Keys") && strcmp(name,"ConfigParams") &&
            strcmp(name,"SchemeVersion") && strcmp(name,"RoTFilePath")) goto done;
    }
    if (json_object_get(root,"RoTFilePath") && !string_field(root,"RoTFilePath")) goto done;
    full_path = absolute_path(input_path);
    capacity = json_size * 2 + 4096;
    if (!full_path || load_group(root,"Certificates",false,full_path,&certs,&capacity) ||
        load_group(root,"Keys",true,full_path,&keys,&capacity)) goto done;
    buffer = malloc(capacity);
    if (!buffer) goto done;
    CborEncoder encoder, map;
    cbor_encoder_init(&encoder,buffer,capacity,0);
    if (cbor_encoder_create_map(&encoder,&map,json_object_size(root)) != CborNoError ||
        encode_group(&map,"Certificates",&certs,false) != CborNoError ||
        encode_group(&map,"Keys",&keys,true) != CborNoError ||
        encode_config(&map,json_object_get(root,"ConfigParams")) != CborNoError) goto done;
    if (json_object_get(root,"RoTFilePath") &&
        (cbor_encode_text_stringz(&map,"RoTFilePath") != CborNoError ||
         cbor_encode_text_stringz(&map,string_field(root,"RoTFilePath")) != CborNoError)) goto done;
    if (cbor_encode_text_stringz(&map,"SchemeVersion") != CborNoError ||
        cbor_encode_text_stringz(&map,"0.0.1") != CborNoError ||
        cbor_encoder_close_container(&encoder,&map) != CborNoError) goto done;
    *buf_size = cbor_encoder_get_buffer_size(&encoder,buffer);
    *out_buf = buffer; buffer = NULL;
    result = 0;
done:
    if (buffer) SecureZeroMemory(buffer,capacity);
    free(buffer); free(json_data); free(full_path); json_decref(root);
    free_group(&certs); free_group(&keys);
    if (result) tr_err("Invalid JSON provisioning or unreadable DER file; credentials were not imported.");
    return result;
}
