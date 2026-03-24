/*
 * Copyright (c) 2025 Izuma Networks Inc
 *
 * This file is licensed under the Limited Revocable Evaluation License.
 * Use of this source code is subject to the terms and conditions of the license.
 * See IZLREL_LICENSE.txt for full details.
 */

#include "common/json2cbor.h"
#include "common/json2cbor_utils.h"
#include <jansson.h>
#include "tinycbor.h"
#include "mbed-trace/mbed_trace.h"

#define TRACE_GROUP "json2cbor"
#define BUF_SIZE 8192

#define CHECK_CBOR(err, msg)                                         \
    if ((err) != CborNoError)                                        \
    {                                                                \
        tr_err("CBOR error: %s: %s\n", msg, cbor_error_string(err)); \
        return;                                                      \
    }

void _encode_cert_or_key(CborEncoder *arr, json_t *item, int is_key)
{
    CborEncoder map;
    const char *path = json_string_value(json_object_get(item, "Data"));

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_CERTIFICATE_STORE_SUPPORT
    uint8_t *data = NULL;
    size_t len = 0;

    if (load_der_file(path, &data, &len) != 0)
    {
        tr_err("Failed to load DER file: %s\n", path);
        return;
    }

    if (len == 0)
    {
        tr_err("Failed to load DER file\n");
        return;
    }
#endif // MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_CERTIFICATE_STORE_SUPPORT

    const char *format = json_string_value(json_object_get(item, "Format"));
    const char *name = json_string_value(json_object_get(item, "Name"));
    const char *type = is_key ? json_string_value(json_object_get(item, "Type")) : NULL;

    size_t map_size = is_key ? 4 : 3;
    cbor_encoder_create_map(arr, &map, map_size);

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_CERTIFICATE_STORE_SUPPORT
    tr_info("Encoding key/cert file content %s into kcm", name);
    CHECK_CBOR(cbor_encode_text_stringz(&map, "Data"), "encoding 'Data' key");
    CHECK_CBOR(cbor_encode_byte_string(&map, data, len), "encoding 'Data' value");
#else
    tr_info("Encoding key/cert external file path %s into kcm", name);
    cbor_encode_text_stringz(&map, "Data");
    cbor_encode_text_stringz(&map, path);
#endif // MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_CERTIFICATE_STORE_SUPPORT

    cbor_encode_text_stringz(&map, "Format");
    cbor_encode_text_stringz(&map, format);

    cbor_encode_text_stringz(&map, "Name");
    cbor_encode_text_stringz(&map, name);
    if (is_key)
    {
        cbor_encode_text_stringz(&map, "Type");
        cbor_encode_text_stringz(&map, type);
    }

    cbor_encoder_close_container(arr, &map);

#ifndef MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_CERTIFICATE_STORE_SUPPORT
    free(data);
#endif // MBED_CONF_MBED_CLOUD_CLIENT_EXTERNAL_CERTIFICATE_STORE_SUPPORT
}

void _encode_config_param(CborEncoder *arr, json_t *item)
{
    CborEncoder map;
    cbor_encoder_create_map(arr, &map, 2);

    cbor_encode_text_stringz(&map, "Name");
    const char *name = json_string_value(json_object_get(item, "Name"));
    cbor_encode_text_stringz(&map, name);

    cbor_encode_text_stringz(&map, "Data");
    json_t *val = json_object_get(item, "Data");
    if (json_is_integer(val))
    {
        int v = json_integer_value(val);
        cbor_encode_int(&map, v);
    }
    else if (json_is_string(val))
    {
        const char *s = json_string_value(val);

        if (strcmp(name, "mbed.VendorId") == 0 || strcmp(name, "mbed.ClassId") == 0)
        {
            uint8_t bytes[16];
            if (parse_hex_16(s, bytes) == 0)
            {
                cbor_encode_byte_string(&map, bytes, 16);
            }
            else
            {
                tr_err("Invalid hex for %s\n", name);
                cbor_encode_text_stringz(&map, s); // fallback
            }
        }
        else
        {
            cbor_encode_text_stringz(&map, s);
        }
    }

    cbor_encoder_close_container(arr, &map);
}

size_t _create_cbor_data(json_t *root, uint8_t *out_buf, size_t buf_size)
{
    size_t map_size = 0;
    const char *key;
    json_t *value;
    size_t i;
    json_t *item;
    CborEncoder encoder, map, certs, keys, config;

    // Count number of top-level keys in JSON for map size
    json_object_foreach(root, key, value) {
        map_size++;
    }

    cbor_encoder_init(&encoder, out_buf, buf_size, 0);
    cbor_encoder_create_map(&encoder, &map, map_size);

    json_t *rot_file_path = json_object_get(root, "RoTFilePath");
    if (rot_file_path) {
        cbor_encode_text_stringz(&map, "RoTFilePath");
        const char *rot_file_path_str = json_string_value(rot_file_path);
        cbor_encode_text_stringz(&map, rot_file_path_str);
        cbor_encoder_close_container(&encoder, &map);
    }

    json_t *cert_array = json_object_get(root, "Certificates");
    if (cert_array) {
        cbor_encode_text_stringz(&map, "Certificates");
        cbor_encoder_create_array(&map, &certs, CborIndefiniteLength);
        json_array_foreach(cert_array, i, item)
        {
            _encode_cert_or_key(&certs, item, 0);
        }
        cbor_encoder_close_container(&map, &certs);
    }

    json_t *key_array = json_object_get(root, "Keys");
    if (key_array) {
        cbor_encode_text_stringz(&map, "Keys");
        cbor_encoder_create_array(&map, &keys, CborIndefiniteLength);
        json_array_foreach(key_array, i, item)
        {
            _encode_cert_or_key(&keys, item, 1);
        }
        cbor_encoder_close_container(&map, &keys);
    }

    json_t *cfg_array = json_object_get(root, "ConfigParams");
    if (cfg_array) {
        cbor_encode_text_stringz(&map, "ConfigParams");
        cbor_encoder_create_array(&map, &config, CborIndefiniteLength);
        json_array_foreach(cfg_array, i, item)
        {
            _encode_config_param(&config, item);
        }
        cbor_encoder_close_container(&map, &config);
    }

    json_t *scheme_version = json_object_get(root, "SchemeVersion");
    if (scheme_version) {
        cbor_encode_text_stringz(&map, "SchemeVersion");
        const char *ver = json_string_value(scheme_version);
        cbor_encode_text_stringz(&map, ver);
        cbor_encoder_close_container(&encoder, &map);
    }

    return cbor_encoder_get_buffer_size(&encoder, out_buf);
}

int json_to_cbor(const char *input_path, uint8_t **out_buf, size_t *buf_size)
{
    json_error_t error;
    json_t *root = json_load_file(input_path, 0, &error);
    if (!root)
    {
        tr_err("Error parsing JSON: %s\n", error.text);
        return 1;
    }

    uint8_t *buf = malloc(BUF_SIZE);
    if (!buf)
    {
        tr_err("Memory allocation failed.\n");
        json_decref(root);
        return 1;
    }

    size_t actual_size = _create_cbor_data(root, buf, BUF_SIZE);

    if (actual_size == 0)
    {
        tr_err("Failed to encode CBOR data.\n");
        free(buf);
        json_decref(root);
        return 1;
    }

    *out_buf = buf;
    *buf_size = actual_size;

    json_decref(root);
    return 0;
}