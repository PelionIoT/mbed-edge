/* SPDX-License-Identifier: Apache-2.0 */
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <jansson.h>
#include "tinycbor.h"
#include "common/json2cbor.h"

#define CHECK(test) do { if (!(test)) { fprintf(stderr, "Check failed at line %d: %s\n", __LINE__, #test); return 1; } } while (0)
static const uint8_t binary[] = {0,13,10,26,127,128,255};
static const char *json_path = "bundle \xc3\xa9/provisioning.json";

static bool write_file(const char *path, const void *data, size_t length)
{
    FILE *file = fopen(path, "wb");
    if (!file) return false;
    bool ok = fwrite(data, 1, length, file) == length;
    return fclose(file) == 0 && ok;
}

static bool write_json(json_t *root)
{
    char *text = json_dumps(root, JSON_COMPACT);
    bool ok = text && write_file(json_path, text, strlen(text));
    free(text);
    return ok;
}

static bool rejected(const char *text)
{
    uint8_t *output = (uint8_t *)1;
    size_t length = 99;
    if (!write_file(json_path, text, strlen(text))) return false;
    return json_to_cbor(json_path, &output, &length) != 0 && output == NULL && length == 0;
}

int main(void)
{
    char directory[] = "/private/tmp/edge-json-XXXXXXXX";
    CHECK(mkdtemp(directory));
    CHECK(chdir(directory) == 0);
    CHECK(mkdir("bundle \xc3\xa9", 0700) == 0);
    CHECK(write_file("bundle \xc3\xa9/der.bin", binary, sizeof(binary)));
    const char *valid = "{\"SchemeVersion\":\"0.0.1\",\"Certificates\":[{\"Name\":\"test\",\"Format\":\"der\",\"Data\":\"der.bin\"}],\"Keys\":[],\"ConfigParams\":[{\"Name\":\"integer\",\"Data\":5000000000},{\"Name\":\"mbed.VendorId\",\"Data\":\"00112233445566778899aabbccddeeff\"}]}";
    json_t *root = json_loads(valid, 0, NULL);
    CHECK(root);
    char large[20001];
    memset(large, 'x', sizeof(large) - 1); large[20000] = 0;
    CHECK(json_array_append_new(json_object_get(root, "ConfigParams"), json_pack("{s:s,s:s}", "Name", "payload", "Data", large)) == 0);
    CHECK(json_object_set_new(root, "RoTFilePath", json_string("unused-test-path")) == 0);
    CHECK(write_json(root));
    uint8_t *output = NULL;
    size_t length = 0;
    CHECK(json_to_cbor(json_path, &output, &length) == 0 && length > 8192);
    CborParser parser;
    CborValue map, value, array, data, end;
    CHECK(cbor_parser_init(output, length, 0, &parser, &map) == CborNoError);
    CHECK(cbor_value_validate_basic(&map) == CborNoError);
    end = map;
    CHECK(cbor_value_advance(&end) == CborNoError && end.ptr == output + length);
    CHECK(cbor_value_map_find_value(&map, "Certificates", &value) == CborNoError);
    CHECK(cbor_value_enter_container(&value, &array) == CborNoError);
    CHECK(cbor_value_map_find_value(&array, "Data", &data) == CborNoError);
    uint8_t bytes[32]; size_t size = sizeof(bytes);
    CHECK(cbor_value_copy_byte_string(&data, bytes, &size, NULL) == CborNoError);
    CHECK(size == sizeof(binary) && !memcmp(bytes, binary, size));
    CHECK(cbor_value_map_find_value(&map, "ConfigParams", &value) == CborNoError);
    CHECK(cbor_value_enter_container(&value, &array) == CborNoError);
    CHECK(cbor_value_map_find_value(&array, "Data", &data) == CborNoError);
    uint64_t number = 0;
    CHECK(cbor_value_get_uint64(&data, &number) == CborNoError && number == UINT64_C(5000000000));
    CHECK(cbor_value_advance(&array) == CborNoError);
    CHECK(cbor_value_map_find_value(&array, "Data", &data) == CborNoError);
    size = sizeof(bytes);
    CHECK(cbor_value_copy_byte_string(&data, bytes, &size, NULL) == CborNoError && size == 16 && bytes[15] == 255);
    CHECK(cbor_value_advance(&array) == CborNoError);
    CHECK(cbor_value_map_find_value(&array, "Data", &data) == CborNoError);
    CHECK(cbor_value_get_string_length(&data, &size) == CborNoError && size == 20000);
    free(output);
    char *absolute = realpath("bundle \xc3\xa9/der.bin", NULL);
    CHECK(absolute);
    CHECK(json_object_set_new(json_array_get(json_object_get(root, "Certificates"), 0), "Data", json_string(absolute)) == 0);
    free(absolute);
    CHECK(write_json(root));
    CHECK(json_to_cbor(json_path, &output, &length) == 0);
    free(output); json_decref(root);
    CHECK(unlink("bundle \xc3\xa9/der.bin") == 0);
    CHECK(json_to_cbor(json_path, &output, &length) != 0 && !output && !length);
    CHECK(rejected("{\"SchemeVersion\":\"0.0.1\",\"SchemeVersion\":\"0.0.1\"}"));
    CHECK(rejected("{\"SchemeVersion\":\"0.0.1\",\"ConfigParams\":[{\"Name\":\"x\",\"Data\":true}]}"));
    CHECK(rejected("{\"SchemeVersion\":\"0.0.1\",\"ConfigParams\":[{\"Name\":\"mbed.VendorId\",\"Data\":\"not-hex\"}]}"));
    CHECK(rejected("{\"SchemeVersion\":\"0.0.1\",\"Certificates\":[{\"Name\":\"x\",\"Format\":\"der\",\"Data\":\"https://example.invalid/key\"}]}"));
    CHECK(rejected("{\"SchemeVersion\":\"0.0.1\",\"unexpected\":1}"));
    CHECK(unlink(json_path) == 0 && rmdir("bundle \xc3\xa9") == 0);
    CHECK(chdir("/") == 0 && rmdir(directory) == 0);
    puts("macOS JSON provisioning checks passed");
    return 0;
}
