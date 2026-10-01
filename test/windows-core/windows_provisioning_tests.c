/* SPDX-License-Identifier: Apache-2.0 */
#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <wchar.h>
#include <jansson.h>
#include "tinycbor.h"
#include "common/json2cbor.h"
#include "common/read_file.h"

#define CHECK(test) do { if (!(test)) { fprintf(stderr,"Check failed at line %d: %s\n",__LINE__,#test); return 1; } } while (0)
static const uint8_t binary[] = {0,13,10,26,127,128,255};
static const char *json_path = "bundle \xc3\xa9/provisioning.json";
static const wchar_t *wide_json_path = L"bundle \x00e9/provisioning.json";
static bool write_file(const wchar_t *path, const void *data, size_t length)
{
    FILE *file = _wfopen(path,L"wb");
    if (!file) return false;
    bool ok = fwrite(data,1,length,file) == length;
    return fclose(file) == 0 && ok;
}
static bool write_json(json_t *root)
{
    char *text = json_dumps(root,JSON_COMPACT);
    bool ok = text && write_file(wide_json_path,text,strlen(text));
    free(text);
    return ok;
}
static bool rejected(const char *text)
{
    uint8_t *output = (uint8_t *)1;
    size_t length = 99;
    if (!write_file(wide_json_path,text,strlen(text))) return false;
    return json_to_cbor(json_path,&output,&length) != 0 && output == NULL && length == 0;
}
int main(void)
{
    wchar_t directory[MAX_PATH];
    swprintf_s(directory,MAX_PATH,L"windows-provisioning-%lu-%llu",GetCurrentProcessId(),GetTickCount64());
    CHECK(CreateDirectoryW(directory,NULL));
    CHECK(SetCurrentDirectoryW(directory));
    CHECK(CreateDirectoryW(L"bundle \x00e9",NULL));
    CHECK(write_file(L"bundle \x00e9/der.bin",binary,sizeof(binary)));
    uint8_t *read = NULL;
    size_t read_size = 0;
    CHECK(edge_read_file("bundle \xc3\xa9/der.bin",&read,&read_size) == 0);
    CHECK(read_size == sizeof(binary) && !memcmp(read,binary,sizeof(binary)));
    free(read);
    const char *valid = "{\"SchemeVersion\":\"0.0.1\",\"Certificates\":[{\"Name\":\"test\",\"Format\":\"der\",\"Data\":\"der.bin\"}],\"Keys\":[],\"ConfigParams\":[{\"Name\":\"integer\",\"Data\":5000000000},{\"Name\":\"mbed.VendorId\",\"Data\":\"00112233445566778899aabbccddeeff\"}]}";
    json_t *root = json_loads(valid,0,NULL);
    CHECK(root != NULL);
    char *large = malloc(20001);
    CHECK(large != NULL);
    memset(large,'x',20000); large[20000] = 0;
    json_t *param = json_pack("{s:s,s:s}","Name","payload","Data",large);
    CHECK(param != NULL);
    CHECK(json_array_append_new(json_object_get(root,"ConfigParams"),param) == 0);
    free(large);
    CHECK(json_object_set_new(root,"RoTFilePath",json_string("unused-test-path")) == 0);
    CHECK(write_json(root));
    uint8_t *output = NULL;
    size_t length = 0;
    CHECK(json_to_cbor(json_path,&output,&length) == 0 && length > 8192);
    CborParser parser;
    CborValue map, value, array, data;
    CHECK(cbor_parser_init(output,length,0,&parser,&map) == CborNoError);
    CHECK(cbor_value_validate_basic(&map) == CborNoError);
    CborValue end = map;
    CHECK(cbor_value_advance(&end) == CborNoError && end.ptr == output + length);
    CHECK(cbor_value_map_find_value(&map,"Certificates",&value) == CborNoError);
    CHECK(cbor_value_enter_container(&value,&array) == CborNoError);
    CHECK(cbor_value_map_find_value(&array,"Data",&data) == CborNoError);
    uint8_t bytes[32]; size_t size = sizeof(bytes);
    CHECK(cbor_value_copy_byte_string(&data,bytes,&size,NULL) == CborNoError);
    CHECK(size == sizeof(binary) && !memcmp(bytes,binary,size));
    CHECK(cbor_value_map_find_value(&map,"ConfigParams",&value) == CborNoError);
    CHECK(cbor_value_enter_container(&value,&array) == CborNoError);
    CHECK(cbor_value_map_find_value(&array,"Data",&data) == CborNoError);
    uint64_t number = 0;
    CHECK(cbor_value_get_uint64(&data,&number) == CborNoError && number == UINT64_C(5000000000));
    CHECK(cbor_value_advance(&array) == CborNoError);
    CHECK(cbor_value_map_find_value(&array,"Data",&data) == CborNoError);
    size = sizeof(bytes);
    CHECK(cbor_value_copy_byte_string(&data,bytes,&size,NULL) == CborNoError && size == 16 && bytes[15] == 255);
    CHECK(cbor_value_advance(&array) == CborNoError);
    CHECK(cbor_value_map_find_value(&array,"Data",&data) == CborNoError);
    CHECK(cbor_value_get_string_length(&data,&size) == CborNoError && size == 20000);
    free(output);
    CHECK(DeleteFileW(L"bundle \x00e9/der.bin"));
    output = NULL; length = 0;
    CHECK(json_to_cbor(json_path,&output,&length) != 0 && !output && !length);
    CHECK(write_file(L"bundle \x00e9/der.bin",binary,0));
    CHECK(json_to_cbor(json_path,&output,&length) != 0 && !output && !length);
    CHECK(rejected("{"));
    CHECK(rejected("{\"SchemeVersion\":\"0.0.1\",\"SchemeVersion\":\"0.0.1\"}"));
    CHECK(rejected("{\"SchemeVersion\":\"0.0.2\"}"));
    CHECK(rejected("{\"SchemeVersion\":\"0.0.1\",\"unknown\":1}"));
    CHECK(rejected("{\"SchemeVersion\":\"0.0.1\",\"Certificates\":{}}"));
    CHECK(rejected("{\"SchemeVersion\":\"0.0.1\",\"Keys\":[{\"Name\":\"x\"}]}"));
    CHECK(rejected("{\"SchemeVersion\":\"0.0.1\",\"ConfigParams\":[{\"Name\":\"x\",\"Data\":true}]}"));
    CHECK(rejected("{\"SchemeVersion\":\"0.0.1\",\"ConfigParams\":[{\"Name\":\"mbed.ClassId\",\"Data\":\"invalid\"}]}"));
    json_decref(root);
    puts("Windows PAL file reading and JSON provisioning checks passed.");
    return 0;
}
