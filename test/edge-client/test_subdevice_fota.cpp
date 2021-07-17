/*
 * ----------------------------------------------------------------------------
 * Copyright 2021 Pelion Ltd.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ----------------------------------------------------------------------------
 */
#if 1

#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"
#include "edge-client/edge_client.h"
#include "edge-client/subdevice_fota.h"
#include "mbed-trace/mbed_trace.h"
#include "../edge-server-mock/test_fota_config.h"
#define ENDPOINT "test-fota"
#define URI "d/test-fota/10252/0/1"

manifest_firmware_info_t* fw_info_buff = NULL;
TEST_GROUP(subdevice_fota_test_group) {
    void setup()
    {

        fw_info_buff = (manifest_firmware_info_t*) calloc(1, sizeof(manifest_firmware_info_t));
    }

    void teardown()
    {
        if(fw_info_buff)
            free(fw_info_buff);
    }
};

TEST(subdevice_fota_test_group, endpoint) {
    tr_info("endpoint test: %s", URI);
    char uri_path[] = URI;
    char endpoint[100] = "";
    get_endpoint(endpoint, uri_path);
    tr_info("%s", endpoint);
    STRCMP_EQUAL(endpoint, ENDPOINT);
    mock().checkExpectations();
}
TEST(subdevice_fota_test_group, download) {
    tr_info("file downloading test");
    char path[FILENAME_MAX] = "";
    int status = start_download(path);
    CHECK(0 == status);
    mock().checkExpectations();
}

TEST(subdevice_fota_test_group, uri) {
    tr_info("url test");
    char relative_path[FILENAME_MAX] = DUMMY_BINARY_LOCATION;
    char* real_path = realpath(relative_path, NULL);
    tr_info("Real path: %s", real_path);
    char real_url[FILENAME_MAX] = "";
    sprintf(real_url, "file://%s", real_path);
    char uri[256] = "";
    get_uri(uri);
    STRCMP_EQUAL(real_url,uri);
    mock().checkExpectations();
}

TEST(subdevice_fota_test_group, class_id) {
    tr_info("class_id test");
    uint8_t class_id[16] = {0};
    get_class_id(class_id);
    STRCMP_EQUAL(CLASS_ID,(char*)class_id);
    mock().checkExpectations();
}

TEST(subdevice_fota_test_group, vendor_id) {
    tr_info("vendor_id test");
    uint8_t vendor_id[16] = {0};
    get_vendor_id(vendor_id);
    STRCMP_EQUAL(VENDOR_ID,(char*)vendor_id);
    mock().checkExpectations();
}

TEST(subdevice_fota_test_group, firmware_version) {
    tr_info("firmware version test");
    fota_component_version_t manifest_fw_version = 0;
    get_version(&(manifest_fw_version));
    CHECK(manifest_fw_version == 1000);
    mock().checkExpectations();
}

TEST(subdevice_fota_test_group, firmware_size) {
    tr_info("firmware size test");
    int fw_size = get_manifest_fw_size();
    CHECK(fw_size == 100000);
    mock().checkExpectations();
}

TEST(subdevice_fota_test_group, component_id) {
    tr_info("component id test");
    int id = get_component_id();
    CHECK(id == 2);
    mock().checkExpectations();
}

TEST(subdevice_fota_test_group, component_name) {
    tr_info("component name test");
    char component_name[12] ="";
    int status = get_component_name(component_name);
    STRCMP_EQUAL("MAIN", component_name);
    CHECK(status == 0);
    mock().checkExpectations();
}

TEST(subdevice_fota_test_group, parse_manifest) {
    uint8_t dummy_manifest[] = {1,2,3,4,5,6,7,8,9,0};
    int status = fota_manifest_parse(dummy_manifest, 10, fw_info_buff);
    CHECK_EQUAL(0, status);
    mock().checkExpectations();
}

TEST(subdevice_fota_test_group, allocate_buffers) {
    int status = subdevice_init_buff();
    CHECK_EQUAL(0, status);
    mock().checkExpectations();
    free_subdev_context_buffers();
}
#endif // MBED_EDGE_SUBDEVICE_FOTA