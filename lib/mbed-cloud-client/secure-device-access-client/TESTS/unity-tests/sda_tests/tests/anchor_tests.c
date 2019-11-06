// ----------------------------------------------------------------------------
// Copyright 2017-2019 ARM Ltd.
//  
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//  
//     http://www.apache.org/licenses/LICENSE-2.0
//  
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------


#include "unity_fixture.h"
#include "sda_log.h"
#include "cose.h"
#include "cose_int.h"
#include "sda_internal_defs.h"
#include "secure_device_access.h"
#include "pal.h"
#include "factory_configurator_client.h"
#include "test_utils.h"
#include "sda_trust_anchor.h"
#include "test_common_utils.h"

TEST_GROUP(trust_anchor_test);

TEST_SETUP(trust_anchor_test)
{
    fcc_tst_setup();
    TEST_SKIP_EXECUTION_ON_FAILURE();
}

TEST_TEAR_DOWN(trust_anchor_test)
{
    fcc_tst_tear_down();
    TEST_SKIP_EXECUTION_ON_FAILURE();
}


const uint8_t test_secp256r1_der_key_1[SDA_TRUST_ANCHOR_SIZE] =
{ 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
  0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xa4, 0x9d, 0xa7, 0xfc, 0xf9,
  0x40, 0x5f, 0xa1, 0x52, 0xcf, 0xea, 0x97, 0x54, 0x8a, 0xc0, 0xae, 0x60, 0x04, 0x24, 0x85, 0x8a,
  0xfc, 0x3a, 0xc3, 0xe5, 0x0d, 0x44, 0xd0, 0xe2, 0x55, 0x0d, 0x34, 0x51, 0xb0, 0x22, 0xe4, 0xb4,
  0xa9, 0x74, 0x25, 0x1a, 0x4e, 0x52, 0xe4, 0xcd, 0x5a, 0x85, 0x06, 0x5d, 0x66, 0x94, 0x58, 0x46,
  0x8f, 0x55, 0xa3, 0xe0, 0x50, 0x7e, 0xee, 0xa4, 0x2e, 0x5f, 0x25 };

const uint8_t test_secp256r1_raw_key_1[KCM_EC_SECP256R1_MAX_PUB_KEY_RAW_SIZE] =
{ 0x04, 0xa4, 0x9d, 0xa7, 0xfc, 0xf9, 0x40, 0x5f, 0xa1, 0x52, 0xcf, 0xea, 0x97, 0x54, 0x8a, 0xc0,
  0xae, 0x60, 0x04, 0x24, 0x85, 0x8a, 0xfc, 0x3a, 0xc3, 0xe5, 0x0d, 0x44, 0xd0, 0xe2, 0x55, 0x0d,
  0x34, 0x51, 0xb0, 0x22, 0xe4, 0xb4, 0xa9, 0x74, 0x25, 0x1a, 0x4e, 0x52, 0xe4, 0xcd, 0x5a, 0x85,
  0x06, 0x5d, 0x66, 0x94, 0x58, 0x46, 0x8f, 0x55, 0xa3, 0xe0, 0x50, 0x7e, 0xee, 0xa4, 0x2e, 0x5f,
  0x25};

const uint8_t test_secp256r1_key1_name[TEST_SDA_TRUST_ANCHOR_KEY_NAME_SIZE] = "mbed.ta.CAC252CE379CC0B2DA9CFD9B3095ADDF66EDF0DFD150A3661E6E5C24B26B821C";

const uint8_t test_secp256r1_der_key_2[SDA_TRUST_ANCHOR_SIZE] = 
{ 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
  0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xcb, 0x24, 0xe6, 0xea, 0x13,
  0xd9, 0x41, 0x6d, 0x9a, 0x35, 0xd7, 0x46, 0x1e, 0x5b, 0xcf, 0xac, 0xf4, 0x79, 0xe2, 0x37, 0xe9,
  0xc6, 0x71, 0x0c, 0x49, 0xff, 0xe2, 0x0c, 0x9a, 0x56, 0xc1, 0xac, 0x0d, 0x89, 0xc2, 0x98, 0x21,
  0xab, 0x72, 0xc8, 0xef, 0x55, 0x0a, 0x2e, 0xf1, 0xe1, 0x5e, 0xf1, 0xfc, 0x10, 0x02, 0x56, 0x41,
  0x51, 0x95, 0x62, 0xa2, 0x14, 0x27, 0x0a, 0x27, 0x03, 0xd4, 0x56 };

const uint8_t test_secp256r1_raw_key_2[KCM_EC_SECP256R1_MAX_PUB_KEY_RAW_SIZE] =
{ 0x04, 0xcb, 0x24, 0xe6, 0xea, 0x13,
0xd9, 0x41, 0x6d, 0x9a, 0x35, 0xd7, 0x46, 0x1e, 0x5b, 0xcf, 0xac, 0xf4, 0x79, 0xe2, 0x37, 0xe9,
0xc6, 0x71, 0x0c, 0x49, 0xff, 0xe2, 0x0c, 0x9a, 0x56, 0xc1, 0xac, 0x0d, 0x89, 0xc2, 0x98, 0x21,
0xab, 0x72, 0xc8, 0xef, 0x55, 0x0a, 0x2e, 0xf1, 0xe1, 0x5e, 0xf1, 0xfc, 0x10, 0x02, 0x56, 0x41,
0x51, 0x95, 0x62, 0xa2, 0x14, 0x27, 0x0a, 0x27, 0x03, 0xd4, 0x56 };

const uint8_t test_secp256r1_key2_name[TEST_SDA_TRUST_ANCHOR_KEY_NAME_SIZE] = "mbed.ta.7ADDF7246BC6BB9B8604DA093B0FC1079389C722119C45E81134B73354231EC3";

const uint8_t test_secp224r1_der_key[106] =
{ 0x30, 0x68, 0x02, 0x01, 0x01, 0x04, 0x1c, 0x98, 0xbb, 0x66, 0x22, 0xa5, 0x39, 0xaa, 0xc2, 0xb3,
  0x39, 0xec, 0xb4, 0x48, 0x9d, 0xba, 0x74, 0x6f, 0x08, 0x99, 0xe5, 0xaf, 0x35, 0x3b, 0xff, 0x9e,
  0xca, 0x7f, 0xff, 0xa0, 0x07, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x21, 0xa1, 0x3c, 0x03, 0x3a,
  0x00, 0x04, 0x54, 0xfb, 0x65, 0x5f, 0x57, 0xc1, 0x73, 0x04, 0x2a, 0x3a, 0xc4, 0xe7, 0xb4, 0xb2,
  0xb4, 0x3b, 0xd2, 0xa2, 0x77, 0x96, 0xf4, 0xea, 0x2e, 0x67, 0x0c, 0xfb, 0x75, 0x5d, 0xfa, 0x9b,
  0x31, 0xde, 0x55, 0x1a, 0x3d, 0xa7, 0xa4, 0x0e, 0xb5, 0x03, 0x9e, 0x89, 0x7c, 0xf1, 0x4d, 0x9e,
  0x94, 0x56, 0x53, 0xbe, 0xb6, 0xd3, 0xd2, 0x32, 0x50, 0xf6 };

TEST(trust_anchor_test, trust_anchor_positive)
{
    sda_status_internal_e sda_status_internal = SDA_STATUS_INTERNAL_SUCCESS;
    uint8_t raw_key_data[KCM_EC_SECP256R1_MAX_PUB_KEY_RAW_SIZE] = { 0 };
    size_t act_raw_key_data_size = 0;

    sda_status_internal = test_provisioning_setup(false, test_secp256r1_key1_name, sizeof(test_secp256r1_key1_name), test_secp256r1_der_key_1, sizeof(test_secp256r1_der_key_1), NULL, 0, NULL, 0);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INTERNAL_SUCCESS, sda_status_internal);

    sda_status_internal = sda_trust_anchor_get(test_secp256r1_key1_name, sizeof(test_secp256r1_key1_name), raw_key_data, sizeof(raw_key_data), &act_raw_key_data_size);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INTERNAL_SUCCESS, sda_status_internal);
    TEST_ASSERT_EQUAL_INT(KCM_EC_SECP256R1_MAX_PUB_KEY_RAW_SIZE, act_raw_key_data_size);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(test_secp256r1_raw_key_1, raw_key_data, act_raw_key_data_size, "Failed in check of string param");

}
TEST(trust_anchor_test, trust_anchor_bad_params)
{
    sda_status_internal_e sda_status_internal = SDA_STATUS_INTERNAL_SUCCESS;
	sda_status_e sda_status = SDA_STATUS_SUCCESS;
    uint8_t raw_key_data[KCM_EC_SECP256R1_MAX_PUB_KEY_RAW_SIZE] = { 0 };
    size_t act_raw_key_data_size = 0;
   
    sda_status = test_provisioning_setup(false, test_secp256r1_key1_name, sizeof(test_secp256r1_key1_name), NULL, sizeof(test_secp256r1_der_key_1), NULL, 0, NULL, 0);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INVALID_REQUEST, sda_status);

    sda_status = test_provisioning_setup(false, test_secp256r1_key1_name, sizeof(test_secp256r1_key1_name), test_secp256r1_der_key_1, 0, NULL, 0, NULL, 0);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INVALID_REQUEST, sda_status);

    sda_status = test_provisioning_setup(false, test_secp256r1_key1_name, sizeof(test_secp256r1_key1_name), test_secp256r1_der_key_1, SDA_TRUST_ANCHOR_SIZE+1, NULL, 0, NULL, 0);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INVALID_REQUEST, sda_status);

    sda_status_internal = sda_trust_anchor_get(NULL, sizeof(test_secp256r1_key1_name), raw_key_data, sizeof(raw_key_data), &act_raw_key_data_size);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INTERNAL_INVALID_PARAMETER, sda_status_internal);

    sda_status_internal = sda_trust_anchor_get(test_secp256r1_key1_name, 0, raw_key_data, sizeof(raw_key_data), &act_raw_key_data_size);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INTERNAL_INVALID_PARAMETER, sda_status_internal);

    sda_status_internal = sda_trust_anchor_get(test_secp256r1_key1_name, sizeof(test_secp256r1_key1_name), NULL, sizeof(raw_key_data), &act_raw_key_data_size);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INTERNAL_INVALID_PARAMETER, sda_status_internal);

    sda_status_internal = sda_trust_anchor_get(test_secp256r1_key1_name, sizeof(test_secp256r1_key1_name), raw_key_data, 0, &act_raw_key_data_size);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INTERNAL_INVALID_PARAMETER, sda_status_internal);

    sda_status_internal = sda_trust_anchor_get(test_secp256r1_key1_name, sizeof(test_secp256r1_key1_name), raw_key_data, KCM_EC_SECP256R1_MAX_PUB_KEY_RAW_SIZE -1, &act_raw_key_data_size);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INTERNAL_INVALID_PARAMETER, sda_status_internal);

    sda_status_internal = sda_trust_anchor_get(test_secp256r1_key1_name, sizeof(test_secp256r1_key1_name), raw_key_data, sizeof(raw_key_data), NULL);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INTERNAL_INVALID_PARAMETER, sda_status_internal);

    sda_status_internal = test_provisioning_setup(false, test_secp256r1_key1_name, sizeof(test_secp256r1_key1_name), test_secp256r1_der_key_1, sizeof(test_secp256r1_der_key_1), NULL, 0, NULL, 0);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INTERNAL_SUCCESS, sda_status_internal);

    sda_status_internal = sda_trust_anchor_get(test_secp256r1_key1_name, sizeof(test_secp256r1_key1_name), raw_key_data, sizeof(raw_key_data), &act_raw_key_data_size);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INTERNAL_SUCCESS, sda_status_internal);
    TEST_ASSERT_EQUAL_INT(KCM_EC_SECP256R1_MAX_PUB_KEY_RAW_SIZE, act_raw_key_data_size);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(test_secp256r1_raw_key_1, raw_key_data, act_raw_key_data_size, "Failed in check of string param");

}
TEST(trust_anchor_test, trust_anchor_negative)
{
    sda_status_e sda_status = SDA_STATUS_SUCCESS;
	sda_status_internal_e sda_status_internal = SDA_STATUS_INTERNAL_SUCCESS;
    uint8_t raw_key_data[KCM_EC_SECP256R1_MAX_PUB_KEY_RAW_SIZE] = { 0 };
    size_t act_raw_key_data_size = 0;

    //Try to set key of wrong size
    sda_status = test_provisioning_setup(false, test_secp256r1_key1_name, sizeof(test_secp256r1_key1_name), test_secp224r1_der_key, sizeof(test_secp224r1_der_key), NULL, 0, NULL, 0);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INVALID_REQUEST, sda_status);

    sda_status_internal = sda_trust_anchor_get(test_secp256r1_key1_name, sizeof(test_secp256r1_key1_name), raw_key_data, sizeof(raw_key_data), &act_raw_key_data_size);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INTERNAL_TRUST_ANCHOR_NOT_FOUND, sda_status_internal);

    //Try to set wrong key as trust anchor
    sda_status = test_provisioning_setup(false, test_secp256r1_key1_name, sizeof(test_secp256r1_key1_name), test_secp224r1_der_key, sizeof(test_secp256r1_der_key_1), NULL, 0, NULL, 0);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_DEVICE_INTERNAL_ERROR, sda_status);

}

TEST_GROUP_RUNNER(trust_anchor_test)
{
    RUN_TEST_CASE(trust_anchor_test, trust_anchor_positive);
    RUN_TEST_CASE(trust_anchor_test, trust_anchor_bad_params);
    RUN_TEST_CASE(trust_anchor_test, trust_anchor_negative);
}
