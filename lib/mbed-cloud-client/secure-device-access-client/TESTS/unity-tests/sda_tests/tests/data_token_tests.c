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
#include "sda_data_token.h"
#include "secure_device_access.h"

static void test_check_token_output(const char *data, const char *delimeter, const char *token_1, const char *token_2, const char *token_3)
{

    sda_string_token_context_s token_ctx;
    uint8_t *data_token_out = NULL;
    size_t data_token_out_size = 0;
    sda_status_internal_e sda_status_internal = SDA_STATUS_INTERNAL_SUCCESS;

    memset((uint8_t*)&token_ctx, 0, sizeof(token_ctx));

    sda_status_internal = sda_helper_init_token_context(&token_ctx, (const uint8_t*)data, strlen(data), delimeter);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INTERNAL_SUCCESS, sda_status_internal);

    if (token_1 != NULL) {
        sda_status_internal = sda_helper_get_next_data_token(&token_ctx, &data_token_out, &data_token_out_size);
        TEST_ASSERT_EQUAL_INT(SDA_STATUS_INTERNAL_SUCCESS, sda_status_internal);
        TEST_ASSERT_EQUAL_INT(data_token_out_size, strlen(token_1));
        TEST_ASSERT_EQUAL_INT8_ARRAY_MESSAGE((uint8_t*)token_1, data_token_out, data_token_out_size, "Fialed in first token");
    }

    if (token_2 != NULL) {
        sda_status_internal = sda_helper_get_next_data_token(&token_ctx, &data_token_out, &data_token_out_size);
        TEST_ASSERT_EQUAL_INT(SDA_STATUS_INTERNAL_SUCCESS, sda_status_internal);
        TEST_ASSERT_EQUAL_INT(data_token_out_size, strlen(token_2));
        TEST_ASSERT_EQUAL_INT8_ARRAY_MESSAGE((uint8_t*)token_2, data_token_out, data_token_out_size, "Fialed in second token");
    }

    if (token_3 != NULL) {
        sda_status_internal = sda_helper_get_next_data_token(&token_ctx, &data_token_out, &data_token_out_size);
        TEST_ASSERT_EQUAL_INT(SDA_STATUS_INTERNAL_SUCCESS, sda_status_internal);
        TEST_ASSERT_EQUAL_INT(data_token_out_size, strlen(token_3));
        TEST_ASSERT_EQUAL_INT8_ARRAY_MESSAGE((uint8_t*)token_3, data_token_out, data_token_out_size, "Fialed in third token");
    }

    sda_status_internal = sda_helper_get_next_data_token(&token_ctx, &data_token_out, &data_token_out_size);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INTERNAL_NO_TOKENS_TO_SEARCH_ERROR, sda_status_internal);

}

TEST_GROUP(data_token_test);


TEST_SETUP(data_token_test)
{

}

TEST_TEAR_DOWN(data_token_test)
{

}


TEST(data_token_test, simple_delimeter_inside_data)
{

    const char data[] = "device-id:545b1017e52f4c70ad92684e802c9249 device-id:f90b1017e5834c70ad92684e802c9249 device-id:f90b1017e52f4c70ad92684e802c9249";
    const char token_1[] = "device-id:545b1017e52f4c70ad92684e802c9249";
    const char token_2[] = "device-id:f90b1017e5834c70ad92684e802c9249";
    const char token_3[] = "device-id:f90b1017e52f4c70ad92684e802c9249";

    const char delimeter[] = " ";

    test_check_token_output(data, delimeter, token_1, token_2, token_3);
    TEST_SKIP_EXECUTION_ON_FAILURE();

}

TEST(data_token_test, simple_delimeter_on_edges)
{

    const char data[] = " device-id:545b1017e52f4c70ad92684e802c9249 device-id:f90b1017e5834c70ad92684e802c9249 device-id:f90b1017e52f4c70ad92684e802c9249 ";
    const char token_1[] = "device-id:545b1017e52f4c70ad92684e802c9249";
    const char token_2[] = "device-id:f90b1017e5834c70ad92684e802c9249";
    const char token_3[] = "device-id:f90b1017e52f4c70ad92684e802c9249";

    const char delimeter[] = " ";

    test_check_token_output(data, delimeter, token_1, token_2, token_3);
    TEST_SKIP_EXECUTION_ON_FAILURE();
}

TEST(data_token_test, complex_delimeter_inside_data)
{

    const char data[] = "dev*_*ice*_*id";
    const char token_1[] = "dev";
    const char token_2[] = "ice";
    const char token_3[] = "id";

    const char delimeter[] = "*_*";

    test_check_token_output(data, delimeter, token_1, token_2, token_3);
    TEST_SKIP_EXECUTION_ON_FAILURE();

}

TEST(data_token_test, complex_delimeter_on_edges)
{

    const char data[] = "*_*device-id:545b1017e52f4c70ad92684e802c9249*_*device-id:f90b1017e5834c70ad92684e802c9249*_*device-id:f90b1017e52f4c70ad92684e802c9249*_*";
    const char token_1[] = "device-id:545b1017e52f4c70ad92684e802c9249";
    const char token_2[] = "device-id:f90b1017e5834c70ad92684e802c9249";
    const char token_3[] = "device-id:f90b1017e52f4c70ad92684e802c9249";
    const char delimeter[] = "*_*";

    test_check_token_output(data, delimeter, token_1, token_2, token_3);
    TEST_SKIP_EXECUTION_ON_FAILURE();

}

TEST(data_token_test, no_delimeter)
{

    const char delimeter[] = "*_*";
    const char token[] = "device-id:545b1017e52f4c70ad92684e802c9249";
    const char data[] = "device-id:545b1017e52f4c70ad92684e802c9249";

    test_check_token_output(data, delimeter, token, NULL, NULL);
    TEST_SKIP_EXECUTION_ON_FAILURE();

}
TEST(data_token_test, one_delimeter)
{

    const char delimeter[] = "*_*";

    const char token_1[] = "device-id:545b1017e52f4c70ad92684e802c9249";
    const char data_1[] = "*_*device-id:545b1017e52f4c70ad92684e802c9249";
    const char data_2[] = "device-id:545b1017e52f4c70ad92684e802c9249*_*";

    test_check_token_output(data_1, delimeter, token_1, NULL, NULL);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    test_check_token_output(data_2, delimeter, token_1, NULL, NULL);
    TEST_SKIP_EXECUTION_ON_FAILURE();
}

TEST(data_token_test, small_data)
{

    const char delimeter[] = "***";

    const char data_1[] = "***1";
    const char data_2[] = "1***";
    const char data_3[] = "***1***";
    const char token_1[] = "1";


    const char data_4[] = "**%1";
    const char token_2[] = "**%1";


    const char data_5[] = "1**^";
    const char token_3[] = "1**^";


    const char data_6[] = "1*^*";
    const char token_4[] = "1*^*";


    const char data_7[] = "*^*1";
    const char token_5[] = "*^*1";

    const char data_8[] = "*^*1*^*";
    const char token_6[] = "*^*1*^*";

    /*****************     token_1    *****************************/
    test_check_token_output(data_1, delimeter, token_1, NULL, NULL);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    test_check_token_output(data_2, delimeter, token_1, NULL, NULL);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    test_check_token_output(data_3, delimeter, token_1, NULL, NULL);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    /*****************     token_2    *****************************/
    test_check_token_output(data_4, delimeter, token_2, NULL, NULL);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    /*****************     token_3    *****************************/
    test_check_token_output(data_5, delimeter, token_3, NULL, NULL);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    /*****************     token_4    *****************************/
    test_check_token_output(data_6, delimeter, token_4, NULL, NULL);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    /*****************     token_5    *****************************/
    test_check_token_output(data_7, delimeter, token_5, NULL, NULL);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    /*****************     token_6    *****************************/
    test_check_token_output(data_8, delimeter, token_6, NULL, NULL);
    TEST_SKIP_EXECUTION_ON_FAILURE();
}

TEST(data_token_test, multiple_delimiter)
{

    const char delimeter[] = "*_*";

    const char data_1[] = "device-id:545b1017e52f4c70ad92684e802c9249*_**_*device-id:f90b1017e5834c70ad92684e802c9249";
    const char data_2[] = "*_**_*device-id:545b1017e52f4c70ad92684e802c9249*_**_*device-id:f90b1017e5834c70ad92684e802c9249*_**_*";
    const char data_3[] = "*_**_**_*device-id:545b1017e52f4c70ad92684e802c9249*_**_**_*device-id:f90b1017e5834c70ad92684e802c9249*_**_**_*";
    const char data_4[] = "*_**_**_*";
    uint8_t *data_token_out = NULL;
    size_t data_token_out_size = 0;
    sda_string_token_context_s token_ctx;
    sda_status_internal_e sda_status_internal = SDA_STATUS_INTERNAL_SUCCESS;

    const char token_1[] = "device-id:545b1017e52f4c70ad92684e802c9249";
    const char token_2[] = "device-id:f90b1017e5834c70ad92684e802c9249";

    test_check_token_output(data_1, delimeter, token_1, token_2, NULL);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    test_check_token_output(data_2, delimeter, token_1, token_2, NULL);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    test_check_token_output(data_3, delimeter, token_1, token_2, NULL);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    memset((uint8_t*)&token_ctx, 0, sizeof(token_ctx));

    sda_status_internal = sda_helper_init_token_context(&token_ctx, (const uint8_t*)data_4, strlen(data_4), delimeter);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INTERNAL_SUCCESS, sda_status_internal);

    sda_status_internal = sda_helper_get_next_data_token(&token_ctx, &data_token_out, &data_token_out_size);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INTERNAL_NO_TOKENS_TO_SEARCH_ERROR, sda_status_internal);
}
TEST(data_token_test, sub_delimeter)
{
    const char delimeter[] = "*_*";

    const char data[] = "*_#device-id:545b1017e52f4c70ad92684e802c*#*device-id:f90b1017e5834c70ad92684e802c9249#$*device-id:f90b1017e52f4c70ad92684e802c9249*_*";
    const char token_1[] = "*_#device-id:545b1017e52f4c70ad92684e802c*#*device-id:f90b1017e5834c70ad92684e802c9249#$*device-id:f90b1017e52f4c70ad92684e802c9249";

    const char data_2[] = "*_*device-id:545b1017e52f4c70ad92684e802c9249*#*ce-id:f90b1017e5834c70ad92684e802c9249*_*device49*_*";
    const char token_2[] = "device-id:545b1017e52f4c70ad92684e802c9249*#*ce-id:f90b1017e5834c70ad92684e802c9249";
    const char token_3[] = "device49";


    const char data_3[] = "*_*device-id:545b1017e52f4c70ad92684e802c9249*_*device-id:f90b1017e5834c70ad92684e802c9249*_*device-id:f90b1017e52f4c70ad92684e802c9249*&*";
    const char token_4[] = "device-id:545b1017e52f4c70ad92684e802c9249";
    const char token_5[] = "device-id:f90b1017e5834c70ad92684e802c9249";
    const char token_6[] = "device-id:f90b1017e52f4c70ad92684e802c9249*&*";


    const char data_4[] = "*_device-id:545b1017e52f4c70ad92684e802c9249*_device-id:f90b1017e5834c70ad92684e802c9249*_*device-id:f90b1017e52f4c70ad92684e802c9249*&*";
    const char token_7[] = "*_device-id:545b1017e52f4c70ad92684e802c9249*_device-id:f90b1017e5834c70ad92684e802c9249";
    const char token_8[] = "device-id:f90b1017e52f4c70ad92684e802c9249*&*";

    const char data_5[] = "*_*_*de*_id*_*0b1017e52*&*";
    const char token_9[] = "_*de*_id";
    const char token_10[] = "0b1017e52*&*";


    test_check_token_output(data, delimeter, token_1, NULL, NULL);
    TEST_SKIP_EXECUTION_ON_FAILURE();


    test_check_token_output(data_2, delimeter, token_2, token_3, NULL);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    test_check_token_output(data_3, delimeter, token_4, token_5, token_6);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    test_check_token_output(data_4, delimeter, token_7, token_8, NULL);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    test_check_token_output(data_5, delimeter, token_9, token_10, NULL);
    TEST_SKIP_EXECUTION_ON_FAILURE();
}

TEST(data_token_test, get_token_test)
{

    const char data[] = "*_*device-id:545b1017e52f4c70ad92684e802c9249*_*device-id:f90b1017e5834c70ad92684e802c9249*_*device-id:f90b1017e52f4c70ad92684e802c9249*_*";
    const char delimeter[] = "*_*";
    const char empty_delimeter[] = "";
    sda_status_internal_e sda_status_internal = SDA_STATUS_INTERNAL_SUCCESS;
    sda_string_token_context_s token_ctx;
    uint8_t *data_token_out = NULL;
    size_t data_token_out_size = 0;

    memset((uint8_t*)&token_ctx, 0, sizeof(token_ctx));

    sda_status_internal = sda_helper_init_token_context(NULL, (const uint8_t*)data, strlen(data), delimeter);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INTERNAL_INVALID_PARAMETER, sda_status_internal);

    sda_status_internal = sda_helper_init_token_context(&token_ctx, (const uint8_t*)data, 0, delimeter);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INTERNAL_INVALID_PARAMETER, sda_status_internal);

    sda_status_internal = sda_helper_init_token_context(&token_ctx, NULL, strlen(data), delimeter);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INTERNAL_INVALID_PARAMETER, sda_status_internal);

    sda_status_internal = sda_helper_init_token_context(&token_ctx, (const uint8_t*)data, strlen(data), NULL);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INTERNAL_INVALID_PARAMETER, sda_status_internal);

    sda_status_internal = sda_helper_init_token_context(&token_ctx, (const uint8_t*)data, strlen(data), empty_delimeter);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INTERNAL_INVALID_PARAMETER, sda_status_internal);

    sda_status_internal = sda_helper_get_next_data_token(&token_ctx, &data_token_out, &data_token_out_size);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INTERNAL_INVALID_PARAMETER, sda_status_internal);

    sda_status_internal = sda_helper_init_token_context(&token_ctx, (const uint8_t*)data, strlen(data), delimeter);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INTERNAL_SUCCESS, sda_status_internal);

    sda_status_internal = sda_helper_get_next_data_token(NULL, &data_token_out, &data_token_out_size);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INTERNAL_INVALID_PARAMETER, sda_status_internal);

    sda_status_internal = sda_helper_get_next_data_token(&token_ctx, NULL, &data_token_out_size);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INTERNAL_INVALID_PARAMETER, sda_status_internal);

    sda_status_internal = sda_helper_get_next_data_token(&token_ctx, &data_token_out, NULL);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_INTERNAL_INVALID_PARAMETER, sda_status_internal);

}

TEST_GROUP_RUNNER(data_token_test)
{

    RUN_TEST_CASE(data_token_test, simple_delimeter_inside_data);
    RUN_TEST_CASE(data_token_test, simple_delimeter_on_edges);
    RUN_TEST_CASE(data_token_test, complex_delimeter_inside_data);
    RUN_TEST_CASE(data_token_test, complex_delimeter_on_edges);
    RUN_TEST_CASE(data_token_test, one_delimeter);
    RUN_TEST_CASE(data_token_test, no_delimeter);
    RUN_TEST_CASE(data_token_test, small_data);
    RUN_TEST_CASE(data_token_test, multiple_delimiter);
    RUN_TEST_CASE(data_token_test, get_token_test);
    RUN_TEST_CASE(data_token_test, sub_delimeter);

}
