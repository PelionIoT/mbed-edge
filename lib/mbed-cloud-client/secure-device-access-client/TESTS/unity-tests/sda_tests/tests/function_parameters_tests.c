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
#include "sda_bundle_parser.h"
#include "factory_configurator_client.h"
#include "sda_bundle_parser.h"
#include "sda_status_internal.h"
#include "pal.h"
#include "test_utils.h"
#include "sda_malloc.h"
#include "test_common_utils.h"

#define TEST_MAX_SIZE_OF_FUNCTION_CALL_BUNDLE  256
#define TEST_MAX_NUMBER_OF_FUNCTION_PARAMETERS 6 
typedef enum {
    SDA_STRING_PARAM,
    SDA_NUMERIC_PARAM,
} sda_param_type_e;

typedef struct string_param {
    char *parameter_name[TEST_MAX_NUMBER_OF_FUNCTION_PARAMETERS];
}string_param_s;

typedef struct test_string_parameters {
    const uint8_t function_call_data[TEST_MAX_SIZE_OF_FUNCTION_CALL_BUNDLE];
    size_t function_call_data_size;
    size_t number_of_parameters;
    string_param_s string_parameters;
} test_string_parameters_s;

typedef struct numeric_param {
    int64_t parameter_value[TEST_MAX_NUMBER_OF_FUNCTION_PARAMETERS];
}numeric_param_s;

typedef struct test_numeric_parameters {
    const uint8_t function_call_data[TEST_MAX_SIZE_OF_FUNCTION_CALL_BUNDLE];
    size_t function_call_data_size;
    size_t number_of_parameters;
    numeric_param_s numeric_parameters;
} test_numeric_parameters_s;


typedef struct mixed_param {
    sda_param_type_e param_type;
    uint32_t param_index;
}mixed_param_s;

typedef struct test_mixed_parameters {
    const uint8_t function_call_data[TEST_MAX_SIZE_OF_FUNCTION_CALL_BUNDLE];
    size_t function_call_data_size;
    size_t number_of_parameters;
    mixed_param_s params_data[TEST_MAX_SIZE_OF_FUNCTION_CALL_BUNDLE];
    numeric_param_s numeric_parameters;
    string_param_s string_parameters;
} test_mixed_parameters_s;


typedef struct test_bad_parameters {
    const uint8_t function_call_data[TEST_MAX_SIZE_OF_FUNCTION_CALL_BUNDLE];
    size_t function_call_data_size;
    sda_status_e expected_sda_status;
} test_bad_parameters_s;


test_bad_parameters_s  function_call_bad_parameter_vectors[] = {

    {   //[2, "lcd-display", ["hello"]]
        { 0x83, 0x02, 0x6B, 0x6C, 0x63, 0x64, 0x2D, 0x64, 0x69, 0x73, 0x70, 0x6C, 0x61, 0x79, 0x81, 0x65,
          0x68, 0x65, 0x6C, 0x6C, 0x6F},
        21,//size of function call
        SDA_STATUS_INVALID_REQUEST },//expected_sda_status

    {   // [1, "lcd-display", []]

        { 0x83, 0x01, 0x6B, 0x6C, 0x63, 0x64, 0x2D, 0x64, 0x69, 0x73, 0x70, 0x6C, 0x61, 0x79, 0x80 },
        15,//size of function call
        SDA_STATUS_INVALID_REQUEST },//expected_sda_status
    {   //[1, "lcd-display",[[123]]]
        { 0x83, 0x01, 0x6B, 0x6C, 0x63, 0x64, 0x2D, 0x64, 0x69, 0x73, 0x70, 0x6C, 0x61, 0x79, 0x81, 0x81,
          0x18, 0x7B },
        18,//size of function call
        SDA_STATUS_INVALID_REQUEST },//expected_sda_status
    {   //[1, "lcd-display", [true]]
        { 0x83, 0x01, 0x6B, 0x6C, 0x63, 0x64, 0x2D, 0x64, 0x69, 0x73, 0x70, 0x6C, 0x61, 0x79, 0x81, 0xF5 },
        16,//size of function call
        SDA_STATUS_INVALID_REQUEST },//expected_sda_status
};
size_t number_of_invalid_vectors = sizeof(function_call_bad_parameter_vectors) / sizeof(test_bad_parameters_s);


test_mixed_parameters_s function_call_mixed_parameter_vectors[] = {
    {   //[1, "lcd-display", ["hello",-345356]]
        { 0x83, 0x01, 0x6B, 0x6C, 0x63, 0x64, 0x2D, 0x64, 0x69, 0x73, 0x70, 0x6C, 0x61, 0x79, 0x82, 0x65,
          0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x3A, 0x00, 0x05, 0x45, 0x0B },
        26,//size of function call
        2,// number of parameters
        { { SDA_STRING_PARAM , 0},{ SDA_NUMERIC_PARAM ,0}},
        { {-345356} },//numeric parameters
        { { "hello" } },//string parameters

    },

    {  //[1, "lcd-display", ["hello",-345356,"kuku again", 4356,-1,"hello_again"]]
        { 0x83, 0x01, 0x6B, 0x6C, 0x63, 0x64, 0x2D, 0x64, 0x69, 0x73, 0x70, 0x6C, 0x61, 0x79, 0x86, 0x65,
          0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x3A, 0x00, 0x05, 0x45, 0x0B, 0x6A, 0x6B, 0x75, 0x6B, 0x75, 0x20,
          0x61, 0x67, 0x61, 0x69, 0x6E, 0x19, 0x11, 0x04, 0x20, 0x6B, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x5F,
          0x61, 0x67, 0x61, 0x69, 0x6E
        },
        53,//size of function call
        6,// number of parameters
        //  "hello"                       -345356                "kuku again"            4356                       -1                       "hello_again"
        { { SDA_STRING_PARAM , 0 },{ SDA_NUMERIC_PARAM ,0 },{ SDA_STRING_PARAM , 1 },{ SDA_NUMERIC_PARAM ,1 },{ SDA_NUMERIC_PARAM ,2 },{ SDA_STRING_PARAM , 2 } },
        { { -345356,4356,-1 } },//numeric parameters
        { { "hello","kuku again","hello_again" } },//string parameters
}

};
size_t number_of_mixed_vectors = sizeof(function_call_mixed_parameter_vectors) / sizeof(test_mixed_parameters_s);


test_string_parameters_s function_call_string_parameter_vectors[] = {
    {   //[1, "lcd-display", ["hello_world"]]
        {0x83, 0x01, 0x6B, 0x6C, 0x63, 0x64, 0x2D, 0x64, 0x69, 0x73, 0x70, 0x6C, 0x61, 0x79, 0x81, 0x6B,
         0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x5F, 0x77, 0x6F, 0x72, 0x6C, 0x64 },
        27,//size of function call
        1,// number of parameters
        {{"hello_world"}}//string parameters
    },
    {   //[1, "lcd-display",["hello_world","hello_again"]]
        {0x83, 0x01, 0x6B, 0x6C, 0x63, 0x64, 0x2D, 0x64, 0x69, 0x73, 0x70, 0x6C, 0x61, 0x79, 0x82, 0x6B,
         0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x5F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x6B, 0x68, 0x65, 0x6C, 0x6C,
         0x6F, 0x5F, 0x61, 0x67, 0x61, 0x69,0x6E },
        39,//size of function call
        2,// number of parameters
        {{  "hello_world" ,"hello_again" }},//string parameters
    },
    {    //[1, "lcd-display", ["hello_world","hello_again","1234_world_hello&&hello_again"]]
        { 0x83, 0x01, 0x6B, 0x6C, 0x63, 0x64, 0x2D, 0x64, 0x69, 0x73, 0x70, 0x6C, 0x61, 0x79, 0x83, 0x6B,
          0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x5F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x6B, 0x68, 0x65, 0x6C, 0x6C,
          0x6F, 0x5F, 0x61, 0x67, 0x61, 0x69, 0x6E, 0x78, 0x1D, 0x31, 0x32, 0x33, 0x34, 0x5F, 0x77, 0x6F,
          0x72, 0x6C, 0x64, 0x5F, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x26, 0x26, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
          0x5F, 0x61, 0x67, 0x61, 0x69, 0x6E },
          70,//size of function call
          3,// number of parameters
          { {"hello_world"  , "hello_again"  ,"1234_world_hello&&hello_again"}},//string parameters
    },
    {  //[1, "lcd-display", ["123456","function_parameters","function_parameters_hello_world","hello_world","hello_again","1234_world_hello&&hello_again"]]

        { 0x83, 0x01, 0x6B, 0x6C, 0x63, 0x64, 0x2D, 0x64, 0x69, 0x73, 0x70, 0x6C, 0x61, 0x79, 0x86, 0x66,
          0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x73, 0x66, 0x75, 0x6E, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x5F,
          0x70, 0x61, 0x72, 0x61, 0x6D, 0x65, 0x74, 0x65, 0x72, 0x73, 0x78, 0x1F, 0x66, 0x75, 0x6E, 0x63,
          0x74, 0x69, 0x6F, 0x6E, 0x5F, 0x70, 0x61, 0x72, 0x61, 0x6D, 0x65, 0x74, 0x65, 0x72, 0x73, 0x5F,
          0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x5F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x6B, 0x68, 0x65, 0x6C, 0x6C,
          0x6F, 0x5F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x6B, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x5F, 0x61, 0x67,
          0x61, 0x69, 0x6E, 0x78, 0x1D, 0x31, 0x32, 0x33, 0x34, 0x5F, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x5F,
          0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x26, 0x26, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x5F, 0x61, 0x67, 0x61,
          0x69, 0x6E},
          130,//size of function call
          6,// number of parameters
          {{  "123456" , "function_parameters","function_parameters_hello_world", "hello_world", "hello_again", "1234_world_hello&&hello_again"}},//string parameters
          }
};



size_t number_of_string_vectors = sizeof(function_call_string_parameter_vectors) / sizeof(test_string_parameters_s);

test_numeric_parameters_s function_call_numeric_parameter_vectors[] = {
    {   //[1, "lcd-display",[123456]]
        { 0x83, 0x01, 0x6B, 0x6C, 0x63, 0x64, 0x2D, 0x64, 0x69, 0x73, 0x70, 0x6C, 0x61, 0x79, 0x81, 0x1A,
        0x00, 0x01, 0xE2, 0x40 },
          20,//size of function call
          1,// number of parameters
          {{ 123456 }}//numeric parameters
    },
    {   //[1, "lcd-display", [123456,345356,345634563456,3456,0,1]]
        { 0x83, 0x01, 0x6B, 0x6C, 0x63, 0x64, 0x2D, 0x64, 0x69, 0x73, 0x70, 0x6C, 0x61, 0x79, 0x86, 0x1A,
          0x00, 0x01, 0xE2, 0x40, 0x1A, 0x00, 0x05, 0x45, 0x0C, 0x1B, 0x00, 0x00, 0x00, 0x50, 0x79, 0x6C,
          0xE5, 0x80, 0x19, 0x0D, 0x80, 0x00, 0x01
        },
        39,//size of function call
        6,// number of parameters
        { { 123456, 345356, 345634563456, 3456, 0, 1 }}//numeric parameters
    },
    {   //[1, "lcd-display", [123456,345356,345634563456,3456,0,1]]
        { 0x83, 0x01, 0x6B, 0x6C, 0x63, 0x64, 0x2D, 0x64, 0x69, 0x73, 0x70, 0x6C, 0x61, 0x79, 0x86, 0x1A,
          0x00, 0x01, 0xE2, 0x40, 0x3A, 0x00, 0x05, 0x45, 0x0B, 0x1B, 0x00, 0x00, 0x00, 0x50, 0x79, 0x6C,
          0xE5, 0x80, 0x19, 0x0D, 0x80, 0x00, 0x20
        },
        39,//size of function call
        6,// number of parameters
        {{ 123456, -345356, 345634563456, 3456, 0, -1 }}//numeric parameters
    }

};

size_t number_of_numeric_vectors = sizeof(function_call_numeric_parameter_vectors) / sizeof(test_numeric_parameters_s);

static void test_get_function_call_to_handle(const uint8_t *function_call_bundle,
                                             size_t function_call_bundle_size,
                                             sda_message_data_s  *message_data,
                                             sda_ctx_internal_s *sda_internal_ctx,
                                             size_t *out_num_of_parameters)
{
    sda_user_operation_data_s user_operation;
    CborValue user_operation_data; // A CBOR representing the operation.
    CborValue user_operation_array;
    CborError  cbor_error = CborNoError;
    CborParser parser;
    size_t array_size = 0;
    sda_status_e sda_status = SDA_STATUS_SUCCESS;

    message_data->user_operation_encoded_buffer.data_buffer_ptr = function_call_bundle;
    message_data->user_operation_encoded_buffer.data_buffer_size = function_call_bundle_size;

    //Initialize cbor parser with encoded buffer
    cbor_error = cbor_parser_init(function_call_bundle, function_call_bundle_size, 0, &parser, &user_operation_data);
    TEST_ASSERT_EQUAL(cbor_error, CborNoError);

    //todo -> retrive array lenght
    cbor_error = cbor_value_enter_container(&user_operation_data, &user_operation_array);
    TEST_ASSERT_EQUAL(cbor_error, CborNoError);

    //Check and get user operation
    cbor_error = cbor_value_advance(&user_operation_array);
    TEST_ASSERT_EQUAL(cbor_error, CborNoError);
    TEST_ASSERT_EQUAL(cbor_value_get_type(&user_operation_array), CborTextStringType);


    //Check and get access token
    cbor_error = cbor_value_advance(&user_operation_array);
    TEST_ASSERT_EQUAL(cbor_error, CborNoError);
    TEST_ASSERT_EQUAL(cbor_value_get_type(&user_operation_array), CborArrayType);

    cbor_error = cbor_value_get_array_length(&user_operation_array, &array_size);
    TEST_ASSERT_EQUAL(cbor_error, CborNoError);

    *out_num_of_parameters = (size_t)array_size;
   // memcpy(&message_data->user_operation_data, &user_operation_data, sizeof(CborValue));

    //message_data->user_operation_data = user_operation_data;
    sda_user_operation_parse(message_data);
    //TEST_ASSERT_EQUAL(SDA_STATUS_SUCCESS, sda_status);

    sda_internal_ctx->message_data = *message_data;

    sda_internal_ctx->message_state = SDA_OP_PROCESSING_MESSAGE;
}

TEST_GROUP(function_parameters);

TEST_SETUP(function_parameters)
{

    sda_status_e sda_status;

    fcc_tst_setup();
    TEST_SKIP_EXECUTION_ON_FAILURE();

    sda_status = sda_init();
    TEST_ASSERT(sda_status == SDA_STATUS_SUCCESS);

}


TEST_TEAR_DOWN(function_parameters)
{
    fcc_status_e fcc_status;
    sda_status_e sda_status;

    sda_status = sda_finalize();
    TEST_ASSERT(sda_status == SDA_STATUS_SUCCESS);
    
    fcc_tst_tear_down();
    TEST_SKIP_EXECUTION_ON_FAILURE();

}



TEST(function_parameters, sda_get_string_parameters_positive)
{
    sda_status_e sda_status = SDA_STATUS_SUCCESS;
    uint8_t *out_string_param = NULL;
    size_t string_param_size_out = 0;
    sda_ctx_internal_s sda_internal_ctx;
    sda_operation_ctx_h handle = (sda_operation_ctx_h*)&sda_internal_ctx;
    uint32_t function_call_data_index = 0;
    uint32_t function_parameter_index = 0;
    size_t num_of_parameters = 0;
    size_t expected_sizeof_parameter_name = 0;
    char *expected_parameter_name = NULL;
    sda_message_data_s  message_data;

    for (function_call_data_index = 0; function_call_data_index < number_of_string_vectors; function_call_data_index++) {

        test_get_function_call_to_handle(function_call_string_parameter_vectors[function_call_data_index].function_call_data,
                                         function_call_string_parameter_vectors[function_call_data_index].function_call_data_size,
                                         &message_data,
                                         &sda_internal_ctx,
                                         &num_of_parameters);
        TEST_SKIP_EXECUTION_ON_FAILURE();
        //Check number of parameters in function call bundle against num of parameters in test vector
        TEST_ASSERT_EQUAL(num_of_parameters, function_call_string_parameter_vectors[function_call_data_index].number_of_parameters);

        for (function_parameter_index = 0; function_parameter_index < num_of_parameters; function_parameter_index++) {
            //Get function data parameter
            sda_status = sda_func_call_data_parameter_get(handle, function_parameter_index, (const uint8_t**)&out_string_param, &string_param_size_out);
            TEST_ASSERT_EQUAL(SDA_STATUS_SUCCESS, sda_status);

            //Set test parameters
            expected_sizeof_parameter_name = strlen(function_call_string_parameter_vectors[function_call_data_index].string_parameters.parameter_name[function_parameter_index]);
            expected_parameter_name = function_call_string_parameter_vectors[function_call_data_index].string_parameters.parameter_name[function_parameter_index];

            //Check test results
            TEST_ASSERT_EQUAL(expected_sizeof_parameter_name, string_param_size_out);
            TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(expected_parameter_name, out_string_param, string_param_size_out, "Failed in check of string param");
            string_param_size_out = 0;
            out_string_param = NULL;
        }
    }
}

TEST(function_parameters, sda_get_numeric_parameters_positive)
{

    sda_status_e sda_status = SDA_STATUS_SUCCESS;
    int64_t out_numeric_param = 0;
    int64_t expected_test_numeric_param = 0;
    sda_ctx_internal_s sda_internal_ctx;
    sda_operation_ctx_h handle = (sda_operation_ctx_h*)&sda_internal_ctx;
    uint32_t function_call_data_index = 0;
    uint32_t function_parameter_index = 0;
    size_t num_of_parameters = 0;
    sda_message_data_s  message_data;


    for (function_call_data_index = 0; function_call_data_index < number_of_numeric_vectors; function_call_data_index++) {

        test_get_function_call_to_handle(function_call_numeric_parameter_vectors[function_call_data_index].function_call_data,
                                         function_call_numeric_parameter_vectors[function_call_data_index].function_call_data_size,
                                         &message_data,
                                         &sda_internal_ctx,
                                         &num_of_parameters);
        TEST_SKIP_EXECUTION_ON_FAILURE();

        //Check number of parameters in function call bundle against num of parameters in test vector
        TEST_ASSERT_EQUAL(num_of_parameters, function_call_numeric_parameter_vectors[function_call_data_index].number_of_parameters);


        for (function_parameter_index = 0; function_parameter_index < num_of_parameters; function_parameter_index++) {
            //Get function string parameter
            sda_status = sda_func_call_numeric_parameter_get(handle, function_parameter_index, &out_numeric_param);
            TEST_ASSERT_EQUAL(SDA_STATUS_SUCCESS, sda_status);

            //Set test parameters
            expected_test_numeric_param = function_call_numeric_parameter_vectors[function_call_data_index].numeric_parameters.parameter_value[function_parameter_index];

            //Check test results
            TEST_ASSERT_EQUAL(expected_test_numeric_param, out_numeric_param);
            expected_test_numeric_param = 0;
        }
    }
}

TEST(function_parameters, sda_get_mixed_parameters_positive)
{

    sda_status_e sda_status = SDA_STATUS_SUCCESS;
    int64_t out_numeric_param = 0;
    int64_t expected_test_numeric_param = 0;
    sda_ctx_internal_s sda_internal_ctx;
    sda_operation_ctx_h handle = (sda_operation_ctx_h*)&sda_internal_ctx;
    uint32_t function_call_data_index = 0;
    uint32_t function_parameter_index = 0;
    size_t num_of_parameters = 0;
    uint32_t test_param_index = 0;
    uint8_t *out_string_param = NULL;
    size_t string_param_size_out = 0;
    char *expected_test_parameter_name = NULL;
    size_t expected_sizeof_parameter_name = 0;
    sda_message_data_s  message_data;


    for (function_call_data_index = 0; function_call_data_index < number_of_mixed_vectors; function_call_data_index++) {

        test_get_function_call_to_handle(function_call_mixed_parameter_vectors[function_call_data_index].function_call_data,
                                         function_call_mixed_parameter_vectors[function_call_data_index].function_call_data_size,
                                         &message_data,
                                         &sda_internal_ctx,
                                         &num_of_parameters);
        TEST_SKIP_EXECUTION_ON_FAILURE();

        //Check number of parameters in function call bundle against num of parameters in test vector
        TEST_ASSERT_EQUAL(num_of_parameters, function_call_mixed_parameter_vectors[function_call_data_index].number_of_parameters);


        for (function_parameter_index = 0; function_parameter_index < num_of_parameters; function_parameter_index++) {
            if (function_call_mixed_parameter_vectors[function_call_data_index].params_data[function_parameter_index].param_type == SDA_NUMERIC_PARAM) {

                //Get function numeric parameter
                sda_status = sda_func_call_numeric_parameter_get(handle, function_parameter_index, &out_numeric_param);
                TEST_ASSERT_EQUAL(SDA_STATUS_SUCCESS, sda_status);

                test_param_index = function_call_mixed_parameter_vectors[function_call_data_index].params_data[function_parameter_index].param_index;
                //Set test parameters
                expected_test_numeric_param = function_call_mixed_parameter_vectors[function_call_data_index].numeric_parameters.parameter_value[test_param_index];

                //Check test results
                TEST_ASSERT_EQUAL(expected_test_numeric_param, out_numeric_param);
                expected_test_numeric_param = 0;
            } else {
                //Get function data parameter
                sda_status = sda_func_call_data_parameter_get(handle, function_parameter_index, (const uint8_t**)&out_string_param, &string_param_size_out);
                TEST_ASSERT_EQUAL(SDA_STATUS_SUCCESS, sda_status);

                //Set test parameters
                test_param_index = function_call_mixed_parameter_vectors[function_call_data_index].params_data[function_parameter_index].param_index;
                //Set test parameters
                expected_test_parameter_name = function_call_mixed_parameter_vectors[function_call_data_index].string_parameters.parameter_name[test_param_index];
                expected_sizeof_parameter_name = strlen(expected_test_parameter_name);

                //Check test results
                TEST_ASSERT_EQUAL(expected_sizeof_parameter_name, string_param_size_out);
                TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(expected_test_parameter_name, out_string_param, string_param_size_out, "Failed in check of string param");
                string_param_size_out = 0;
                out_string_param = NULL;
            }
        }
    }
}

TEST(function_parameters, sda_get_string_bad_params)
{

    sda_status_e sda_status = SDA_STATUS_SUCCESS;
    uint8_t *out_string_param = NULL;
    size_t num_of_parameters = 0;
    sda_ctx_internal_s sda_internal_ctx;
    sda_operation_ctx_h handle = (sda_operation_ctx_h*)&sda_internal_ctx;
    sda_message_data_s  message_data;
    size_t string_param_size_out = 0;

    test_get_function_call_to_handle(function_call_string_parameter_vectors[0].function_call_data,
                                     function_call_string_parameter_vectors[0].function_call_data_size,
                                     &message_data,
                                     &sda_internal_ctx,
                                     &num_of_parameters);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    sda_status = sda_func_call_data_parameter_get(NULL, 0, (const uint8_t**)&out_string_param, &string_param_size_out);
    TEST_ASSERT_EQUAL(SDA_STATUS_INVALID_REQUEST, sda_status);

    sda_status = sda_func_call_data_parameter_get(handle, 10, (const uint8_t**)&out_string_param, &string_param_size_out);
    TEST_ASSERT_EQUAL(SDA_STATUS_INVALID_REQUEST, sda_status);

    sda_status = sda_func_call_data_parameter_get(handle, 0, (const uint8_t**)&out_string_param, NULL);
    TEST_ASSERT_EQUAL(SDA_STATUS_INVALID_REQUEST, sda_status);
}

TEST(function_parameters, sda_get_numeric_bad_params)
{

    sda_status_e sda_status = SDA_STATUS_SUCCESS;
    int64_t out_numeric_param = 0;
    sda_ctx_internal_s sda_internal_ctx;
    sda_operation_ctx_h handle = (sda_operation_ctx_h*)&sda_internal_ctx;
    uint32_t function_parameter_index = 0;
    size_t num_of_parameters = 0;
    sda_message_data_s  message_data;

    test_get_function_call_to_handle(function_call_numeric_parameter_vectors[0].function_call_data,
                                     function_call_numeric_parameter_vectors[0].function_call_data_size,
                                     &message_data,
                                     &sda_internal_ctx,
                                     &num_of_parameters);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Get function string parameter
    sda_status = sda_func_call_numeric_parameter_get(NULL, function_parameter_index, &out_numeric_param);
    TEST_ASSERT_EQUAL(SDA_STATUS_INVALID_REQUEST, sda_status);

    //Get function string parameter
    sda_status = sda_func_call_numeric_parameter_get(handle, 10, &out_numeric_param);
    TEST_ASSERT_EQUAL(SDA_STATUS_INVALID_REQUEST, sda_status);

    //Get function string parameter
    sda_status = sda_func_call_numeric_parameter_get(handle, function_parameter_index, NULL);
    TEST_ASSERT_EQUAL(SDA_STATUS_INVALID_REQUEST, sda_status);
}

TEST(function_parameters, sda_invalid_function_call_bundle)
{

    sda_status_e sda_status = SDA_STATUS_SUCCESS;
    int64_t out_numeric_param = 0;
    sda_ctx_internal_s sda_internal_ctx;
    sda_operation_ctx_h handle = (sda_operation_ctx_h*)&sda_internal_ctx;
    uint32_t function_call_data_index = 0;
    uint32_t function_parameter_index = 0;
    size_t num_of_parameters = 0;
    sda_message_data_s  message_data;


    for (function_call_data_index = 0; function_call_data_index < number_of_invalid_vectors; function_call_data_index++) {

        test_get_function_call_to_handle(function_call_bad_parameter_vectors[function_call_data_index].function_call_data,
                                         function_call_bad_parameter_vectors[function_call_data_index].function_call_data_size,
                                         &message_data,
                                         &sda_internal_ctx,
                                         &num_of_parameters);
        TEST_SKIP_EXECUTION_ON_FAILURE();

        //Get function string parameter
        sda_status = sda_func_call_numeric_parameter_get(handle, function_parameter_index, &out_numeric_param);
        TEST_ASSERT_EQUAL(function_call_bad_parameter_vectors[function_call_data_index].expected_sda_status, sda_status);
    }
}
TEST_GROUP_RUNNER(function_parameters)
{
    //positive tests
    RUN_TEST_CASE(function_parameters, sda_get_string_parameters_positive);
    RUN_TEST_CASE(function_parameters, sda_get_numeric_parameters_positive);
    RUN_TEST_CASE(function_parameters, sda_get_mixed_parameters_positive);
    RUN_TEST_CASE(function_parameters, sda_get_string_bad_params);
    RUN_TEST_CASE(function_parameters, sda_get_numeric_bad_params);
    RUN_TEST_CASE(function_parameters, sda_invalid_function_call_bundle);
}

