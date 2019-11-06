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
#include "factory_configurator_client.h"
#include "sda_status.h"
#include "sda_bundle_parser.h"
#include "pal.h"
#include "test_utils.h"
#include "sda_malloc.h"
#include "sda_trust_anchor.h"
#include "sda_verification.h"
#include "sda_testdata.h"
#include "sda_error_handling.h"
#include "test_common_utils.h"


#define TEST_SDA_RESPONSE_TYPE_ID_INDEX 0
#define TEST_SDA_RESPONSE_STATUS_INDEX  1
#define TEST_SDA_RESPONSE_NONCE_INDEX 2
#define TEST_SDA_USER_STRING "Test user buffer"
#define TEST_SDA_USER_STRING_SIZE (sizeof(TEST_SDA_USER_STRING) - 1)
#define TEST_SDA_RESPONSE_MESSAGE_SIZE (SDA_RESPONSE_HEADER_SIZE + TEST_SDA_USER_STRING_SIZE)

static void check_response(sda_message_id_e type_id, int status, uint8_t *sda_response_cbor, size_t sda_responce_cbor_size, uint64_t *responce_nonce)
{
    CborError cbor_error = CborNoError;
    CborParser parser;
    CborValue sda_responce_array;
    CborValue type_id_value;
    CborValue status_value;
    CborValue nonce_value;
    CborValue user_buffer_value;
    size_t sda_responce_array_size = 0;
    uint32_t type_id_int = 0;
    uint32_t status_int = 0;
    uint32_t user_buffer_size;
    uint8_t *user_buffer_ptr;
    uint64_t nonce = 0;

    //check cbor params
    TEST_ASSERT_NOT_EQUAL(NULL, sda_response_cbor);
    TEST_ASSERT_NOT_EQUAL(0, sda_responce_cbor_size);

    cbor_error = cbor_parser_init(sda_response_cbor, sda_responce_cbor_size, 0, &parser, &sda_responce_array);
    TEST_ASSERT_EQUAL(cbor_error, CborNoError);
    TEST_ASSERT_EQUAL(true, cbor_value_is_map(&sda_responce_array));

    //check type-id
    cbor_error = cbor_get_map_element_by_int_key(&sda_responce_array, SDA_RESPONSE_MAP_KEY_TYPE, &type_id_value);
    TEST_ASSERT_EQUAL_INT(CborNoError, cbor_error);
    TEST_ASSERT_EQUAL(true, cbor_value_is_integer(&type_id_value));

    //Get id type as int
    cbor_error = cbor_value_get_int(&type_id_value, (int*)&type_id_int);
    TEST_ASSERT_EQUAL_INT(CborNoError, cbor_error);
    TEST_ASSERT_EQUAL(true, type_id_int > 0);
    TEST_ASSERT_EQUAL_INT(type_id, type_id_int);

    //check status
    cbor_error = cbor_get_map_element_by_int_key(&sda_responce_array, SDA_RESPONSE_MAP_KEY_RESULT, &status_value);
    TEST_ASSERT_EQUAL_INT(cbor_error, CborNoError);
    TEST_ASSERT_EQUAL(true, cbor_value_is_integer(&status_value));

    //Get result as int
    cbor_error = cbor_value_get_int(&status_value, (int*)&status_int);
    TEST_ASSERT_EQUAL_INT(cbor_error, CborNoError);
    TEST_ASSERT_EQUAL(true, status_int >= 0);
    TEST_ASSERT_EQUAL_INT(status, status_int);

    // If status is success and message type is operation, check for the test user buffer
    if (status_int == SDA_STATUS_SUCCESS && type_id_int == SDA_OPERATION_RESPONSE_MESSAGE_ID) {
        cbor_error = cbor_get_map_element_by_int_key(&sda_responce_array, SDA_RESPONSE_MAP_KEY_USER_BUFFER, &user_buffer_value);
        TEST_ASSERT_EQUAL_INT(CborNoError, cbor_error);
        TEST_ASSERT_EQUAL(true, cbor_value_is_byte_string(&user_buffer_value));

        //Get id type as int
        cbor_error = cbor_value_get_byte_string_chunk(&user_buffer_value, &user_buffer_ptr, &user_buffer_size, NULL);
        TEST_ASSERT_EQUAL_INT(CborNoError, cbor_error);
        TEST_ASSERT_EQUAL_INT(TEST_SDA_USER_STRING_SIZE, user_buffer_size);
        TEST_ASSERT_EQUAL_MEMORY(TEST_SDA_USER_STRING, user_buffer_ptr, TEST_SDA_USER_STRING_SIZE);
    }

    if (type_id == SDA_NONCE_RESPONSE_MESSAGE_ID) {

        cbor_error = cbor_get_map_element_by_int_key(&sda_responce_array, SDA_RESPONSE_MAP_KEY_NONCE, &nonce_value);

        TEST_ASSERT_EQUAL_INT(CborNoError, cbor_error);
        TEST_ASSERT_EQUAL(true, cbor_value_is_unsigned_integer(&nonce_value));

        cbor_error = cbor_value_get_uint64(&nonce_value, &nonce);
        TEST_ASSERT_EQUAL_INT(CborNoError, cbor_error);
        TEST_ASSERT_EQUAL(true, nonce > 0);
        if (responce_nonce != NULL) {
            *responce_nonce = nonce;
        }

    }
}

sda_status_e sda_test_callback_return_error(sda_operation_ctx_h handle)
{
    sda_status_e sda_status = SDA_STATUS_SUCCESS;
    sda_command_type_e command_type;

    sda_status = sda_command_type_get(handle, &command_type);
    SDA_ERR_RECOVERABLE_RETURN_IF(sda_status != SDA_STATUS_SUCCESS, sda_status, "Failed to get command type");
    SDA_ERR_RECOVERABLE_RETURN_IF(SDA_OPERATION_FUNC_CALL != command_type, sda_status = SDA_STATUS_INVALID_REQUEST, "Wrong command type");

    return SDA_STATUS_INVALID_REQUEST;
}

//Positive flow of user callback
sda_status_e sda_test_callback(sda_operation_ctx_h handle, void *callback_param)
{
    sda_status_e sda_status = SDA_STATUS_SUCCESS;
    char* scope_to_compare = "lcd-display-hello";
    size_t scope_size;
    char* func_call_name;
    size_t func_call_name_size;
    char* func_call_name_to_compare = "lcd-display";
    uint8_t *string_param = NULL;
    size_t string_param_size_out = 0;
    int64_t numeric_param = 0;
    int64_t expected_numeric_param = 5;
    const char function_param[] = "hello";
    sda_command_type_e command_type;
    char *scope = NULL;
    uint16_t *check_callback_param = (uint16_t*)callback_param;

    sda_status = sda_command_type_get(handle, &command_type);
    SDA_ERR_RECOVERABLE_RETURN_IF(sda_status != SDA_STATUS_SUCCESS, sda_status, "Failed to get command type");
    SDA_ERR_RECOVERABLE_RETURN_IF(SDA_OPERATION_FUNC_CALL != command_type, sda_status = SDA_STATUS_INVALID_REQUEST, "Wrong command type");

    sda_status = sda_func_call_data_parameter_get(handle, 0, (const uint8_t**)&string_param, &string_param_size_out);
    SDA_ERR_RECOVERABLE_RETURN_IF(sda_status != SDA_STATUS_SUCCESS, sda_status, "Failed to get string parameter");
    SDA_ERR_RECOVERABLE_RETURN_IF((memcmp(function_param, string_param, string_param_size_out) != 0), sda_status = SDA_STATUS_INVALID_REQUEST, "Wrong string function parameter");

    sda_status = sda_func_call_numeric_parameter_get(handle, 1, &numeric_param);
    SDA_ERR_RECOVERABLE_RETURN_IF(sda_status != SDA_STATUS_SUCCESS, sda_status, "Failed to get numeric parameter");
    SDA_ERR_RECOVERABLE_RETURN_IF(expected_numeric_param != numeric_param, sda_status = SDA_STATUS_INVALID_REQUEST, "Wrong numeric parameter");

    sda_status = sda_scope_get_next(handle, (const uint8_t**)&scope, &scope_size);
    SDA_ERR_RECOVERABLE_RETURN_IF(sda_status != SDA_STATUS_SUCCESS, sda_status, "Failed to get scope");
    SDA_ERR_RECOVERABLE_RETURN_IF((memcmp(scope_to_compare, scope, scope_size) != 0), sda_status = SDA_STATUS_INVALID_REQUEST, "Failed in scope check ");


    sda_status = sda_func_call_name_get(handle, (const uint8_t**)&func_call_name, &func_call_name_size);
    SDA_ERR_RECOVERABLE_RETURN_IF(sda_status != SDA_STATUS_SUCCESS, sda_status, "Failed to get function call name");
    SDA_ERR_RECOVERABLE_RETURN_IF((memcmp(func_call_name_to_compare, func_call_name, func_call_name_size) != 0), sda_status = SDA_STATUS_INVALID_REQUEST, "Failed in function call name check ");

    sda_status = sda_response_data_set(handle, (uint8_t*)TEST_SDA_USER_STRING, TEST_SDA_USER_STRING_SIZE);
    SDA_ERR_RECOVERABLE_RETURN_IF(sda_status != SDA_STATUS_SUCCESS, sda_status, "Failed to set user data");

    if (callback_param != NULL) {
        SDA_ERR_RECOVERABLE_RETURN_IF(*check_callback_param != 0xad, sda_status, "Failed to check callback parameter");
    }
    return SDA_STATUS_SUCCESS;
}



TEST_GROUP(sda_test);

TEST_SETUP(sda_test)
{
    fcc_status_e fcc_status;
    sda_status_e sda_status;
    uint64_t nonce_data = 664396747115767313;// 14785200172873371264;
    const char enpoint_name[] = "0160c1976ccf0a580a010e1303c00000";
    const char device_id[] = "f90b1017e52f4c70ad92684e802c9249";

    fcc_tst_setup();
    TEST_SKIP_EXECUTION_ON_FAILURE();

    sda_status = sda_init();
    TEST_ASSERT(sda_status == SDA_STATUS_SUCCESS);

    //set trust anchor
    sda_status = test_provisioning_setup(
        false, (const uint8_t*)g_trust_anchor_name, sizeof(g_trust_anchor_name),
        g_trust_anchor, SDA_TRUST_ANCHOR_SIZE, (const uint8_t *)device_id,
       strlen(device_id), (const uint8_t*)enpoint_name, strlen(enpoint_name));
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_SUCCESS, sda_status);

    //set nonce
    test_sda_nonce_set(nonce_data);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_SUCCESS, sda_status);
}

TEST_TEAR_DOWN(sda_test)
{
    fcc_status_e fcc_status;
    sda_status_e sda_status;

    sda_status = sda_finalize();
    TEST_ASSERT(sda_status == SDA_STATUS_SUCCESS);

    fcc_tst_tear_down();
    TEST_SKIP_EXECUTION_ON_FAILURE();
}


TEST(sda_test, sda_nonce_request_positive)
{
    sda_status_e sda_status = SDA_STATUS_SUCCESS;
    uint8_t sda_nonce_response[TEST_SDA_RESPONSE_MESSAGE_SIZE] = { 0 };
    size_t actual_sda_nonce_response_size;
    uint64_t temp_nonce_result = 0;
    const uint8_t nonce_request_blob[] = { 0x81,0x01 };
    uint64_t responce_nonce = 0;

    for (int i = 0; i < 12; i++) {

        //Call to sda_operation_process with nonce request 1
        sda_status = sda_operation_process(nonce_request_blob, sizeof(nonce_request_blob), NULL, NULL, sda_nonce_response, sizeof(sda_nonce_response), &actual_sda_nonce_response_size);
        TEST_ASSERT_EQUAL(SDA_STATUS_SUCCESS, sda_status);

        //Check first response
        check_response(SDA_NONCE_RESPONSE_MESSAGE_ID, SDA_STATUS_SUCCESS, sda_nonce_response, actual_sda_nonce_response_size,&responce_nonce);
        if (i > 0) {
            TEST_ASSERT(responce_nonce != temp_nonce_result);
        }

        temp_nonce_result = responce_nonce;
    }
}

TEST(sda_test, sda_operation_request_positive)
{
    sda_status_e sda_status = SDA_STATUS_SUCCESS;
    uint8_t sda_operation_response[TEST_SDA_RESPONSE_MESSAGE_SIZE] = { 0 };
    size_t actual_sda_operation_response_size;
    uint16_t callback_parameter = 0xad;

    test_sda_nonce_set(g_lcd_display_nonce);

    //Call to sda_operation_process with operation request
    sda_status = sda_operation_process(g_lcd_display_operation_bundle, sizeof(g_lcd_display_operation_bundle), *sda_test_callback, (void*)&callback_parameter, sda_operation_response, sizeof(sda_operation_response), &actual_sda_operation_response_size);
    TEST_ASSERT_EQUAL(SDA_STATUS_SUCCESS , sda_status);

    check_response(SDA_OPERATION_RESPONSE_MESSAGE_ID, SDA_STATUS_SUCCESS, sda_operation_response, actual_sda_operation_response_size, NULL);
}

TEST(sda_test, sda_operation_request_response_too_small)
{
    sda_status_e sda_status = SDA_STATUS_SUCCESS;
	// allocate smaller buffer for the operation response
    uint8_t sda_operation_response[TEST_SDA_RESPONSE_MESSAGE_SIZE - 1] = { 0 };
    size_t actual_sda_operation_response_size;

    test_sda_nonce_set(g_lcd_display_nonce);

    //Call to sda_operation_process with operation request
    sda_status = sda_operation_process(g_lcd_display_operation_bundle, sizeof(g_lcd_display_operation_bundle), *sda_test_callback, NULL, sda_operation_response, sizeof(sda_operation_response), &actual_sda_operation_response_size);
    TEST_ASSERT_EQUAL(SDA_STATUS_INSUFFICIENT_RESPONSE_BUFFER_SIZE_ERROR, sda_status);

    check_response(SDA_OPERATION_RESPONSE_MESSAGE_ID, SDA_STATUS_INSUFFICIENT_RESPONSE_BUFFER_SIZE_ERROR, 
                   sda_operation_response, actual_sda_operation_response_size, NULL);
}

TEST(sda_test, sda_operation_request_callback_negative)
{
    sda_status_e sda_status = SDA_STATUS_SUCCESS;
    uint8_t sda_operation_response[TEST_SDA_RESPONSE_MESSAGE_SIZE] = { 0 };
    size_t actual_sda_operation_response_size;

    test_sda_nonce_set(g_lcd_display_nonce);

    //Call to sda_operation_process with error callback
    sda_status = sda_operation_process(g_lcd_display_operation_bundle, sizeof(g_lcd_display_operation_bundle), *sda_test_callback_return_error, NULL, sda_operation_response, sizeof(sda_operation_response), &actual_sda_operation_response_size);
    TEST_ASSERT_EQUAL(SDA_STATUS_INVALID_REQUEST, sda_status);

    check_response(SDA_OPERATION_RESPONSE_MESSAGE_ID, SDA_STATUS_INVALID_REQUEST, sda_operation_response, actual_sda_operation_response_size, NULL);

    test_sda_nonce_set(g_lcd_display_nonce);

    //User callback is - Null
    sda_status = sda_operation_process(g_lcd_display_operation_bundle, sizeof(g_lcd_display_operation_bundle), NULL, NULL, sda_operation_response, sizeof(sda_operation_response), &actual_sda_operation_response_size);
    TEST_ASSERT_EQUAL(SDA_STATUS_INVALID_REQUEST, sda_status);

    check_response(SDA_OPERATION_RESPONSE_MESSAGE_ID, SDA_STATUS_INVALID_REQUEST, sda_operation_response, actual_sda_operation_response_size, NULL);
}

TEST(sda_test, sda_test_scope_array)
{
    char scope_array[] = "test_scope test_scope_1 lcd_display_hello";
    char *scope_test_array[] = { "test_scope", "test_scope_1", "lcd_display_hello" };
    char* single_scope_out;
    sda_ctx_internal_s handle;
    sda_status_e sda_status = SDA_STATUS_SUCCESS;
    char* scope_delimiter = " ";
    size_t single_scope_out_size;

    //initialize handle array
    memset(&handle, 0x0, sizeof(sda_ctx_internal_s));
    handle.message_state = SDA_OP_PROCESSING_MESSAGE;

    //set scope array
    handle.message_data.claims.scope_data = (uint8_t*)scope_array;
    handle.message_data.claims.scope_data_size = strlen(scope_array);

    //init token context
    sda_status = sda_helper_init_token_context(&(handle.message_data.data_token_ctx), handle.message_data.claims.scope_data,
                                               handle.message_data.claims.scope_data_size, scope_delimiter);
    TEST_ASSERT_EQUAL(SDA_STATUS_SUCCESS, sda_status);

    for (int i = 0; i < 10; i++) {

        for (int j = 0; j < 3; j++) {

            SDA_LOG_INFO("%s\n", scope_test_array[j]);

            sda_status = sda_scope_get_next((sda_operation_ctx_h)&handle, (const uint8_t**)&single_scope_out, &single_scope_out_size);
            TEST_ASSERT_EQUAL(SDA_STATUS_SUCCESS, sda_status);
            TEST_ASSERT_EQUAL_MEMORY(scope_test_array[j], single_scope_out, single_scope_out_size);
        }
        sda_status = sda_scope_get_next((sda_operation_ctx_h)&handle, (const uint8_t**)&single_scope_out, &single_scope_out_size);
        TEST_ASSERT_EQUAL(SDA_STATUS_NO_MORE_SCOPES, sda_status);
    }
}


TEST(sda_test, sda_check_params)
{

    sda_status_e sda_status = SDA_STATUS_SUCCESS;
    uint8_t sda_operation_response[TEST_SDA_RESPONSE_MESSAGE_SIZE] = { 0 };
    size_t actual_sda_operation_response_size;
    sda_ctx_internal_s sda_internal_ctx;
    sda_operation_ctx_h handle = (sda_operation_ctx_h*)&sda_internal_ctx;
    sda_command_type_e command_type;
    char *scope = NULL;
    size_t scope_size;
    char* func_call_name = NULL;
    size_t func_call_name_size;

    // Set initial state
    sda_internal_ctx.message_state = SDA_OP_START_PROCESSING_MESSAGE;

    //sda_operation_process params
    sda_status = sda_operation_process( NULL, sizeof(g_lcd_display_operation_bundle), NULL, NULL, sda_operation_response, sizeof(sda_operation_response), &actual_sda_operation_response_size);
    TEST_ASSERT_EQUAL(SDA_STATUS_INVALID_REQUEST, sda_status);
    sda_status = sda_operation_process( g_lcd_display_operation_bundle, 0, NULL, NULL, sda_operation_response, sizeof(sda_operation_response), &actual_sda_operation_response_size);
    TEST_ASSERT_EQUAL(SDA_STATUS_INVALID_REQUEST, sda_status);

    //sda_command_type_get params
    sda_status = sda_command_type_get(NULL, &command_type);
    TEST_ASSERT_EQUAL(SDA_STATUS_INVALID_REQUEST, sda_status);
    sda_status = sda_command_type_get(handle, NULL);
    TEST_ASSERT_EQUAL(SDA_STATUS_INVALID_REQUEST, sda_status);

    //sda_scope_get_next params
    sda_status = sda_scope_get_next(NULL, (const uint8_t**)&scope, &scope_size);
    TEST_ASSERT_EQUAL(SDA_STATUS_INVALID_REQUEST, sda_status);
    sda_status = sda_scope_get_next(handle, NULL, &scope_size);
    TEST_ASSERT_EQUAL(SDA_STATUS_INVALID_REQUEST, sda_status);
    sda_status = sda_scope_get_next(handle, (const uint8_t**)&scope, NULL);
    TEST_ASSERT_EQUAL(SDA_STATUS_INVALID_REQUEST, sda_status);

    //sda_func_call_name_get params  
    sda_status = sda_func_call_name_get(NULL, (const uint8_t**)&func_call_name, &func_call_name_size);
    TEST_ASSERT_EQUAL(SDA_STATUS_INVALID_REQUEST, sda_status);
    sda_status = sda_func_call_name_get(handle, NULL, &func_call_name_size);
    TEST_ASSERT_EQUAL(SDA_STATUS_INVALID_REQUEST, sda_status);
    sda_status = sda_func_call_name_get(handle, (const uint8_t**)&func_call_name, NULL);
    TEST_ASSERT_EQUAL(SDA_STATUS_INVALID_REQUEST, sda_status);
}

TEST(sda_test, sda_nonce_request_negative)
{
    sda_status_e sda_status = SDA_STATUS_SUCCESS;
    uint8_t sda_nonce_response[TEST_SDA_RESPONSE_MESSAGE_SIZE] = { 0 };
    size_t actual_sda_nonce_response_size;
    const uint8_t nonce_request_wrong_type_blob[] = { 0xa1,0x41,0x32,0x03 };

    //Call to  sda_operation_process with nonce request
    sda_status = sda_operation_process(nonce_request_wrong_type_blob, sizeof(nonce_request_wrong_type_blob), NULL , NULL, sda_nonce_response, sizeof(sda_nonce_response), &actual_sda_nonce_response_size);
    TEST_ASSERT_EQUAL(SDA_STATUS_INVALID_REQUEST, sda_status);

    check_response(SDA_ERROR_MESSAGE_ID, SDA_STATUS_INVALID_REQUEST, sda_nonce_response, actual_sda_nonce_response_size, NULL);
}

TEST(sda_test, sda_operation_request_negative)
{
    sda_status_e sda_status = SDA_STATUS_SUCCESS;
    uint8_t sda_operation_response[TEST_SDA_RESPONSE_MESSAGE_SIZE] = { 0 };
    size_t actual_sda_operation_response_size;

    uint8_t *operation_request_wrong_signature_blob = sda_malloc(sizeof(g_lcd_display_operation_bundle));
    TEST_ASSERT_NOT_NULL(operation_request_wrong_signature_blob);

    memcpy(operation_request_wrong_signature_blob, g_lcd_display_operation_bundle, sizeof(g_lcd_display_operation_bundle));    
    
    //Corrupt signature
    operation_request_wrong_signature_blob[sizeof(g_lcd_display_operation_bundle) -1] = 0xFF;
    operation_request_wrong_signature_blob[sizeof(g_lcd_display_operation_bundle) - 2] = 0xFF;

    test_sda_nonce_set(g_lcd_display_nonce);


    //Call to sda_operation_process with operation request
    sda_status = sda_operation_process( operation_request_wrong_signature_blob, sizeof(g_lcd_display_operation_bundle), NULL, *sda_test_callback, sda_operation_response, sizeof(sda_operation_response), &actual_sda_operation_response_size);
    sda_free(operation_request_wrong_signature_blob);
    TEST_ASSERT_EQUAL(SDA_STATUS_VERIFICATION_ERROR, sda_status);

    //Call to sda_command_type_get and get an error
    check_response(SDA_OPERATION_RESPONSE_MESSAGE_ID, SDA_STATUS_VERIFICATION_ERROR, sda_operation_response, actual_sda_operation_response_size, NULL);
}

TEST(sda_test, sda_wrong_type_command)
{

    sda_status_e sda_status = SDA_STATUS_SUCCESS;
    uint8_t sda_message_response[TEST_SDA_RESPONSE_MESSAGE_SIZE] = { 0 };
    size_t actual_sda_message_response_size;
    char *scope = NULL;
    size_t scope_size;
    char* func_call_name = NULL;
    size_t func_call_name_size;
    sda_command_type_e command_type;
    const uint8_t nonce_request_wrong_type_command[] = { 0x81, 0x17 };

    //Call to sda_operation_process with nonce request
    sda_status = sda_operation_process( nonce_request_wrong_type_command, sizeof(nonce_request_wrong_type_command), *sda_test_callback, NULL, sda_message_response, sizeof(sda_message_response), &actual_sda_message_response_size);
    TEST_ASSERT_EQUAL(SDA_STATUS_INVALID_REQUEST, sda_status);

    check_response(SDA_ERROR_MESSAGE_ID, SDA_STATUS_INVALID_REQUEST, sda_message_response, actual_sda_message_response_size, NULL);
}

TEST(sda_test, sda_check_api_call_order)
{
    sda_status_e sda_status = SDA_STATUS_SUCCESS;
    uint8_t sda_message_response[TEST_SDA_RESPONSE_MESSAGE_SIZE] = { 0 };
    size_t actual_sda_message_response_size;
    sda_ctx_internal_s sda_internal_ctx;
    sda_operation_ctx_h handle = (sda_operation_ctx_h*)&sda_internal_ctx;
    char *scope = NULL;
    size_t scope_size;
    char* func_call_name = NULL;
    size_t func_call_name_size;
    sda_command_type_e command_type;

    // Set initial state
    sda_internal_ctx.message_state = SDA_OP_START_PROCESSING_MESSAGE;

    sda_status = sda_scope_get_next(handle, (const uint8_t**)&scope, &scope_size);
    TEST_ASSERT_EQUAL(SDA_STATUS_INVALID_REQUEST, sda_status);

    sda_status = sda_command_type_get(handle, &command_type);
    TEST_ASSERT_EQUAL(SDA_STATUS_INVALID_REQUEST, sda_status);

    sda_status = sda_func_call_name_get(handle, (const uint8_t**)&func_call_name, &func_call_name_size);
    TEST_ASSERT_EQUAL(SDA_STATUS_INVALID_REQUEST, sda_status);

    test_sda_nonce_set(g_lcd_display_nonce);

    //Call to sda_operation_process with operation
    sda_status = sda_operation_process(g_lcd_display_operation_bundle, sizeof(g_lcd_display_operation_bundle), *sda_test_callback, NULL, sda_message_response, sizeof(sda_message_response), &actual_sda_message_response_size);
    TEST_ASSERT_EQUAL(SDA_STATUS_SUCCESS, sda_status);

    //Call to sda_operation_process with operation again (should to fail with verification error as result of nonce verification failure)
    sda_status = sda_operation_process(g_lcd_display_operation_bundle, sizeof(g_lcd_display_operation_bundle), *sda_test_callback, NULL, sda_message_response, sizeof(sda_message_response), &actual_sda_message_response_size);
    TEST_ASSERT_EQUAL(SDA_STATUS_VERIFICATION_ERROR, sda_status);

    check_response(SDA_OPERATION_RESPONSE_MESSAGE_ID, SDA_STATUS_VERIFICATION_ERROR, sda_message_response, actual_sda_message_response_size, NULL);
}

TEST(sda_test, sda_init_test)
{

    sda_status_e sda_status = SDA_STATUS_SUCCESS;
    uint8_t sda_message_response[TEST_SDA_RESPONSE_MESSAGE_SIZE] = { 0 };
    size_t actual_sda_message_response_size;
    sda_ctx_internal_s sda_internal_ctx;
    sda_operation_ctx_h handle = (sda_operation_ctx_h*)&sda_internal_ctx;
    char *scope = NULL;
    size_t scope_size;
    char* func_call_name = NULL;
    size_t func_call_name_size;
    sda_command_type_e command_type;
    uint64_t nonce_data = 664396747115767313;// 14785200172873371264;
    const char enpoint_name[] = "0160c1976ccf0a580a010e1303c00000";
    const char device_id[] = "f90b1017e52f4c70ad92684e802c9249";

    sda_status = sda_finalize();
    TEST_ASSERT(sda_status == SDA_STATUS_SUCCESS);

    // Set initial state
    sda_internal_ctx.message_state = SDA_OP_START_PROCESSING_MESSAGE;

    sda_status = sda_scope_get_next(handle, (const uint8_t**)&scope, &scope_size);
    TEST_ASSERT_EQUAL(SDA_STATUS_NOT_INITIALIZED, sda_status);

    sda_status = sda_command_type_get(handle, &command_type);
    TEST_ASSERT_EQUAL(SDA_STATUS_NOT_INITIALIZED, sda_status);

    sda_status = sda_func_call_name_get(handle, (const uint8_t**)&func_call_name, &func_call_name_size);
    TEST_ASSERT_EQUAL(SDA_STATUS_NOT_INITIALIZED, sda_status);

    //Call to sda_operation_process with operation
    sda_status = sda_operation_process(g_lcd_display_operation_bundle, sizeof(g_lcd_display_operation_bundle), *sda_test_callback, NULL, sda_message_response, sizeof(sda_message_response), &actual_sda_message_response_size);
    TEST_ASSERT_EQUAL(SDA_STATUS_NOT_INITIALIZED, sda_status);

    // Set initial state
    sda_internal_ctx.message_state = SDA_OP_START_PROCESSING_MESSAGE;

    sda_status = sda_init();
    TEST_ASSERT(sda_status == SDA_STATUS_SUCCESS);

    //set nonce
    test_sda_nonce_set(g_lcd_display_nonce);
    TEST_ASSERT_EQUAL_INT(SDA_STATUS_SUCCESS, sda_status);

    //Call to sda_operation_process with operation
    sda_status = sda_operation_process(g_lcd_display_operation_bundle, sizeof(g_lcd_display_operation_bundle), *sda_test_callback, NULL, sda_message_response, sizeof(sda_message_response), &actual_sda_message_response_size);
    TEST_ASSERT_EQUAL(SDA_STATUS_SUCCESS, sda_status);


}

TEST_GROUP_RUNNER(sda_test)
{
    //positive tests
    RUN_TEST_CASE(sda_test, sda_nonce_request_positive);
    RUN_TEST_CASE(sda_test, sda_operation_request_positive);
    RUN_TEST_CASE(sda_test, sda_operation_request_callback_negative);
    RUN_TEST_CASE(sda_test, sda_test_scope_array);
    //negative tests
    RUN_TEST_CASE(sda_test, sda_check_params);
    RUN_TEST_CASE(sda_test, sda_init_test);
    RUN_TEST_CASE(sda_test, sda_nonce_request_negative);
    RUN_TEST_CASE(sda_test, sda_operation_request_negative);
    RUN_TEST_CASE(sda_test, sda_wrong_type_command);
    RUN_TEST_CASE(sda_test, sda_check_api_call_order);
    RUN_TEST_CASE(sda_test, sda_operation_request_response_too_small);
}
