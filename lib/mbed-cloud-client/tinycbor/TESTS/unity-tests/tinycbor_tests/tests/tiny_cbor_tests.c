//----------------------------------------------------------------------------
//   The confidential and proprietary information contained in this file may
//   only be used by a person authorised under and to the extent permitted
//   by a subsisting licensing agreement from ARM Limited or its affiliates.
//
//          (C) COPYRIGHT 2013-2016 ARM Limited or its affiliates.
//              ALL RIGHTS RESERVED
//
//   This entire notice must be reproduced on all copies of this file
//   and copies of this file may only be made by a person if such person is
//   permitted to do so under the terms of a subsisting license agreement
//   from ARM Limited or its affiliates.
//----------------------------------------------------------------------------

#include "unity_fixture.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "unity_helper_macros.h"
#include "tinycbor.h"





TEST_GROUP(TinyCborTests);

TEST_SETUP(TinyCborTests)
{
}

TEST_TEAR_DOWN(TinyCborTests)
{
}

/*
main map diagnostic -> {"key1": 1, "array_in_bytes": h'83036B736F6D6520737472696E6783040506', "key3": "an irrelevant string"}
value of "array_in_bytes" : internal array diagnostic -> [3, "some string", [4, 5, 6]]
*/
uint8_t encoded_map_with_defined_size[] = { 0xA3, 0x64, 0x6B, 0x65, 0x79, 0x31, 0x01, 0x6E, 0x61, 0x72, 0x72, 0x61, 0x79, 0x5F, 0x69, 0x6E, 0x5F, 0x62, 0x79, 0x74,
                          0x65, 0x73, 0x52, 0x83, 0x03, 0x6B, 0x73, 0x6F, 0x6D, 0x65, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6E, 0x67, 0x83, 0x04, 0x05,
                          0x06, 0x64, 0x6B, 0x65, 0x79, 0x33, 0x74, 0x61, 0x6E, 0x20, 0x69, 0x72, 0x72, 0x65, 0x6C, 0x65, 0x76, 0x61, 0x6E, 0x74,
                          0x20, 0x73, 0x74, 0x72, 0x69, 0x6E, 0x67 };


uint8_t encoded_map_with_undefined_size[] = { 0xbf ,0x64 ,0x6b ,0x65 ,0x79 ,0x31 ,0x01 ,0x6e ,0x61 ,0x72 ,0x72 ,0x61 ,0x79 ,0x5f ,0x69 ,0x6e ,0x5f ,0x62 ,0x79 ,0x74,
                                             0x65 ,0x73 ,0x52 ,0x83 ,0x03 ,0x6b ,0x73 ,0x6f ,0x6d ,0x65 ,0x20 ,0x73 ,0x74 ,0x72 ,0x69 ,0x6e ,0x67 ,0x83 ,0x04 ,0x05,
                                             0x06 ,0x64 ,0x6b ,0x65 ,0x79 ,0x33 ,0x74 ,0x61 ,0x6e ,0x20 ,0x69 ,0x72 ,0x72 ,0x65 ,0x6c ,0x65 ,0x76 ,0x61 ,0x6e ,0x74,
                                             0x20 ,0x73 ,0x74 ,0x72 ,0x69 ,0x6e ,0x67 ,0xff };


TEST(TinyCborTests, parser_test)
{
    CborError cbor_error = CborNoError;
    CborParser parser;
    CborValue main_value;
    CborValue internal_value;
    CborValue map_value;
    CborValue element;
    bool status = false;
    int int_value = 0;
    char array_string_1[] = "an irrelevant string";
    uint8_t *temp_buffer= NULL;
    size_t temp_buffer_size = 0;


    //Initialize cbor parser with encoded buffer
    cbor_error = cbor_parser_init(encoded_map_with_defined_size, sizeof(encoded_map_with_defined_size), 0, &parser, &main_value);
    TEST_ASSERT_EQUAL_MESSAGE(cbor_error , CborNoError, "cbor_parser_init of encoded_map_with_defined_size failed");

    //Check that encoded buffer stucture is a map
    status = cbor_value_is_map(&main_value);
    TEST_ASSERT_MESSAGE(status == true, "cbor_value_is_map of main map is failed");

    //********************************************************************
    //Check first element "key1": 1
    // find value of key key "key1"
    cbor_error = cbor_value_map_find_value(&main_value, "key1", &map_value);
    TEST_ASSERT_EQUAL_MESSAGE(cbor_error , CborNoError, "cbor_value_map_find_value of first element failed");

    //Check that the type of the value is integer
    status = cbor_value_is_integer(&map_value);
    TEST_ASSERT_MESSAGE(status == true, "cbor_value_is_integer of first element failed");

    //Get the value of the integer and check it
    cbor_error = cbor_value_get_int(&map_value, &int_value);
    TEST_ASSERT_EQUAL_MESSAGE(cbor_error , CborNoError, "cbor_value_get_int of first element failed");
    TEST_ASSERT_EQUAL_MESSAGE(int_value , 1, "int_value is different than expected");

    //*******************************************************************
    //Check third element "key3": "an irrelevant string"
    // find value of key key "key3" 
    cbor_error = cbor_value_map_find_value(&main_value, "key3", &map_value);
    TEST_ASSERT_EQUAL_MESSAGE(cbor_error , CborNoError, "cbor_value_map_find_value of third element failed");

    //Check that the type of the value is string
    status = cbor_value_is_text_string(&map_value);
    TEST_ASSERT_MESSAGE(status == true, "cbor_value_is_text_string of third element failed");


    cbor_error = cbor_value_get_text_string_chunk(&map_value,(const char **)&temp_buffer, &temp_buffer_size, &element);
    TEST_ASSERT_EQUAL_MESSAGE(cbor_error , CborNoError, "cbor_value_get_byte_string_chunk of third element failed");
    TEST_ASSERT_EQUAL_INT8_ARRAY_MESSAGE(array_string_1, temp_buffer, strlen(array_string_1), "Text string of the third element is wrong");


    temp_buffer = NULL;
    temp_buffer_size = 0;

    //***********************************************************
    //Check second element "array_in_bytes": h'83036B736F6D6520737472696E6783040506'
    // find value of key key "array_in_bytes"
    cbor_error = cbor_value_map_find_value(&main_value, "array_in_bytes", &map_value);
    TEST_ASSERT_EQUAL(cbor_error, CborNoError);

    //Check that the type of the value is byte string  h'83036B736F6D6520737472696E6783040506'
    status = cbor_value_is_byte_string(&map_value);
    TEST_ASSERT_EQUAL(status, true);

    cbor_error = cbor_value_get_byte_string_chunk(&map_value, (const uint8_t **)&temp_buffer, &temp_buffer_size, &element);
    TEST_ASSERT_EQUAL(cbor_error, CborNoError);
    TEST_ASSERT_NOT_EQUAL(temp_buffer, NULL);
    TEST_ASSERT_NOT_EQUAL(temp_buffer_size, 0);


    cbor_error = cbor_parser_init(temp_buffer, temp_buffer_size, 0, &parser, &internal_value);
    TEST_ASSERT_EQUAL_MESSAGE(cbor_error, CborNoError, "cbor_parser_init of internal buffer fialed");

    cbor_error = cbor_value_is_array(&internal_value);
    TEST_ASSERT_EQUAL(status, true);
  
}


TEST(TinyCborTests, parser_empty_maps_test)
{
    CborError cbor_error = CborNoError;
    CborParser parser;
    CborValue main_value;
    CborValue element;
    bool status = false;
    size_t map_lenght = 1000;

    uint8_t empty_map[] = { 0xA0 };
    uint8_t empty_map_inside_array[] = { 0x81, 0xC1,0xA0 };

    /********************************************************************************************/
    //These tests checks tst_encoder cases that was commented due to old version of qt

    //Initialize cbor parser with empty_map
    cbor_error = cbor_parser_init(empty_map, sizeof(empty_map), 0, &parser, &main_value);
    TEST_ASSERT_EQUAL_MESSAGE(cbor_error, CborNoError, "cbor_parser_init of empty_map failed");

    //Check that empty_map structure is a map
    status = cbor_value_is_map(&main_value);
    TEST_ASSERT_MESSAGE(status == true, "cbor_value_is_map of empty_map is failed");

    cbor_error = cbor_value_get_map_length(&main_value, &map_lenght);
    TEST_ASSERT_EQUAL_MESSAGE(cbor_error, CborNoError, "cbor_value_get_map_length of empty_map is failed");
    TEST_ASSERT_EQUAL_MESSAGE(map_lenght, 0, "The size of the empty map should be 0");

    /*****************************/
    //Initialize cbor parser with empty_map_inside_array
    cbor_error = cbor_parser_init(empty_map_inside_array, sizeof(empty_map_inside_array), 0, &parser, &main_value);
    TEST_ASSERT_EQUAL_MESSAGE(cbor_error, CborNoError, "cbor_parser_init of empty_map failed");


    //Check that empty_map structure is a map
    status = cbor_value_is_array(&main_value);
    TEST_ASSERT_MESSAGE(status == true, "cbor_value_is_array of empty_map_inside_array is failed");

    cbor_error = cbor_value_enter_container(&main_value, &element);
    TEST_ASSERT_EQUAL_MESSAGE(cbor_error, CborNoError, "cbor_value_enter_container of empty_map_inside_array failed");

    status = cbor_value_is_tag(&element);
    TEST_ASSERT_MESSAGE(status == true, "cbor_value_is_tag of empty_map_inside_array is failed");

    status = cbor_value_advance(&element);
    TEST_ASSERT_EQUAL_MESSAGE(cbor_error, CborNoError, "cbor_value_advance of empty_map_inside_array failed");

    status = cbor_value_is_map(&element);
    TEST_ASSERT_EQUAL_MESSAGE(cbor_error, CborNoError, "cbor_value_is_map of empty_map_inside_array failed");

    cbor_error = cbor_value_get_map_length(&element, &map_lenght);
    TEST_ASSERT_EQUAL_MESSAGE(cbor_error, CborNoError, "cbor_value_get_map_length of empty_map_inside_array is failed");
    TEST_ASSERT_EQUAL_MESSAGE(map_lenght, 0, "The size of the empty map should be 0");

}

TEST(TinyCborTests, encoder_test)
{
    CborError cbor_error = CborNoError;
    CborEncoder encoder;
    CborEncoder map_encoder;
    int buffer_iterator = 0;
    uint8_t *encoded_out_buffer = NULL;
    size_t encoded_out_buffer_len = 0;
    size_t size_of_map_to_create = 0;
    size_t expected_size_of_out_map = 0;
    uint8_t *expected_out_map_data = NULL;
    const uint8_t byte_string[] = { 0x83,0x03,0x6B,0x73,0x6F,0x6D,0x65,0x20,0x73,0x74,0x72,0x69,0x6E,0x67,0x83,0x04,0x05,0x06 };


    for (buffer_iterator = 0; buffer_iterator < 2; buffer_iterator++) {

        if (buffer_iterator == 0) {
            size_of_map_to_create = CborIndefiniteLength;
            expected_size_of_out_map = sizeof(encoded_map_with_undefined_size);
            expected_out_map_data = encoded_map_with_undefined_size;
        }
        else {
            size_of_map_to_create = 3;
            expected_size_of_out_map = sizeof(encoded_map_with_defined_size);
            expected_out_map_data = encoded_map_with_defined_size;
        }

        if (encoded_out_buffer != NULL) {
            free(encoded_out_buffer);
            encoded_out_buffer = NULL;
            encoded_out_buffer_len = 0;
        }

        while (true) {
            // Create CBOR map
            cbor_encoder_init(&encoder, encoded_out_buffer, encoded_out_buffer_len, 0);

            cbor_error = cbor_encoder_create_map(&encoder, &map_encoder, size_of_map_to_create); // Use CborIndefiniteLength if map size not known upon creation
            TEST_ASSERT_MESSAGE(cbor_error != CborErrorOutOfMemory || cbor_error != CborNoError, "cbor_encoder_create_map failed");

            //Create "key1": 1
            cbor_error = cbor_encode_text_stringz(&map_encoder, "key1");
            TEST_ASSERT_MESSAGE(cbor_error != CborErrorOutOfMemory || cbor_error != CborNoError, "cbor_encode_text_stringz for key1 returned wrong result");
            cbor_error = cbor_encode_int(&map_encoder, 1);
            TEST_ASSERT_MESSAGE(cbor_error != CborErrorOutOfMemory || cbor_error != CborNoError, "cbor_encode_int  of value -1-  failed");

            //Create "array_in_bytes": h'83036B736F6D6520737472696E6783040506'
            cbor_error = cbor_encode_text_stringz(&map_encoder, "array_in_bytes");
            //This encoding shoud fail, as encoded_out_buffer is too small 
            TEST_ASSERT_MESSAGE(cbor_error != CborErrorOutOfMemory || cbor_error != CborNoError, "cbor_encode_text_stringz for array_in_bytes returned wrong result");
            cbor_error = cbor_encode_byte_string(&map_encoder, byte_string, sizeof(byte_string));
            TEST_ASSERT_MESSAGE(cbor_error != CborErrorOutOfMemory || cbor_error != CborNoError, "cbor_encode_byte_string  of value -83036B736F6D6520737472696E6783040506-  returned wrong result");

            //Create "key3": "an irrelevant string"
            cbor_error = cbor_encode_text_stringz(&map_encoder, "key3");
            TEST_ASSERT_MESSAGE(cbor_error != CborErrorOutOfMemory || cbor_error != CborNoError, "cbor_encode_text_stringz  of key -key3- returned wrong result");
            cbor_error = cbor_encode_text_stringz(&map_encoder, "an irrelevant string");
            TEST_ASSERT_MESSAGE(cbor_error != CborErrorOutOfMemory || cbor_error != CborNoError, "cbor_encode_text_stringz  of value -an irrelevant string1- returned wrong result");

            cbor_error = cbor_encoder_close_container(&encoder, &map_encoder);
            TEST_ASSERT_MESSAGE(cbor_error != CborErrorOutOfMemory || cbor_error != CborNoError, "cbor_encoder_close_container  returned wrong result");


            if (cbor_error == CborErrorOutOfMemory) {
                encoded_out_buffer_len = cbor_encoder_get_extra_bytes_needed(&encoder);
                printf("\n encoded_out_buffer_len is %d", encoded_out_buffer_len);
                encoded_out_buffer = (uint8_t *)malloc(encoded_out_buffer_len);
            }
            else {
                printf("\n cbor_error is not error!!!!");
                break;
            }
        }

        //Compare created encoded buffer with the expected
        TEST_ASSERT_MESSAGE(encoded_out_buffer_len == expected_size_of_out_map, "The size of encoded buffer is different than expected");
        TEST_ASSERT_EQUAL_INT8_ARRAY_MESSAGE(encoded_out_buffer, expected_out_map_data, encoded_out_buffer_len, "Text encoded buffer is different than expected");
    }
    free(encoded_out_buffer);
}
TEST(TinyCborTests, encoder_empty_map_test)
{
    CborError cbor_error = CborNoError;
    CborEncoder encoder;
    CborEncoder map_encoder;
    int buffer_iterator = 0;
    uint8_t *encoded_out_buffer = NULL;
    size_t encoded_out_buffer_len = 0;
    size_t expected_size_of_out_map = 0;
    uint8_t *expected_out_map_data = NULL;
    uint8_t empty_map[] = { 0xA0 };


    if (buffer_iterator == 0) {
        expected_size_of_out_map = sizeof(empty_map);
        expected_out_map_data = empty_map;
    }

    while (true) {
        // Create CBOR map
        cbor_encoder_init(&encoder, encoded_out_buffer, encoded_out_buffer_len, 0);

        cbor_error = cbor_encoder_create_map(&encoder, &map_encoder, 0);
        TEST_ASSERT_MESSAGE(cbor_error != CborErrorOutOfMemory || cbor_error != CborNoError, "cbor_encoder_create_map failed");


        cbor_error = cbor_encoder_close_container(&encoder, &map_encoder);
        TEST_ASSERT_MESSAGE(cbor_error != CborErrorOutOfMemory || cbor_error != CborNoError, "cbor_encoder_close_container  returned wrong result");


        if (cbor_error == CborErrorOutOfMemory) {
            encoded_out_buffer_len = cbor_encoder_get_extra_bytes_needed(&encoder);
             encoded_out_buffer = (uint8_t *)malloc(encoded_out_buffer_len);
        }  else {
             printf("\n the output map is : 0x%x 0x%x", encoded_out_buffer[0], encoded_out_buffer[0]);
            break;
        }
    }

    //Compare created encoded buffer with the expected
    TEST_ASSERT_MESSAGE(encoded_out_buffer_len == expected_size_of_out_map, "The size of encoded buffer is different than expected");
    TEST_ASSERT_EQUAL_INT8_ARRAY_MESSAGE(encoded_out_buffer, expected_out_map_data, encoded_out_buffer_len, "Text encoded buffer is different than expected");
    free(encoded_out_buffer);
}

TEST(TinyCborTests, encode_byte_string_start_finish_test)
{
    CborError cbor_error = CborNoError;
    CborEncoder encoder;
    uint8_t expected_cbor[] = { 0x58 , 0x32 , 0x00 , 0x01 , 0x02 , 0x03 , 0x04 , 0x05 , 0x06 , 0x07 , 0x08 , 0x09 , 0x00 , 0x01 , 0x02 , 0x03 , 0x04 , 0x05 , 0x06 , 0x07 , 0x08 , 0x09 , 0x00 , 0x01 , 0x02 , 0x03 , 0x04 , 0x05 , 0x06 , 0x07 , 0x08 , 0x09 , 0x00 , 0x01 , 0x02 , 0x03 , 0x04 , 0x05 , 0x06 , 0x07 , 0x08 , 0x09 , 0x00 , 0x01 , 0x02 , 0x03 , 0x04 , 0x05 , 0x06 , 0x07 , 0x08 , 0x09 };
    uint8_t encoded_buffer[sizeof(expected_cbor)];
    uint8_t *byte_string;
    size_t byte_string_len;

    cbor_encoder_init(&encoder, encoded_buffer, sizeof(encoded_buffer), 0);

    cbor_error = cbor_encode_byte_string_start(&encoder, (const uint8_t**)&byte_string, &byte_string_len);
    TEST_ASSERT_EQUAL(cbor_error, CborNoError);
    TEST_ASSERT_EQUAL(byte_string_len, sizeof(encoded_buffer) - 2); // type + 1 byte len

    memcpy(byte_string, expected_cbor + 2, byte_string_len);

    cbor_error = cbor_encode_byte_string_finish(&encoder, byte_string_len);
    TEST_ASSERT_EQUAL(cbor_error, CborNoError);
    TEST_ASSERT_EQUAL_INT8_ARRAY_MESSAGE(expected_cbor, encoded_buffer, sizeof(expected_cbor), "Encoded buffer is different than expected");
}


TEST_GROUP_RUNNER(TinyCborTests)
{
	RUN_TEST_CASE(TinyCborTests, parser_test);
    RUN_TEST_CASE(TinyCborTests, parser_empty_maps_test);
    RUN_TEST_CASE(TinyCborTests, encoder_test);
    RUN_TEST_CASE(TinyCborTests, encoder_empty_map_test);
    RUN_TEST_CASE(TinyCborTests, encode_byte_string_start_finish_test);
}
