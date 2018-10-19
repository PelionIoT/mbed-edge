// ----------------------------------------------------------------------------
// Copyright 2016-2017 ARM Ltd.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "kcm_internal.h"
#include "key_config_manager.h"
#include "pv_log.h"
#include "pv_macros.h"
#include "pv_log.h"
#include "pv_macros.h"
#include "testdata.h"
#include "key_config_manager.h"
#include "factory_configurator_client.h"
#include "storage.h"
#include "ce_common_helper.h"
#include "ce_status.h"
#include "certificate_enrollment.h"
#include "ce_internal.h"


// FIXME - create it in generate test data scripts
#define CERTIFICATE_TEST_ITERATIONS 3
typedef struct test_certificate_chain_data_ {
    const uint8_t *certificate;
    size_t certificate_size;
} test_certificate_chain_data_s;
test_certificate_chain_data_s test_certificate_vector[CERTIFICATE_TEST_ITERATIONS][KCM_MAX_NUMBER_OF_CERTITICATES_IN_CHAIN] = {
    {
        {
            .certificate = testdata_x509_pth_chain_child_4der,
            .certificate_size = sizeof(testdata_x509_pth_chain_child_4der),
        },
        {
            .certificate = testdata_x509_pth_chain_child_3der,
            .certificate_size = sizeof(testdata_x509_pth_chain_child_3der),
        },
        {
            .certificate = testdata_x509_pth_chain_child_2der,
            .certificate_size = sizeof(testdata_x509_pth_chain_child_2der),
        },
        {
            .certificate = testdata_x509_pth_chain_child_1der,
            .certificate_size = sizeof(testdata_x509_pth_chain_child_1der),
        },
        {
            .certificate = testdata_x509_pth_ca_chain_1der,
            .certificate_size = sizeof(testdata_x509_pth_ca_chain_1der),
        }
    },
    {
        {
            .certificate = testdata_x509_pth_chain_child_4der,
            .certificate_size = sizeof(testdata_x509_pth_chain_child_4der),
        },
        {
            .certificate = testdata_x509_pth_chain_child_3der,
            .certificate_size = sizeof(testdata_x509_pth_chain_child_3der),
        },
        {
            .certificate = testdata_x509_pth_chain_child_2der,
            .certificate_size = sizeof(testdata_x509_pth_chain_child_2der),
        },
        {
            .certificate = testdata_x509_pth_chain_child_1der,
            .certificate_size = sizeof(testdata_x509_pth_chain_child_1der),
        },
        {
            .certificate = testdata_x509_pth_ca_chain_1der,
            .certificate_size = sizeof(testdata_x509_pth_ca_chain_1der),
        }
    },
    {
        {
            .certificate = testdata_x509_pth_chain_child_3der,
            .certificate_size = sizeof(testdata_x509_pth_chain_child_3der),
        },
        {

            .certificate = testdata_x509_pth_chain_child_4der,
            .certificate_size = sizeof(testdata_x509_pth_chain_child_4der),
        },
        {
            .certificate = testdata_x509_pth_ca_chain_1der,
            .certificate_size = sizeof(testdata_x509_pth_ca_chain_1der),

        },
        {
            .certificate = testdata_x509_pth_chain_child_1der,
            .certificate_size = sizeof(testdata_x509_pth_chain_child_1der),
        },
        {
            .certificate = testdata_x509_pth_chain_child_2der,
            .certificate_size = sizeof(testdata_x509_pth_chain_child_2der),
        }
    },
};


extern const char g_renewal_status_file[];
extern const char g_lwm2m_name[];

extern kcm_status_e ce_get_kcm_data(const uint8_t *parameter_name,
    size_t size_of_parameter_name,
    kcm_item_type_e kcm_type,
    kcm_data_source_type_e data_source_type,
    uint8_t **kcm_data,
    size_t *kcm_data_size);

/* The function stores set of private key, public key and certificate items, according to its source type,
The public key and certifiate data are optional*/
static  void test_store_items(const uint8_t *item_name, size_t item_name_len,
    const uint8_t *priv_key_data, size_t priv_key_data_size,
    const uint8_t *pub_key_data, size_t pub_key_data_size,
    const uint8_t *certificate_data, size_t certificate_data_size,
    kcm_data_source_type_e source_type)
{
    bool kcm_item_is_factory = false;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char *private_key_name = (char*)item_name;
    char *certificate_name = (char*)item_name;
    char *public_key_name = (char*)item_name;

    if (source_type == KCM_ORIGINAL_ITEM) {
        kcm_item_is_factory = true;
    }
    if (strcmp((const char*)item_name, (const char*)"LWM2M") == 0) {
        private_key_name = (char*)g_fcc_lwm2m_device_private_key_name;
        certificate_name = (char*)g_fcc_lwm2m_device_certificate_name;
        public_key_name = (char*)NULL;
    }

    if (priv_key_data != NULL) {
        kcm_status = _kcm_item_store((const uint8_t*)private_key_name, strlen((const char*)private_key_name), KCM_PRIVATE_KEY_ITEM, kcm_item_is_factory, priv_key_data, priv_key_data_size, source_type);
        TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);
    }

    if (pub_key_data != NULL && public_key_name != NULL) {
        kcm_status = _kcm_item_store((const uint8_t*)public_key_name, strlen((const char*)public_key_name), KCM_PUBLIC_KEY_ITEM, kcm_item_is_factory, pub_key_data, pub_key_data_size, source_type);
        TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);
    }

    if (certificate_data != NULL) {
        kcm_status = _kcm_item_store((const uint8_t*)certificate_name, strlen((const char*)certificate_name), KCM_CERTIFICATE_ITEM, kcm_item_is_factory, certificate_data, certificate_data_size, source_type);
        TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);
    }
}
/* the function checks status of private key, public key and certificate items by getting its size,
and compares the returned status to the expected status for each item*/
static void  test_check_items(const uint8_t *item_name, size_t item_name_len,
    kcm_status_e priv_key_status,
    kcm_status_e pub_key_status,
    kcm_status_e certificate_status,
    kcm_data_source_type_e source_type)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    size_t kcm_data_size = 0;
    char *private_key_name = (char*)item_name;
    char *certificate_name = (char*)item_name;
    char *public_key_name = (char*)item_name;

    if (strcmp((const char*)item_name, "LWM2M") == 0) {
        private_key_name = (char*)g_fcc_lwm2m_device_private_key_name;
        certificate_name = (char*)g_fcc_lwm2m_device_certificate_name;
        public_key_name = (char*)NULL;
    }

    kcm_status = _kcm_item_get_data_size((const uint8_t*)private_key_name, strlen(private_key_name), KCM_PRIVATE_KEY_ITEM, source_type, &kcm_data_size);
    TEST_ASSERT_TRUE(kcm_status == priv_key_status);
    if (priv_key_status == KCM_STATUS_SUCCESS) {
        TEST_ASSERT_TRUE(kcm_data_size != 0);
    }
    kcm_data_size = 0;

    if (public_key_name != NULL) {
        kcm_status = _kcm_item_get_data_size((const uint8_t*)public_key_name, strlen((const char*)public_key_name), KCM_PUBLIC_KEY_ITEM, source_type, &kcm_data_size);
        TEST_ASSERT_TRUE(kcm_status == pub_key_status);
        if (pub_key_status == KCM_STATUS_SUCCESS) {
            TEST_ASSERT_TRUE(kcm_data_size != 0);
        }
        kcm_data_size = 0;
    }


    kcm_status = _kcm_item_get_data_size((const uint8_t*)certificate_name, strlen((const char*)certificate_name), KCM_CERTIFICATE_ITEM, source_type, &kcm_data_size);
    TEST_ASSERT_TRUE(kcm_status == certificate_status);
    if (certificate_status == KCM_STATUS_SUCCESS) {
        TEST_ASSERT_TRUE(kcm_data_size != 0);
    }
}
/*The function reads current item according to its source and type and cpmares it with expected data*/
static void test_read_and_compare_item(const uint8_t *item_name, size_t item_name_len,
    const uint8_t *expected_data, size_t expected_data_len,
    kcm_item_type_e kcm_type,
    kcm_data_source_type_e source_type)
{
    size_t kcm_data_size = 0;
    uint8_t *kcm_data = NULL;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;

    kcm_status = ce_get_kcm_data((const uint8_t*)item_name, strlen((const char*)item_name), kcm_type, source_type, &kcm_data, &kcm_data_size);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Compare original and backup items
    TEST_ASSERT_TRUE(kcm_data_size == expected_data_len);
    TEST_ASSERT_EQUAL_MEMORY(kcm_data, expected_data, expected_data_len);

    free(kcm_data);

}

/*The function reads current item according to its source and type and cpmares it with expected data*/
static void  test_read_and_compare_two_items(const uint8_t *item_name,
    size_t item_name_len,
    kcm_item_type_e kcm_type,
    bool is_equal)

{
    size_t kcm_backup_data_size = 0;
    uint8_t *kcm_backup_data = NULL;
    size_t kcm_original_data_size = 0;
    uint8_t *kcm_original_data = NULL;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    int res = 0;


    kcm_status = ce_get_kcm_data((const uint8_t*)item_name, strlen((const char*)item_name), kcm_type, KCM_BACKUP_ITEM, &kcm_backup_data, &kcm_backup_data_size);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    kcm_status = ce_get_kcm_data((const uint8_t*)item_name, strlen((const char*)item_name), kcm_type, KCM_ORIGINAL_ITEM, &kcm_original_data, &kcm_original_data_size);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Compare original and backup items
    if (is_equal == true) {
        TEST_ASSERT_TRUE(kcm_backup_data_size == kcm_original_data_size);
        TEST_ASSERT_EQUAL_MEMORY(kcm_backup_data, kcm_original_data, kcm_original_data_size);
    }
    else {
        res = memcmp(kcm_backup_data, kcm_original_data, kcm_backup_data_size >= kcm_original_data_size ? kcm_original_data_size : kcm_backup_data_size);
        TEST_ASSERT_TRUE(res != 0);
    }

    free(kcm_backup_data);
    free(kcm_original_data);

}

TEST_GROUP(ce_safe_store_tests);


TEST_SETUP(ce_safe_store_tests)
{
    ce_tst_setup();
    TEST_SKIP_EXECUTION_ON_FAILURE();
}

TEST_TEAR_DOWN(ce_safe_store_tests)
{
    ce_tst_tear_down();
    TEST_SKIP_EXECUTION_ON_FAILURE();
}




TEST(ce_safe_store_tests, ce_create_backup_lwm2m)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char item_name[] = "LWM2M";
    char *private_key_name = (char*)g_fcc_lwm2m_device_private_key_name;
    char *certificate_name = (char*)g_fcc_lwm2m_device_certificate_name;

    //Store original items
    //*************************************************************************************************
    test_store_items((uint8_t*)item_name, strlen((const char*)item_name),
        (uint8_t*)testdata_private_ecc_python_key_2der, sizeof(testdata_private_ecc_python_key_2der),
        NULL,0,
        (uint8_t*)testdata_x509_pth_chain_child_1der, sizeof(testdata_x509_pth_chain_child_1der),
        KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check private key
    test_read_and_compare_item((const uint8_t*)private_key_name, strlen((const char*)private_key_name), testdata_private_ecc_python_key_2der, sizeof(testdata_private_ecc_python_key_2der), KCM_PRIVATE_KEY_ITEM, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check certificate
    test_read_and_compare_item((const uint8_t*)certificate_name, strlen((const char*)certificate_name), testdata_x509_pth_chain_child_1der, sizeof(testdata_x509_pth_chain_child_1der), KCM_CERTIFICATE_ITEM, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Create backup items
    //*************************************************************************************************
    kcm_status = ce_create_backup_items(item_name, true);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Check backup items
    //*************************************************************************************************
    //Check private key
    test_read_and_compare_item((const uint8_t*)private_key_name, strlen((const char*)private_key_name), testdata_private_ecc_python_key_2der, sizeof(testdata_private_ecc_python_key_2der), KCM_PRIVATE_KEY_ITEM, KCM_BACKUP_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check certificate
    test_read_and_compare_item((const uint8_t*)certificate_name, strlen((const char*)certificate_name), testdata_x509_pth_chain_child_1der, sizeof(testdata_x509_pth_chain_child_1der), KCM_CERTIFICATE_ITEM, KCM_BACKUP_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();
}
TEST(ce_safe_store_tests, ce_create_backup_single_certificate_and_public_key)
{
    
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char item_name[] = "restore_backup_test";

    //Store original items
    //*************************************************************************************************
    test_store_items((uint8_t*)item_name, strlen((const char*)item_name),
        testdata_private_ecc_python_key_2der, sizeof(testdata_private_ecc_python_key_2der),
        testdata_public_ecc_python_key_2der, sizeof(testdata_public_ecc_python_key_2der),
        testdata_x509_pth_chain_child_1der, sizeof(testdata_x509_pth_chain_child_1der),
        KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check that backup items are not in storage - status of all items is KCM_STATUS_ITEM_NOT_FOUND
    //*************************************************************************************************
    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_BACKUP_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Create backup items
    //*************************************************************************************************
    kcm_status =  ce_create_backup_items(item_name, true);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Check backup items
    //*************************************************************************************************
    //Check private key
    test_read_and_compare_item((const uint8_t*)item_name, strlen((const char*)item_name), testdata_private_ecc_python_key_2der, sizeof(testdata_private_ecc_python_key_2der), KCM_PRIVATE_KEY_ITEM, KCM_BACKUP_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check public key
    test_read_and_compare_item((const uint8_t*)item_name, strlen((const char*)item_name), testdata_public_ecc_python_key_2der, sizeof(testdata_public_ecc_python_key_2der), KCM_PUBLIC_KEY_ITEM, KCM_BACKUP_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check certificate
    test_read_and_compare_item((const uint8_t*)item_name, strlen((const char*)item_name), testdata_x509_pth_chain_child_1der, sizeof(testdata_x509_pth_chain_child_1der), KCM_CERTIFICATE_ITEM, KCM_BACKUP_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Clean backup items
    //*************************************************************************************************
    kcm_status = ce_clean_items((const char*)item_name, KCM_BACKUP_ITEM, true);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Check backup items - should be removed
    //*************************************************************************************************
    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_BACKUP_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Clean original items
    //*************************************************************************************************
    kcm_status = ce_clean_items((const char*)item_name, KCM_ORIGINAL_ITEM, true);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Check original items - should be removed
    //*************************************************************************************************
    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();
}

TEST(ce_safe_store_tests, ce_create_backup_certificate_chain_without_public_key)
{

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char item_name[] = "restore_backup_test_1";
    size_t kcm_data_size = 0;
    uint8_t *kcm_data = NULL;
    kcm_cert_chain_handle cert_chain_handle;
    size_t kcm_chain_len;
    uint32_t j;
    size_t kcm_out_chain_len = 0;
    uint8_t *data_buffer = NULL;
    size_t buffer_size = 0;

    //Store original items (private key and certificate chain)
    //*************************************************************************************************
    test_store_items((uint8_t*)item_name, strlen(item_name),
        testdata_private_ecc_python_key_2der, sizeof(testdata_private_ecc_python_key_2der),
        NULL, 0,//public key
        NULL, 0,//certificate
        KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Store certificate chain
    /****************************/
    kcm_chain_len = 5;

    // create and store chain by create, add and close
    kcm_status = kcm_cert_chain_create(&cert_chain_handle, (uint8_t*)item_name, strlen(item_name), kcm_chain_len, true);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    for (j = 0; j < kcm_chain_len; j++) {
        kcm_status = kcm_cert_chain_add_next(cert_chain_handle, test_certificate_vector[0][j].certificate, test_certificate_vector[0][j].certificate_size);
        TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);
    }

    kcm_status = kcm_cert_chain_close(cert_chain_handle);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);
    /****************************/

    //Check that backup items are not in storage
    //*************************************************************************************************
    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_BACKUP_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check that no backup certificate chain
    kcm_status = _kcm_cert_chain_open(&cert_chain_handle, (const uint8_t*)item_name, strlen((const char*)item_name), KCM_BACKUP_ITEM, &kcm_out_chain_len);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_ITEM_NOT_FOUND);

    //Create backup items with public key - should fail, as original public key wasn't saved
    //*************************************************************************************************
    kcm_status = ce_create_backup_items(item_name, true);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_ITEM_NOT_FOUND);

    //Create backup items with public key - should pass
    //*************************************************************************************************
    kcm_status = ce_create_backup_items(item_name, false);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Check backup items
    //*************************************************************************************************
    //Check private key
    test_read_and_compare_item((const uint8_t*)item_name, strlen((const char*)item_name), testdata_private_ecc_python_key_2der, sizeof(testdata_private_ecc_python_key_2der), KCM_PRIVATE_KEY_ITEM, KCM_BACKUP_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check public key -should fail,as original public key wasn't saved
    kcm_status = ce_get_kcm_data((const uint8_t*)item_name, strlen((const char*)item_name), KCM_PUBLIC_KEY_ITEM, KCM_BACKUP_ITEM, &kcm_data, &kcm_data_size);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_ITEM_NOT_FOUND);


    //Check backup certificate chain and compare against expected data
    kcm_out_chain_len = 0;
    kcm_status  = _kcm_cert_chain_open(&cert_chain_handle, (const uint8_t*)item_name, strlen((const char*)item_name), KCM_BACKUP_ITEM, &kcm_out_chain_len);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);
    TEST_ASSERT_TRUE(kcm_out_chain_len == kcm_chain_len);

    for (j = 0; j < kcm_chain_len; j++) {
        kcm_status = _kcm_cert_chain_get_next_size(cert_chain_handle, KCM_BACKUP_ITEM, &buffer_size);
        TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

        data_buffer = malloc(buffer_size);
        TEST_ASSERT_FALSE(data_buffer == NULL);

        kcm_status = _kcm_cert_chain_get_next_data(cert_chain_handle, data_buffer, buffer_size, KCM_BACKUP_ITEM, &buffer_size);
        TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);
        TEST_ASSERT_TRUE(buffer_size == test_certificate_vector[0][j].certificate_size);
        TEST_ASSERT_EQUAL_HEX8_ARRAY(data_buffer, test_certificate_vector[0][j].certificate, test_certificate_vector[0][j].certificate_size);
        free(data_buffer);
    }

    kcm_status = _kcm_cert_chain_close(cert_chain_handle, KCM_BACKUP_ITEM);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

}

TEST(ce_safe_store_tests, ce_create_backup_bad_params)
{

    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char item_name[] = "restore_backup_test_2";
  
    //Create backup items - no original data
    kcm_status = ce_create_backup_items(item_name, false);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_ITEM_NOT_FOUND);

    //Store original certificate item
    //*************************************************************************************************
    kcm_status = kcm_item_store((const uint8_t*)item_name, strlen((const char*)item_name), KCM_CERTIFICATE_ITEM, true, testdata_x509_pth_chain_child_1der, sizeof(testdata_x509_pth_chain_child_1der), NULL);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Create backup items - NULL name pointer
    kcm_status = ce_create_backup_items(NULL, false);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_INVALID_PARAMETER);

    //Create backup items - true for unexisting public key
    kcm_status = ce_create_backup_items(item_name, true);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_ITEM_NOT_FOUND);

    //Create backup items - mandatory privatye key is missing
    kcm_status = ce_create_backup_items(item_name, false);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_ITEM_NOT_FOUND);

    //Store missing original private key
    //*************************************************************************************************
    kcm_status = kcm_item_store((const uint8_t*)item_name, strlen((const char*)item_name), KCM_PRIVATE_KEY_ITEM, true, testdata_private_ecc_python_key_2der, sizeof(testdata_private_ecc_python_key_2der), NULL);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    kcm_status = ce_create_backup_items((const char*)item_name, false);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);
}

TEST(ce_safe_store_tests, ce_clean_lwm2m_items_test)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char item_name[] = "LWM2M";

    //Store original items
    //*************************************************************************************************
    test_store_items((uint8_t*)item_name, strlen((const char*)item_name),
        testdata_private_ecc_python_key_2der, sizeof(testdata_private_ecc_python_key_2der),
        testdata_public_ecc_python_key_2der, sizeof(testdata_public_ecc_python_key_2der),//public key
        testdata_x509_pth_chain_child_1der, sizeof(testdata_x509_pth_chain_child_1der),//certificate
        KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Create backup items
    //*************************************************************************************************
    kcm_status = ce_create_backup_items(item_name, true);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Clean private key and certificate items, public key still in the storage
    //*************************************************************************************************
    kcm_status = ce_clean_items((const char*)item_name, KCM_ORIGINAL_ITEM, false);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Check status of original items
    //*************************************************************************************************
    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_SUCCESS, KCM_STATUS_ITEM_NOT_FOUND, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Clean all original items
    //*************************************************************************************************
    kcm_status = ce_clean_items((const char*)item_name, KCM_ORIGINAL_ITEM, true);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Check status of original items - all items deleted from storage
    //*************************************************************************************************
    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check status of backup items
    //*************************************************************************************************
    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_SUCCESS, KCM_STATUS_SUCCESS, KCM_STATUS_SUCCESS, KCM_BACKUP_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Clean all backup items
    //*************************************************************************************************
    kcm_status = ce_clean_items((const char*)item_name, KCM_BACKUP_ITEM, true);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Check status of backup items
    //*************************************************************************************************
    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_BACKUP_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();
}
TEST(ce_safe_store_tests, ce_clean_items_test)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char item_name[] = "restore_backup_test_3";

    //Clean original and backup items on empty storage
    //*************************************************************************************************
    kcm_status = ce_clean_items((const char*)item_name, KCM_ORIGINAL_ITEM, false);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    kcm_status = ce_clean_items((const char*)item_name, KCM_BACKUP_ITEM, true);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Bad params
    //*************************************************************************************************
    kcm_status = ce_clean_items(NULL, KCM_ORIGINAL_ITEM, false);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_INVALID_PARAMETER);

    kcm_status = ce_clean_items((const char*)item_name, KCM_SOURCE_TYPE_LAST_ITEM, false);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_INVALID_PARAMETER);

    //Store original items
    //*************************************************************************************************
    test_store_items((uint8_t*)item_name, strlen((const char*)item_name),
        testdata_private_ecc_python_key_2der, sizeof(testdata_private_ecc_python_key_2der),
        testdata_public_ecc_python_key_2der, sizeof(testdata_public_ecc_python_key_2der),//public key
        testdata_x509_pth_chain_child_1der, sizeof(testdata_x509_pth_chain_child_1der),//certificate
        KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Create backup items
    //*************************************************************************************************
    kcm_status = ce_create_backup_items(item_name, true);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Clean private key and certificate items, public key still in the storage
    //*************************************************************************************************
    kcm_status = ce_clean_items((const char*)item_name, KCM_ORIGINAL_ITEM, false);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Check status of original items
    //*************************************************************************************************
    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_SUCCESS, KCM_STATUS_ITEM_NOT_FOUND, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Clean all original items
    //*************************************************************************************************
    kcm_status = ce_clean_items((const char*)item_name, KCM_ORIGINAL_ITEM, true);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Check status of original items - all items deleted from storage
    //*************************************************************************************************
    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check status of backup items
    //*************************************************************************************************
    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_SUCCESS, KCM_STATUS_SUCCESS, KCM_STATUS_SUCCESS, KCM_BACKUP_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Clean all backup items
    //*************************************************************************************************
    kcm_status = ce_clean_items((const char*)item_name, KCM_BACKUP_ITEM, true);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Check status of backup items
    //*************************************************************************************************
    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_BACKUP_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();
}


TEST(ce_safe_store_tests, ce_restore_backup_lwm2m2_params)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char item_name[] = "LWM2M";

    //Store original items
    //*************************************************************************************************
    test_store_items((uint8_t*)item_name, strlen((const char*)item_name),
        testdata_private_ecc_python_key_2der, sizeof(testdata_private_ecc_python_key_2der),
        testdata_public_ecc_python_key_2der, sizeof(testdata_public_ecc_python_key_2der),//public key
        testdata_x509_pth_chain_child_1der, sizeof(testdata_x509_pth_chain_child_1der),//certificate
        KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Create backup items
    //*************************************************************************************************
    kcm_status = ce_create_backup_items(item_name, true);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Clean original items
    //*************************************************************************************************
    kcm_status = ce_clean_items((const char*)item_name, KCM_ORIGINAL_ITEM, true);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Store new original items
    //*************************************************************************************************
    test_store_items((uint8_t*)item_name, strlen((const char*)item_name),
        testdata_private_ecc_python_key_1der, sizeof(testdata_private_ecc_python_key_1der),
        testdata_public_ecc_python_key_1der, sizeof(testdata_public_ecc_python_key_1der),//public key
        testdata_x509_pth_chain_child_2der, sizeof(testdata_x509_pth_chain_child_2der),//certificate
        KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Restore backup items
    //*************************************************************************************************
    kcm_status = ce_restore_backup_items(item_name);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Check original and backup items
    //*************************************************************************************************
    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_SUCCESS, KCM_STATUS_SUCCESS, KCM_STATUS_SUCCESS, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();
    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_BACKUP_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();
}

TEST(ce_safe_store_tests, ce_restore_backup_params)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char item_name[] = "restore_backup_test_4";

    //Store original items
    //*************************************************************************************************
    test_store_items((uint8_t*)item_name, strlen(item_name),
        testdata_private_ecc_python_key_2der, sizeof(testdata_private_ecc_python_key_2der),
        testdata_public_ecc_python_key_2der, sizeof(testdata_public_ecc_python_key_2der),//public key
        testdata_x509_pth_chain_child_1der, sizeof(testdata_x509_pth_chain_child_1der),//certificate
        KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Create backup items
    //*************************************************************************************************
    kcm_status = ce_create_backup_items(item_name, true);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Clean original items
    //*************************************************************************************************
    kcm_status = ce_clean_items((const char*)item_name, KCM_ORIGINAL_ITEM, true);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Store new original items
    //*************************************************************************************************
    test_store_items((uint8_t*)item_name, strlen((const char*)item_name),
        testdata_private_ecc_python_key_1der, sizeof(testdata_private_ecc_python_key_1der),
        testdata_public_ecc_python_key_1der, sizeof(testdata_public_ecc_python_key_1der),//public key
        testdata_x509_pth_chain_child_2der, sizeof(testdata_x509_pth_chain_child_2der),//certificate
        KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check original and backup items; should be different
    //*************************************************************************************************
    test_read_and_compare_two_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_PRIVATE_KEY_ITEM, false);
    TEST_SKIP_EXECUTION_ON_FAILURE();
    test_read_and_compare_two_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_PUBLIC_KEY_ITEM, false);
    TEST_SKIP_EXECUTION_ON_FAILURE();
    test_read_and_compare_two_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_CERTIFICATE_ITEM, false);
    TEST_SKIP_EXECUTION_ON_FAILURE();
    //Restore backup items
    //*************************************************************************************************
    kcm_status = ce_restore_backup_items(item_name);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Check original and backup items; should be equel
    //*************************************************************************************************
    test_read_and_compare_item((const uint8_t*)item_name, strlen((const char*)item_name), testdata_private_ecc_python_key_2der, sizeof(testdata_private_ecc_python_key_2der), KCM_PRIVATE_KEY_ITEM, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();
    //Check public key
    test_read_and_compare_item((const uint8_t*)item_name, strlen((const char*)item_name), testdata_public_ecc_python_key_2der, sizeof(testdata_public_ecc_python_key_2der), KCM_PUBLIC_KEY_ITEM, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();
    //Check certificate
    test_read_and_compare_item((const uint8_t*)item_name, strlen((const char*)item_name), testdata_x509_pth_chain_child_1der, sizeof(testdata_x509_pth_chain_child_1der), KCM_CERTIFICATE_ITEM, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();
}


TEST(ce_safe_store_tests, ce_restore_backup_params_bad_params)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char item_name[] = "restore_backup_test_5";


    //Restore backup items - storage is empty - shoul fail
    //*************************************************************************************************
    kcm_status = ce_restore_backup_items(item_name);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_ITEM_NOT_FOUND);

    //Store original items
    //*************************************************************************************************
    test_store_items((uint8_t*)item_name, strlen((const char*)item_name),
        testdata_private_ecc_python_key_2der, sizeof(testdata_private_ecc_python_key_2der),
        testdata_public_ecc_python_key_2der, sizeof(testdata_public_ecc_python_key_2der),//public key
        testdata_x509_pth_chain_child_1der, sizeof(testdata_x509_pth_chain_child_1der),//certificate
        KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Restore backup items - should fail,as no backup data in storage
    //*************************************************************************************************
    kcm_status = ce_restore_backup_items(item_name);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_ITEM_NOT_FOUND);

    //Create backup items
    //*************************************************************************************************
    kcm_status = ce_create_backup_items(item_name, true);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Bad params
    kcm_status = ce_restore_backup_items(NULL);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_INVALID_PARAMETER);

    //Clean original items
    //*************************************************************************************************
    kcm_status = ce_clean_items((const char*)item_name, KCM_ORIGINAL_ITEM, true);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Check status of original items
    //*************************************************************************************************
    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();
   
}
TEST(ce_safe_store_tests, ce_restore_backup_params_with_factory_reset)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char item_name[] = "restore_backup_test_6";

    //Store original items - with factory flag
    //*************************************************************************************************
    test_store_items((uint8_t*)item_name, strlen((const char*)item_name),
        testdata_private_ecc_python_key_2der, sizeof(testdata_private_ecc_python_key_2der),
        testdata_public_ecc_python_key_2der, sizeof(testdata_public_ecc_python_key_2der),//public key
        testdata_x509_pth_chain_child_1der, sizeof(testdata_x509_pth_chain_child_1der),//certificate
        KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Create backup items
    //*************************************************************************************************
    kcm_status = ce_create_backup_items(item_name, true);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Clean original items
    //*************************************************************************************************
    kcm_status = ce_clean_items((const char*)item_name, KCM_ORIGINAL_ITEM, true);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Store new original items
    //*************************************************************************************************
    test_store_items((uint8_t*)item_name, strlen((const char*)item_name),
        testdata_private_ecc_python_key_1der, sizeof(testdata_private_ecc_python_key_1der),
        testdata_public_ecc_python_key_1der, sizeof(testdata_public_ecc_python_key_1der),//public key
        testdata_x509_pth_chain_child_2der, sizeof(testdata_x509_pth_chain_child_2der),//certificate
        KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    kcm_status = ce_restore_backup_items(item_name);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    test_read_and_compare_item((const uint8_t*)item_name, strlen((const char*)item_name), testdata_private_ecc_python_key_2der, sizeof(testdata_private_ecc_python_key_2der), KCM_PRIVATE_KEY_ITEM, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();
    //Check public key
    test_read_and_compare_item((const uint8_t*)item_name, strlen((const char*)item_name), testdata_public_ecc_python_key_2der, sizeof(testdata_public_ecc_python_key_2der), KCM_PUBLIC_KEY_ITEM, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();
    //Check certificate
    test_read_and_compare_item((const uint8_t*)item_name, strlen((const char*)item_name), testdata_x509_pth_chain_child_1der, sizeof(testdata_x509_pth_chain_child_1der), KCM_CERTIFICATE_ITEM, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();
    //Factory reset
    kcm_factory_reset();

    //After factory reset the items should be restored from factory backup, and this is the items was saved with factory flag
    test_read_and_compare_item((const uint8_t*)item_name, strlen((const char*)item_name), testdata_private_ecc_python_key_1der, sizeof(testdata_private_ecc_python_key_1der), KCM_PRIVATE_KEY_ITEM, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();
    //Check public key
    test_read_and_compare_item((const uint8_t*)item_name, strlen((const char*)item_name), testdata_public_ecc_python_key_1der, sizeof(testdata_public_ecc_python_key_1der), KCM_PUBLIC_KEY_ITEM, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();
    //Check certificate
    test_read_and_compare_item((const uint8_t*)item_name, strlen((const char*)item_name), testdata_x509_pth_chain_child_2der, sizeof(testdata_x509_pth_chain_child_2der), KCM_CERTIFICATE_ITEM, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();
 
}

TEST(ce_safe_store_tests, ce_safe_renewal_single_certificate)
{
    char item_name[] = "LWM2M";
    ce_status_e  ce_status = CE_STATUS_SUCCESS;
    ce_renewal_params_s test_renewal_data;
    cs_ec_key_context_s ec_key_ctx;
    struct cert_chain_context_s test_chain_data;
    struct cert_context_s cert_data;
    char *private_key_name = (char*)g_fcc_lwm2m_device_private_key_name;
    char *certificate_name = (char*)g_fcc_lwm2m_device_certificate_name;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    size_t kcm_item_data_size_out = 0;

    memset(&test_renewal_data, 0, sizeof(ce_renewal_params_s));
    memset(&ec_key_ctx, 0, sizeof(cs_ec_key_context_s));
    memset(&test_chain_data, 0, sizeof(struct cert_chain_context_s));
    memset(&cert_data, 0, sizeof(struct cert_context_s));

    //Store original items - with factory flag
    //*************************************************************************************************
    test_store_items((uint8_t*)item_name, strlen((const char*)item_name),
        testdata_private_ecc_python_key_2der, sizeof(testdata_private_ecc_python_key_2der),
        NULL,0,
        testdata_x509_pth_chain_child_1der, sizeof(testdata_x509_pth_chain_child_1der),
        KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Set key crypto context
    memcpy(&ec_key_ctx.priv_key, &testdata_private_ecc_python_key_3der, sizeof(testdata_private_ecc_python_key_3der));
    ec_key_ctx.priv_key_size = sizeof(testdata_private_ecc_python_key_3der);

    //Set ce_renewal_params_s structure -> certificate and private key are correlated 
    //*************************************************************************************************
    test_renewal_data.crypto_handle = (cs_key_handle_t)&ec_key_ctx;
    test_chain_data.certs = (struct cert_context_s*)&cert_data;
    //Set cert data
    test_chain_data.chain_length = 1;
    test_chain_data.certs->cert = (uint8_t*)&testdata_x509_pth_chain_child_2der;
    test_chain_data.certs->cert_length = sizeof(testdata_x509_pth_chain_child_2der);
    test_chain_data.certs->next = NULL;
    test_renewal_data.cert_data = (struct cert_chain_context_s*)&test_chain_data;

    //Call ce_safe_renewal
    //*************************************************************************************************
    ce_status = ce_safe_renewal((const char*)item_name, &test_renewal_data);
    TEST_ASSERT_TRUE(ce_status == CE_STATUS_SUCCESS);

    //Check new parameters
    //*************************************************************************************************
    //Check private key
    test_read_and_compare_item((const uint8_t*)private_key_name, strlen(private_key_name), testdata_private_ecc_python_key_3der, sizeof(testdata_private_ecc_python_key_3der), KCM_PRIVATE_KEY_ITEM, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();
    //Check certificate
    test_read_and_compare_item((const uint8_t*)certificate_name, strlen(certificate_name), testdata_x509_pth_chain_child_2der, sizeof(testdata_x509_pth_chain_child_2der), KCM_CERTIFICATE_ITEM, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check status of backup items
    //*************************************************************************************************
    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_BACKUP_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check renewal status
    kcm_status = _kcm_item_get_data_size((const uint8_t *)g_renewal_status_file, (size_t)strlen(g_renewal_status_file), KCM_CONFIG_ITEM, KCM_BACKUP_ITEM, &kcm_item_data_size_out);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_ITEM_NOT_FOUND);

    //add check of backup and renewal status files
}

TEST(ce_safe_store_tests, ce_safe_renewal_certificate_chain)
{
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    char item_name[] = "LWM2M";
    ce_status_e  ce_status = CE_STATUS_SUCCESS;
    ce_renewal_params_s test_renewal_data;
    cs_ec_key_context_s ec_key_ctx;
    struct cert_chain_context_s test_chain_data;
    size_t kcm_chain_len = 5;
    kcm_cert_chain_handle cert_chain_handle;
    struct cert_context_s cert_data[5];
    uint32_t j;
    size_t kcm_out_chain_len = 0;
    uint8_t *data_buffer = NULL;
    size_t buffer_size = 0;
    char *private_key_name = (char*)g_fcc_lwm2m_device_private_key_name;
    char *certificate_name = (char*)g_fcc_lwm2m_device_certificate_name;
    size_t kcm_item_data_size_out = 0;
    int test_index = 0;

    memset(&test_renewal_data, 0, sizeof(ce_renewal_params_s));
    memset(&ec_key_ctx, 0, sizeof(cs_ec_key_context_s));
    memset(&test_chain_data, 0, sizeof(struct cert_chain_context_s));

    //Store original items (private key and certificate chain)
    //*************************************************************************************************
    test_store_items((uint8_t*)item_name, strlen(item_name),
        testdata_priv_ecc_key2der, sizeof(testdata_priv_ecc_key2der),
        NULL, 0,//public key
        NULL, 0,//certificate
        KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Store original certificate chain = 2
    //*************************************************************************************************
    kcm_chain_len = 2;

    // create and store chain by create, add and close
    kcm_status = kcm_cert_chain_create(&cert_chain_handle, (uint8_t*)certificate_name, strlen(certificate_name), kcm_chain_len, true);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    kcm_status = kcm_cert_chain_add_next(cert_chain_handle, testdata_x509_pth_ca_1der, sizeof(testdata_x509_pth_ca_1der));
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    kcm_status = kcm_cert_chain_add_next(cert_chain_handle, testdata_x509_pth_ca_childder, sizeof(testdata_x509_pth_ca_childder));
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    kcm_status = kcm_cert_chain_close(cert_chain_handle);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Set key crypto context, no public key
    //*************************************************************************************************
    memcpy(&ec_key_ctx.priv_key, &testdata_private_ecc_python_key_5der, sizeof(testdata_private_ecc_python_key_5der));
    ec_key_ctx.priv_key_size = sizeof(testdata_private_ecc_python_key_5der);

    //Set crypto handle to renewal data structure
    //*************************************************************************************************
    test_renewal_data.crypto_handle = (cs_key_handle_t)&ec_key_ctx;

    //Set certificate chain data to renewal data structure
    //*************************************************************************************************
    test_chain_data.chain_length = 5;
    //Set cert_data array
    for (j = 0; j < test_chain_data.chain_length; j++) {

        cert_data[j].cert = (uint8_t*)test_certificate_vector[0][j].certificate;
        cert_data[j].cert_length =(uint16_t) test_certificate_vector[0][j].certificate_size;
        if (j == test_chain_data.chain_length - 1) {
            cert_data[j].next = NULL;
        }
        else {
            cert_data[j].next = (struct cert_context_s *)&cert_data[j + 1];
        }
    }
    //set chain data structure
    test_chain_data.certs = (struct cert_context_s *)&cert_data[0];
    test_renewal_data.cert_data = (struct cert_chain_context_s*)&test_chain_data;

    //Call to renewal

    //Check twice to unsure that pointer to certificate  chain is not changed
    for (test_index = 0; test_index < 2; test_index++) {
        //*************************************************************************************************
        ce_status = ce_safe_renewal((const char*)item_name, &test_renewal_data);
        TEST_ASSERT_TRUE(ce_status == CE_STATUS_SUCCESS);

        //Check new private key
        //*************************************************************************************************
        test_read_and_compare_item((const uint8_t*)private_key_name, strlen(private_key_name), testdata_private_ecc_python_key_5der, sizeof(testdata_private_ecc_python_key_5der), KCM_PRIVATE_KEY_ITEM, KCM_ORIGINAL_ITEM);
        TEST_SKIP_EXECUTION_ON_FAILURE();

        //Check original new certificate chain
        //*************************************************************************************************
        kcm_out_chain_len = 0;
        kcm_chain_len = test_chain_data.chain_length;
        kcm_status = _kcm_cert_chain_open(&cert_chain_handle, (const uint8_t*)certificate_name, strlen((const char*)certificate_name), KCM_ORIGINAL_ITEM, &kcm_out_chain_len);
        TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);
        TEST_ASSERT_TRUE(kcm_out_chain_len == kcm_chain_len);

        for (j = 0; j < kcm_chain_len; j++) {
            kcm_status = _kcm_cert_chain_get_next_size(cert_chain_handle, KCM_ORIGINAL_ITEM, &buffer_size);
            TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

            data_buffer = malloc(buffer_size);
            TEST_ASSERT_FALSE(data_buffer == NULL);

            kcm_status = _kcm_cert_chain_get_next_data(cert_chain_handle, data_buffer, buffer_size, KCM_ORIGINAL_ITEM, &buffer_size);
            TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);
            TEST_ASSERT_TRUE(buffer_size == test_certificate_vector[0][j].certificate_size);
            TEST_ASSERT_EQUAL_HEX8_ARRAY(data_buffer, test_certificate_vector[0][j].certificate, test_certificate_vector[0][j].certificate_size);
            free(data_buffer);
        }

        kcm_status = _kcm_cert_chain_close(cert_chain_handle, KCM_BACKUP_ITEM);
        TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

        //Check renewal status
        kcm_status = _kcm_item_get_data_size((const uint8_t *)g_renewal_status_file, (size_t)strlen(g_renewal_status_file), KCM_CONFIG_ITEM, KCM_BACKUP_ITEM, &kcm_item_data_size_out);
        TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_ITEM_NOT_FOUND);

    }
 

}

TEST(ce_safe_store_tests, ce_safe_renewal_bad_params)
{
    char item_name[] = "bad_params";
    ce_status_e  ce_status = CE_STATUS_SUCCESS;
    kcm_status_e  kcm_status = KCM_STATUS_SUCCESS;
    ce_renewal_params_s test_renewal_data;
    cs_ec_key_context_s ec_key_ctx;
    struct cert_chain_context_s test_chain_data;
    struct cert_context_s cert_data;
    size_t kcm_item_data_size_out = 0;

    memset(&test_renewal_data, 0, sizeof(ce_renewal_params_s));
    memset(&ec_key_ctx, 0, sizeof(cs_ec_key_context_s));
    memset(&test_chain_data, 0, sizeof(struct cert_chain_context_s));
    memset(&cert_data, 0, sizeof(struct cert_context_s));

    //NULL parameters
    //*************************************************************************************************
    ce_status = ce_safe_renewal(NULL, &test_renewal_data);
    TEST_ASSERT_TRUE(ce_status == CE_STATUS_INVALID_PARAMETER);

    ce_status = ce_safe_renewal((const char*)item_name, NULL);
    TEST_ASSERT_TRUE(ce_status == CE_STATUS_INVALID_PARAMETER);

    //Set ce_renewal_params_s structure -> private key and certificate are not correlated
    //*************************************************************************************************
    //Set key crypto context
    memcpy(&ec_key_ctx.priv_key, &testdata_private_ecc_python_key_3der, sizeof(testdata_private_ecc_python_key_3der));
    ec_key_ctx.priv_key_size = sizeof(testdata_private_ecc_python_key_3der);
    memcpy(&ec_key_ctx.pub_key, &testdata_public_ecc_python_key_3der, sizeof(testdata_public_ecc_python_key_3der));
    ec_key_ctx.pub_key_size = sizeof(testdata_public_ecc_python_key_3der);
    test_renewal_data.crypto_handle = (cs_key_handle_t)&ec_key_ctx;
    test_chain_data.certs = (struct cert_context_s*)&cert_data;
    //Set cert data
    test_chain_data.chain_length = 1;
    test_chain_data.certs->cert = (uint8_t*)&testdata_x509_pth_chain_child_1der;
    test_chain_data.certs->cert_length = sizeof(testdata_x509_pth_chain_child_1der);
    test_chain_data.certs->next = NULL;
    test_renewal_data.cert_data = (struct cert_chain_context_s*)&test_chain_data;

    //Call ce_safe_renewal when new items are not correlated -> should fail to verify items
    ce_status = ce_safe_renewal((const char*)item_name, &test_renewal_data);
    TEST_ASSERT_TRUE(ce_status == CE_STATUS_RENEWAL_ITEM_VALIDATION_ERROR);

    //Check status of original and backup items -> shoun't exist
    //*************************************************************************************************
    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check status of original and backup items -> shoun't exist
    //*************************************************************************************************
    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_BACKUP_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check renewal status
  //  kcm_status = _kcm_item_get_data_size((const uint8_t *)g_renewal_status_file, (size_t)strlen(g_renewal_status_file), KCM_CONFIG_ITEM, KCM_BACKUP_ITEM, &kcm_item_data_size_out);
  //  TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_ITEM_NOT_FOUND);

    //Set correlated certificate
    test_chain_data.certs->cert = (uint8_t*)&testdata_x509_pth_chain_child_2der;
    test_chain_data.certs->cert_length = sizeof(testdata_x509_pth_chain_child_2der);

    //Call ce_safe_renewal when original items is missing -> should fail to create backup items
    //todo -> set original items error
    ce_status = ce_safe_renewal((const char*)item_name, &test_renewal_data);
    TEST_ASSERT_TRUE(ce_status == CE_STATUS_ORIGINAL_ITEM_ERROR);


    //Check status of original and backup items -> shoun't exist
    //*************************************************************************************************
    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check status of original and backup items -> shoun't exist
    //*************************************************************************************************
    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_BACKUP_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();
    //todo : add check of renewal status 

    //Store original items - only private key
    //*************************************************************************************************
    test_store_items((uint8_t*)item_name, strlen((const char*)item_name),
        testdata_private_ecc_python_key_2der, sizeof(testdata_private_ecc_python_key_2der),
        NULL, 0,// testdata_public_ecc_python_key_2der, sizeof(testdata_public_ecc_python_key_2der),//public key
        NULL, 0,//testdata_x509_pth_chain_child_1der, sizeof(testdata_x509_pth_chain_child_1der),//certificate
        KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Call ce_safe_renewal when mandatory certificate item is missing -> should fail to create backup items
    ce_status = ce_safe_renewal((const char*)item_name, &test_renewal_data);
    TEST_ASSERT_TRUE(ce_status == CE_STATUS_ORIGINAL_ITEM_ERROR);

    //Check status of original and backup items -> only original private key exists
    //*************************************************************************************************
    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_SUCCESS, KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check status of original and backup items -> shoun't exist
    //*************************************************************************************************
    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_BACKUP_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Store original certificate
    //*************************************************************************************************
    test_store_items((uint8_t*)item_name, strlen((const char*)item_name),
        NULL, 0,
        testdata_public_ecc_python_key_2der, sizeof(testdata_public_ecc_python_key_2der),
        testdata_x509_pth_chain_child_2der, sizeof(testdata_x509_pth_chain_child_2der),
        KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Call ce_safe_renewal when mandatory certificate item is missing -> should fail to create backup items
    ce_status = ce_safe_renewal((const char*)item_name, &test_renewal_data);
    TEST_ASSERT_TRUE(ce_status == CE_STATUS_SUCCESS);

    //Check status of backup items
    //*************************************************************************************************
    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_BACKUP_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check new parameters
    //*************************************************************************************************
    //Check private key
    test_read_and_compare_item((const uint8_t*)item_name, strlen(item_name), testdata_private_ecc_python_key_3der, sizeof(testdata_private_ecc_python_key_3der), KCM_PRIVATE_KEY_ITEM, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();
    //Check public key
    test_read_and_compare_item((const uint8_t*)item_name, strlen(item_name), testdata_public_ecc_python_key_3der, sizeof(testdata_public_ecc_python_key_3der), KCM_PUBLIC_KEY_ITEM, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();
    //Check certificate
    test_read_and_compare_item((const uint8_t*)item_name, strlen(item_name), testdata_x509_pth_chain_child_2der, sizeof(testdata_x509_pth_chain_child_2der), KCM_CERTIFICATE_ITEM, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check renewal status
    kcm_status = _kcm_item_get_data_size((const uint8_t *)g_renewal_status_file, (size_t)strlen(g_renewal_status_file), KCM_CONFIG_ITEM, KCM_BACKUP_ITEM, &kcm_item_data_size_out);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_ITEM_NOT_FOUND);

}


TEST(ce_safe_store_tests, ce_safe_renewal_with_existing_renewal_status)
{
    char item_name[] = "LWM2M";
    ce_status_e  ce_status = CE_STATUS_SUCCESS;
    ce_renewal_params_s test_renewal_data;
    cs_ec_key_context_s ec_key_ctx;
    struct cert_chain_context_s test_chain_data;
    struct cert_context_s cert_data;
    char *private_key_name = (char*)g_fcc_lwm2m_device_private_key_name;
    char *certificate_name = (char*)g_fcc_lwm2m_device_certificate_name;
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    size_t kcm_item_data_size_out = 0;

    memset(&test_renewal_data, 0, sizeof(ce_renewal_params_s));
    memset(&ec_key_ctx, 0, sizeof(cs_ec_key_context_s));
    memset(&test_chain_data, 0, sizeof(struct cert_chain_context_s));
    memset(&cert_data, 0, sizeof(struct cert_context_s));

    //Store original items - with factory flag
    //*************************************************************************************************
    test_store_items((uint8_t*)item_name, strlen((const char*)item_name),
        testdata_private_ecc_python_key_2der, sizeof(testdata_private_ecc_python_key_2der),
        NULL, 0,
        testdata_x509_pth_chain_child_1der, sizeof(testdata_x509_pth_chain_child_1der),
        KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Set key crypto context
    memcpy(&ec_key_ctx.priv_key, &testdata_private_ecc_python_key_3der, sizeof(testdata_private_ecc_python_key_3der));
    ec_key_ctx.priv_key_size = sizeof(testdata_private_ecc_python_key_3der);

    //Set ce_renewal_params_s structure -> certificate and private key are correlated 
    //*************************************************************************************************
    test_renewal_data.crypto_handle = (cs_key_handle_t)&ec_key_ctx;
    test_chain_data.certs = (struct cert_context_s*)&cert_data;
    //Set cert data
    test_chain_data.chain_length = 1;
    test_chain_data.certs->cert = (uint8_t*)&testdata_x509_pth_chain_child_2der;
    test_chain_data.certs->cert_length = sizeof(testdata_x509_pth_chain_child_2der);
    test_chain_data.certs->next = NULL;
    test_renewal_data.cert_data = (struct cert_chain_context_s*)&test_chain_data;

    //Create renewal status file and write item_name to the file
    kcm_status = ce_create_renewal_status(item_name);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Call ce_safe_renewal
    //*************************************************************************************************
    ce_status = ce_safe_renewal((const char*)item_name, &test_renewal_data);
    TEST_ASSERT_TRUE(ce_status == CE_STATUS_SUCCESS);

    //Check new parameters
    //*************************************************************************************************
    //Check private key
    test_read_and_compare_item((const uint8_t*)private_key_name, strlen(private_key_name), testdata_private_ecc_python_key_3der, sizeof(testdata_private_ecc_python_key_3der), KCM_PRIVATE_KEY_ITEM, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();
    //Check certificate
    test_read_and_compare_item((const uint8_t*)certificate_name, strlen(certificate_name), testdata_x509_pth_chain_child_2der, sizeof(testdata_x509_pth_chain_child_2der), KCM_CERTIFICATE_ITEM, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check status of backup items
    //*************************************************************************************************
    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_BACKUP_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check renewal status
    kcm_status = _kcm_item_get_data_size((const uint8_t *)g_renewal_status_file, (size_t)strlen(g_renewal_status_file), KCM_CONFIG_ITEM, KCM_BACKUP_ITEM, &kcm_item_data_size_out);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_ITEM_NOT_FOUND);

}


TEST(ce_safe_store_tests, ce_check_and_restore_backup_status_with_kcm_init_test)
{
    char *item_name = NULL;
    char item_name_1[] = "verify_renewal";
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    size_t kcm_item_data_size_out = 0;
    int test_iteration = 0;
    char *private_key_name = (char*)g_fcc_lwm2m_device_private_key_name;
    char *certificate_name = (char*)g_fcc_lwm2m_device_certificate_name;
    char *public_key = NULL;

    /*****************************************************************************************************/
    /* 1. Case:    original items - present              **** backup items - present              **** status renewal - present  ===> backup moved to original, status renewal removed **/
    /* 2. Case:    original items - present              **** backup items - missing              **** status renewal - present  ===> original not deleted, status renweal removed **/
    /* 3. Case:    original items - missing              **** backup items - present              **** status renewal - present  ===> backup moved to original, status renewal removed**/
    /* 4. Case:    original items - missing              **** backup items - missing              **** status renewal - present  ===> status renewal removed**/
    /* 5. Case:    original items - certificate missing  **** backup items - present              **** status renewal - present  ===> status renewal removed**/
    /* 6. Case:    original items - present              **** backup items - private key missing  **** status renewal - present  ===> status renewal removed**/
    /*****************************************************************************************************/

    //**************************************************************************************************************************************************
    //Case 1 - original items - present  **** backup items - present **** status renewal - present  ===> backup moved to original, status renewal removed * /
    //**************************************************************************************************************************************************

    for (test_iteration = 0; test_iteration < 4; test_iteration++) {

        if (test_iteration % 1 == 0) {
            item_name = item_name_1;
        }
        if (test_iteration % 2 == 0) {
            item_name = (char*)g_lwm2m_name;
        }

        if (strcmp(item_name, g_lwm2m_name)) {
            private_key_name = (char*)item_name;
            certificate_name = (char*)item_name;
            public_key = item_name;
        } else {
            private_key_name = (char*)g_fcc_lwm2m_device_private_key_name;
            certificate_name = (char*)g_fcc_lwm2m_device_certificate_name;
            public_key = NULL;
        }

        //Store original items
        //*************************************************************************************************
        test_store_items((uint8_t*)item_name, strlen((const char*)item_name),
            testdata_private_ecc_python_key_2der, sizeof(testdata_private_ecc_python_key_2der),
            testdata_public_ecc_python_key_2der, sizeof(testdata_public_ecc_python_key_2der),
            testdata_x509_pth_chain_child_1der, sizeof(testdata_x509_pth_chain_child_1der),
            KCM_ORIGINAL_ITEM);
        TEST_SKIP_EXECUTION_ON_FAILURE();

        //Store new backup items
        //*************************************************************************************************
        test_store_items((uint8_t*)item_name, strlen((const char*)item_name),
            testdata_private_ecc_python_key_1der, sizeof(testdata_private_ecc_python_key_1der),
            testdata_public_ecc_python_key_1der, sizeof(testdata_public_ecc_python_key_1der),//public key
            testdata_x509_pth_chain_child_2der, sizeof(testdata_x509_pth_chain_child_2der),//certificate
            KCM_BACKUP_ITEM);
        TEST_SKIP_EXECUTION_ON_FAILURE();

        //Create renewal status file and write item_name to the file
        kcm_status = ce_create_renewal_status(item_name);
        TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

        if (test_iteration % 2 == 0) {
            //Call to kcm_finalize and kcm_init to check renewal status
            kcm_status = kcm_finalize();
            TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);
            kcm_status = kcm_init();
            TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);
        } else {
            //Call to ce_check_and_restore_backup_status
            ce_check_and_restore_backup_status();
        }

        //Check status of backup items
        //*************************************************************************************************
        test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_BACKUP_ITEM);
        TEST_SKIP_EXECUTION_ON_FAILURE();

        //Check new parameters
        //*************************************************************************************************
        //Check private key
        test_read_and_compare_item((const uint8_t*)private_key_name, strlen(private_key_name), testdata_private_ecc_python_key_1der, sizeof(testdata_private_ecc_python_key_1der), KCM_PRIVATE_KEY_ITEM, KCM_ORIGINAL_ITEM);
        TEST_SKIP_EXECUTION_ON_FAILURE();
        //Check public key
        if (public_key != NULL) {
            test_read_and_compare_item((const uint8_t*)public_key, strlen(public_key), testdata_public_ecc_python_key_1der, sizeof(testdata_public_ecc_python_key_1der), KCM_PUBLIC_KEY_ITEM, KCM_ORIGINAL_ITEM);
            TEST_SKIP_EXECUTION_ON_FAILURE();
        }

        //Check certificate
        test_read_and_compare_item((const uint8_t*)certificate_name, strlen(certificate_name), testdata_x509_pth_chain_child_2der, sizeof(testdata_x509_pth_chain_child_2der), KCM_CERTIFICATE_ITEM, KCM_ORIGINAL_ITEM);
        TEST_SKIP_EXECUTION_ON_FAILURE();

        //Check renewal status
        kcm_status = _kcm_item_get_data_size((const uint8_t *)g_renewal_status_file, (size_t)strlen(g_renewal_status_file), KCM_CONFIG_ITEM, KCM_BACKUP_ITEM, &kcm_item_data_size_out);
        TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_ITEM_NOT_FOUND);
        //*************************************************************************************************

        //**************************************************************************************************************************************************
        //Case 2   original items - present  **** backup items - missing **** status renewal - present  ===> original not deleted, status renweal removed* /
        //**************************************************************************************************************************************************

        ce_clean_items((const char *)item_name, KCM_BACKUP_ITEM, true);

        //Create renewal status file and write item_name to the file
        kcm_status = ce_create_renewal_status(item_name);
        TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

        if (test_iteration % 2 == 0) {
            //Call to kcm_finalize and kcm_init to check renewal status
            kcm_status = kcm_finalize();
            TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);
            kcm_status = kcm_init();
            TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);
        } else {
            //Call to ce_check_and_restore_backup_status
            ce_check_and_restore_backup_status();
        }

        //Check status of backup items
        //*************************************************************************************************
        test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_BACKUP_ITEM);
        TEST_SKIP_EXECUTION_ON_FAILURE();

        //Check new parameters
        //*************************************************************************************************
        //Check private key
        test_read_and_compare_item((const uint8_t*)private_key_name, strlen(private_key_name), testdata_private_ecc_python_key_1der, sizeof(testdata_private_ecc_python_key_1der), KCM_PRIVATE_KEY_ITEM, KCM_ORIGINAL_ITEM);
        TEST_SKIP_EXECUTION_ON_FAILURE();
        //Check public key
        if (public_key != NULL) {
            test_read_and_compare_item((const uint8_t*)public_key, strlen(public_key), testdata_public_ecc_python_key_1der, sizeof(testdata_public_ecc_python_key_1der), KCM_PUBLIC_KEY_ITEM, KCM_ORIGINAL_ITEM);
            TEST_SKIP_EXECUTION_ON_FAILURE();
        }
        //Check certificate
        test_read_and_compare_item((const uint8_t*)certificate_name, strlen(certificate_name), testdata_x509_pth_chain_child_2der, sizeof(testdata_x509_pth_chain_child_2der), KCM_CERTIFICATE_ITEM, KCM_ORIGINAL_ITEM);
        TEST_SKIP_EXECUTION_ON_FAILURE();

        //Check renewal status
        kcm_status = _kcm_item_get_data_size((const uint8_t *)g_renewal_status_file, (size_t)strlen(g_renewal_status_file), KCM_CONFIG_ITEM, KCM_BACKUP_ITEM, &kcm_item_data_size_out);
        TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_ITEM_NOT_FOUND);

        //**************************************************************************************************************************************************
        //Case 3   original items - missing  **** backup items - present **** status renewal - present  ===> backup moved to original, status renewal removed**/
        //**************************************************************************************************************************************************

        //Clean original items
        //*************************************************************************************************
        ce_clean_items((const char *)item_name, KCM_ORIGINAL_ITEM, true);

        //Store backup items
        //*************************************************************************************************
        test_store_items((uint8_t*)item_name, strlen((const char*)item_name),
            testdata_private_ecc_python_key_2der, sizeof(testdata_private_ecc_python_key_2der),
            testdata_public_ecc_python_key_2der, sizeof(testdata_public_ecc_python_key_2der),
            testdata_x509_pth_chain_child_1der, sizeof(testdata_x509_pth_chain_child_1der),
            KCM_BACKUP_ITEM);
        TEST_SKIP_EXECUTION_ON_FAILURE();

        //Create renewal status file and write item_name to the file
        //*************************************************************************************************
        kcm_status = ce_create_renewal_status(item_name);
        TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

        if (test_iteration % 2 == 0) {
            //Call to kcm_finalize and kcm_init to check renewal status
            kcm_status = kcm_finalize();
            TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);
            kcm_status = kcm_init();
            TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);
        } else {
            //Call to ce_check_and_restore_backup_status
            ce_check_and_restore_backup_status();
        }

        //Check status of backup items
        //*************************************************************************************************
        test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_BACKUP_ITEM);
        TEST_SKIP_EXECUTION_ON_FAILURE();

        //Check new parameters
        //*************************************************************************************************
        //Check private key
        test_read_and_compare_item((const uint8_t*)private_key_name, strlen(private_key_name), testdata_private_ecc_python_key_2der, sizeof(testdata_private_ecc_python_key_2der), KCM_PRIVATE_KEY_ITEM, KCM_ORIGINAL_ITEM);
        TEST_SKIP_EXECUTION_ON_FAILURE();
        //Check public key
        if (public_key != NULL) {
            test_read_and_compare_item((const uint8_t*)public_key, strlen(public_key), testdata_public_ecc_python_key_2der, sizeof(testdata_public_ecc_python_key_2der), KCM_PUBLIC_KEY_ITEM, KCM_ORIGINAL_ITEM);
            TEST_SKIP_EXECUTION_ON_FAILURE();
        }
        //Check certificate
        test_read_and_compare_item((const uint8_t*)certificate_name, strlen(certificate_name), testdata_x509_pth_chain_child_1der, sizeof(testdata_x509_pth_chain_child_1der), KCM_CERTIFICATE_ITEM, KCM_ORIGINAL_ITEM);
        TEST_SKIP_EXECUTION_ON_FAILURE();

        //Check renewal status
        kcm_status = _kcm_item_get_data_size((const uint8_t *)g_renewal_status_file, (size_t)strlen(g_renewal_status_file), KCM_CONFIG_ITEM, KCM_BACKUP_ITEM, &kcm_item_data_size_out);
        TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_ITEM_NOT_FOUND);

        //**************************************************************************************************************************************************
        //Case 4    original items - missing  **** backup items - missing **** status renewal - present  ===> status renewal removed**/
        //**************************************************************************************************************************************************

        ce_clean_items((const char *)item_name, KCM_ORIGINAL_ITEM, true);
        ce_clean_items((const char *)item_name, KCM_BACKUP_ITEM, true);

        //Create renewal status file and write item_name to the file
        kcm_status = ce_create_renewal_status(item_name);
        TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

        if (test_iteration % 2 == 0) {
            //Call to kcm_finalize and kcm_init to check renewal status
            kcm_status = kcm_finalize();
            TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);
            kcm_status = kcm_init();
            TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);
        } else {
            //Call to ce_check_and_restore_backup_status
            ce_check_and_restore_backup_status();
        }

        test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_BACKUP_ITEM);
        TEST_SKIP_EXECUTION_ON_FAILURE();

        test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_ORIGINAL_ITEM);
        TEST_SKIP_EXECUTION_ON_FAILURE();

        //Check renewal status
        kcm_status = _kcm_item_get_data_size((const uint8_t *)g_renewal_status_file, (size_t)strlen(g_renewal_status_file), KCM_CONFIG_ITEM, KCM_BACKUP_ITEM, &kcm_item_data_size_out);
        TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_ITEM_NOT_FOUND);
    }


    //**************************************************************************************************************************************************
    /* 5. Case:    original items - certificate missing  **** backup items - present              **** status renewal - present  ===> status renewal removed**/
    //**************************************************************************************************************************************************

    test_store_items((uint8_t*)item_name, strlen((const char*)item_name),
        testdata_private_ecc_python_key_2der, sizeof(testdata_private_ecc_python_key_2der),
        testdata_public_ecc_python_key_2der, sizeof(testdata_public_ecc_python_key_2der),
        NULL,0,//testdata_x509_pth_chain_child_1der, sizeof(testdata_x509_pth_chain_child_1der),
        KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Store new backup items
    //*************************************************************************************************
    test_store_items((uint8_t*)item_name, strlen((const char*)item_name),
        testdata_private_ecc_python_key_1der, sizeof(testdata_private_ecc_python_key_1der),
        testdata_public_ecc_python_key_1der, sizeof(testdata_public_ecc_python_key_1der),//public key
        testdata_x509_pth_chain_child_2der, sizeof(testdata_x509_pth_chain_child_2der),//certificate
        KCM_BACKUP_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Create renewal status file and write item_name to the file
    kcm_status = ce_create_renewal_status(item_name);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    if (test_iteration % 2 == 0) {
        //Call to kcm_finalize and kcm_init to check renewal status
        kcm_status = kcm_finalize();
        TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);
        kcm_status = kcm_init();
        TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);
    }
    else {
        //Call to ce_check_and_restore_backup_status
        ce_check_and_restore_backup_status();
    }

    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_BACKUP_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_SUCCESS, KCM_STATUS_SUCCESS, KCM_STATUS_SUCCESS, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check renewal status
    kcm_status = _kcm_item_get_data_size((const uint8_t *)g_renewal_status_file, (size_t)strlen(g_renewal_status_file), KCM_CONFIG_ITEM, KCM_BACKUP_ITEM, &kcm_item_data_size_out);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_ITEM_NOT_FOUND);

}




TEST(ce_safe_store_tests, ce_check_and_restore_backup_status_partial_data)
{
    char *item_name = "part_item";
    kcm_status_e kcm_status = KCM_STATUS_SUCCESS;
    size_t kcm_item_data_size_out = 0;
    int test_iteration = 0;
   // char *private_key_name = (char*)g_fcc_lwm2m_device_private_key_name;
   // char *certificate_name = (char*)g_fcc_lwm2m_device_certificate_name;
   // char *public_key = NULL;

    /*****************************************************************************************************/
    /* 1. Case:    original items - partial              **** backup items - present              **** status renewal - present  ===> backup moved to original, status renewal removed **/
    /* 2. Case:    original items - present              **** backup items - partial              **** status renewal - present  ===> original not deleted, backup deleted,status renweal removed **/
    /* 3. Case:    original items - partial              **** backup items - partial              **** status renewal - present  ===> original not deleted, backup deleted,status renweal removed **/
    /*****************************************************************************************************/

    //**************************************************************************************************************************************************
    //Case 1 - original items - partial  **** backup items - present **** status renewal - present  ===> backup moved to original, status renewal removed * /
    //**************************************************************************************************************************************************

    //Store original items
    //*************************************************************************************************
    test_store_items((uint8_t*)item_name, strlen((const char*)item_name),
        testdata_private_ecc_python_key_2der, sizeof(testdata_private_ecc_python_key_2der),
        testdata_public_ecc_python_key_2der, sizeof(testdata_public_ecc_python_key_2der),
        NULL,0,//testdata_x509_pth_chain_child_1der, sizeof(testdata_x509_pth_chain_child_1der),
        KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Store new backup items
    //*************************************************************************************************
    test_store_items((uint8_t*)item_name, strlen((const char*)item_name),
        testdata_private_ecc_python_key_1der, sizeof(testdata_private_ecc_python_key_1der),
        testdata_public_ecc_python_key_1der, sizeof(testdata_public_ecc_python_key_1der),//public key
        testdata_x509_pth_chain_child_2der, sizeof(testdata_x509_pth_chain_child_2der),//certificate
        KCM_BACKUP_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Create renewal status file and write item_name to the file
    kcm_status = ce_create_renewal_status(item_name);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);


    //Call to ce_check_and_restore_backup_status
    ce_check_and_restore_backup_status();

    //Check status of backup items
    //*************************************************************************************************
    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_BACKUP_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check new parameters
    //*************************************************************************************************
    //Check private key
    test_read_and_compare_item((const uint8_t*)item_name, strlen(item_name), testdata_private_ecc_python_key_1der, sizeof(testdata_private_ecc_python_key_1der), KCM_PRIVATE_KEY_ITEM, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();
    //Check public key
    test_read_and_compare_item((const uint8_t*)item_name, strlen(item_name), testdata_public_ecc_python_key_1der, sizeof(testdata_public_ecc_python_key_1der), KCM_PUBLIC_KEY_ITEM, KCM_ORIGINAL_ITEM);
        TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check certificate
    test_read_and_compare_item((const uint8_t*)item_name, strlen(item_name), testdata_x509_pth_chain_child_2der, sizeof(testdata_x509_pth_chain_child_2der), KCM_CERTIFICATE_ITEM, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check renewal status
    kcm_status = _kcm_item_get_data_size((const uint8_t *)g_renewal_status_file, (size_t)strlen(g_renewal_status_file), KCM_CONFIG_ITEM, KCM_BACKUP_ITEM, &kcm_item_data_size_out);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_ITEM_NOT_FOUND);
    //*************************************************************************************************

    /* Case 2 original items - present              **** backup items - partial              **** status renewal - present  ===> original not deleted, backup deleted,status renweal removed **/
    //*************************************************************************************************
    ce_clean_items((const char *)item_name, KCM_ORIGINAL_ITEM, true);
    ce_clean_items((const char *)item_name, KCM_BACKUP_ITEM, true);

    //Store original items
    //*************************************************************************************************
    test_store_items((uint8_t*)item_name, strlen((const char*)item_name),
        testdata_private_ecc_python_key_2der, sizeof(testdata_private_ecc_python_key_2der),
        testdata_public_ecc_python_key_2der, sizeof(testdata_public_ecc_python_key_2der),
        testdata_x509_pth_chain_child_1der, sizeof(testdata_x509_pth_chain_child_1der),
        KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Store new backup items
    //*************************************************************************************************
    test_store_items((uint8_t*)item_name, strlen((const char*)item_name),
        NULL,0,//    testdata_private_ecc_python_key_1der, sizeof(testdata_private_ecc_python_key_1der),
        testdata_public_ecc_python_key_1der, sizeof(testdata_public_ecc_python_key_1der),//public key
        testdata_x509_pth_chain_child_2der, sizeof(testdata_x509_pth_chain_child_2der),//certificate
        KCM_BACKUP_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Create renewal status file and write item_name to the file
    kcm_status = ce_create_renewal_status(item_name);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Call to ce_check_and_restore_backup_status
    ce_check_and_restore_backup_status();

    //Check status of backup items
    //*************************************************************************************************
    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_BACKUP_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check new parameters
    //*************************************************************************************************
    //Check private key
    test_read_and_compare_item((const uint8_t*)item_name, strlen(item_name), testdata_private_ecc_python_key_2der, sizeof(testdata_private_ecc_python_key_2der), KCM_PRIVATE_KEY_ITEM, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();
    //Check public key
    test_read_and_compare_item((const uint8_t*)item_name, strlen(item_name), testdata_public_ecc_python_key_2der, sizeof(testdata_public_ecc_python_key_2der), KCM_PUBLIC_KEY_ITEM, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check certificate
    test_read_and_compare_item((const uint8_t*)item_name, strlen(item_name), testdata_x509_pth_chain_child_1der, sizeof(testdata_x509_pth_chain_child_1der), KCM_CERTIFICATE_ITEM, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check renewal status
    kcm_status = _kcm_item_get_data_size((const uint8_t *)g_renewal_status_file, (size_t)strlen(g_renewal_status_file), KCM_CONFIG_ITEM, KCM_BACKUP_ITEM, &kcm_item_data_size_out);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_ITEM_NOT_FOUND);

    /* Case 2 original items - partial              **** backup items - partial              **** status renewal - present  ===> original not deleted, backup deleted,status renweal removed **/
    //*************************************************************************************************

    ce_clean_items((const char *)item_name, KCM_ORIGINAL_ITEM, true);
    ce_clean_items((const char *)item_name, KCM_BACKUP_ITEM, true);

    //Store original items
    //*************************************************************************************************
    test_store_items((uint8_t*)item_name, strlen((const char*)item_name),
        NULL,0,//testdata_private_ecc_python_key_2der, sizeof(testdata_private_ecc_python_key_2der),
        testdata_public_ecc_python_key_2der, sizeof(testdata_public_ecc_python_key_2der),
        testdata_x509_pth_chain_child_1der, sizeof(testdata_x509_pth_chain_child_1der),
        KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Store new backup items
    //*************************************************************************************************
    test_store_items((uint8_t*)item_name, strlen((const char*)item_name),
        NULL, 0,//    testdata_private_ecc_python_key_1der, sizeof(testdata_private_ecc_python_key_1der),
        testdata_public_ecc_python_key_1der, sizeof(testdata_public_ecc_python_key_1der),//public key
        testdata_x509_pth_chain_child_2der, sizeof(testdata_x509_pth_chain_child_2der),//certificate
        KCM_BACKUP_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Create renewal status file and write item_name to the file
    kcm_status = ce_create_renewal_status(item_name);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_SUCCESS);

    //Call to ce_check_and_restore_backup_status
    ce_check_and_restore_backup_status();

    //Check new parameters
    //*************************************************************************************************
    //Check certificate
    test_read_and_compare_item((const uint8_t*)item_name, strlen(item_name), testdata_x509_pth_chain_child_1der, sizeof(testdata_x509_pth_chain_child_1der), KCM_CERTIFICATE_ITEM, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    //Check renewal status
    kcm_status = _kcm_item_get_data_size((const uint8_t *)g_renewal_status_file, (size_t)strlen(g_renewal_status_file), KCM_CONFIG_ITEM, KCM_BACKUP_ITEM, &kcm_item_data_size_out);
    TEST_ASSERT_TRUE(kcm_status == KCM_STATUS_ITEM_NOT_FOUND);

    //Check status of backup items
    //*************************************************************************************************
    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_ITEM_NOT_FOUND, KCM_BACKUP_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    test_check_items((const uint8_t*)item_name, strlen((const char*)item_name), KCM_STATUS_ITEM_NOT_FOUND, KCM_STATUS_SUCCESS, KCM_STATUS_SUCCESS, KCM_ORIGINAL_ITEM);
    TEST_SKIP_EXECUTION_ON_FAILURE();
}



TEST_GROUP_RUNNER(ce_safe_store_tests)
{
    RUN_TEST_CASE(ce_safe_store_tests, ce_create_backup_single_certificate_and_public_key);
    RUN_TEST_CASE(ce_safe_store_tests, ce_create_backup_lwm2m);
    RUN_TEST_CASE(ce_safe_store_tests, ce_create_backup_certificate_chain_without_public_key);
    RUN_TEST_CASE(ce_safe_store_tests, ce_create_backup_bad_params);
    RUN_TEST_CASE(ce_safe_store_tests, ce_clean_items_test);
    RUN_TEST_CASE(ce_safe_store_tests, ce_clean_lwm2m_items_test);
    RUN_TEST_CASE(ce_safe_store_tests, ce_restore_backup_params);
    RUN_TEST_CASE(ce_safe_store_tests, ce_restore_backup_lwm2m2_params);
    RUN_TEST_CASE(ce_safe_store_tests, ce_restore_backup_params_bad_params);
    RUN_TEST_CASE(ce_safe_store_tests, ce_restore_backup_params_with_factory_reset);
    RUN_TEST_CASE(ce_safe_store_tests, ce_safe_renewal_single_certificate);
    RUN_TEST_CASE(ce_safe_store_tests, ce_safe_renewal_certificate_chain);
    RUN_TEST_CASE(ce_safe_store_tests, ce_safe_renewal_bad_params);
    RUN_TEST_CASE(ce_safe_store_tests, ce_safe_renewal_with_existing_renewal_status);
    RUN_TEST_CASE(ce_safe_store_tests, ce_check_and_restore_backup_status_with_kcm_init_test);
    RUN_TEST_CASE(ce_safe_store_tests, ce_check_and_restore_backup_status_partial_data);

}
