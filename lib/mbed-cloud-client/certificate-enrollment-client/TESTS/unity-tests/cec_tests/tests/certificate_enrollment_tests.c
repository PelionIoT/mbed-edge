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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "unity_fixture.h"
#include "pv_error_handling.h"
#include "ce_common_helper.h"
#include "factory_configurator_client.h"
#include "certificate_enrollment.h"
#include "key_config_manager.h"
#include "kcm_internal.h"
#include "testdata.h"
#include "ce_crypto_test_utils.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"


TEST_GROUP(certificate_enrollment_tests);

TEST_SETUP(certificate_enrollment_tests)
{
    ce_tst_setup();
    TEST_SKIP_EXECUTION_ON_FAILURE();
}

TEST_TEAR_DOWN(certificate_enrollment_tests)
{
    ce_tst_tear_down();
    TEST_SKIP_EXECUTION_ON_FAILURE();
}


static ce_status_e create_x509_csr(const char *certificate_name, uint8_t **csr_out, size_t *csr_size_out)
{
    kcm_status_e kcm_status;
    ce_status_e ce_status;
    cs_key_handle_t key_h;

    kcm_status = cs_ec_key_new(&key_h);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), CE_STATUS_ERROR, "failed for cs_ec_key_new()");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_h == 0), CE_STATUS_ERROR, "got invalid handle value");

    // request to update the certificate we've just stored
    ce_status = ce_generate_keys_and_create_csr_from_certificate(certificate_name, key_h, csr_out, csr_size_out);

    kcm_status = cs_ec_key_free(&key_h);
    SA_PV_ERR_RECOVERABLE_RETURN_IF((kcm_status != KCM_STATUS_SUCCESS), CE_STATUS_ERROR, "failed for cs_ec_key_free()");
    SA_PV_ERR_RECOVERABLE_RETURN_IF((key_h != 0), CE_STATUS_ERROR, "got invalid handle value - should be zero");

    return ce_status;
}

TEST(certificate_enrollment_tests, try_to_update_some_custom_certificate_without_private_key_in_storage)
{
    ce_status_e ce_status;

    uint8_t *csr_buff = NULL;
    size_t csr_buff_size = 0;
    const char *certificate_name = "arm-cert";

    kcm_status_e kcm_status;

    // store certificate
    kcm_status = kcm_item_store((const uint8_t *)certificate_name, strlen(certificate_name), KCM_CERTIFICATE_ITEM, false,
                                testdata_x509_crt_based_on_csr_pyth_cmp_cri_der, sizeof(testdata_x509_crt_based_on_csr_pyth_cmp_cri_der), NULL);

    TEST_ASSERT_EQUAL_INT(KCM_STATUS_SUCCESS, kcm_status);

    /* NO PRIVATE KEY IN STORE */

    ce_status = create_x509_csr(certificate_name, &csr_buff, &csr_buff_size);
    TEST_ASSERT_EQUAL(CE_STATUS_ITEM_NOT_FOUND, ce_status);
    TEST_ASSERT_NULL(csr_buff);
    TEST_ASSERT_TRUE(csr_buff_size == 0);
}

TEST(certificate_enrollment_tests, try_to_update_bootstrap_certificate)
{
    ce_status_e ce_status;

    uint8_t *csr_buff = NULL;
    size_t csr_buff_size = 17;

    store_certificate_and_private_key(g_fcc_bootstrap_device_certificate_name);
    
    ce_status = create_x509_csr(g_fcc_bootstrap_device_certificate_name, &csr_buff, &csr_buff_size);
    
    TEST_ASSERT_EQUAL(CE_STATUS_FORBIDDEN_REQUEST, ce_status);
    TEST_ASSERT_NULL(csr_buff);
    TEST_ASSERT_EQUAL(17, csr_buff_size);
}

TEST(certificate_enrollment_tests, update_lwm2m_certificate)
{
    ce_status_e ce_status;

    uint8_t *csr_buff = NULL;
    size_t csr_buff_size = 0;
    mbedtls_x509_crt crt;


    store_certificate_and_private_key("LWM2M");
    
    // create CSR by the device
    ce_status = create_x509_csr("LWM2M", &csr_buff, &csr_buff_size);
    TEST_ASSERT_EQUAL(CE_STATUS_SUCCESS, ce_status);
    TEST_ASSERT_NOT_NULL(csr_buff);
    TEST_ASSERT_TRUE(csr_buff_size > 0);

    // convert the resulting CSR back to certificate using mbedtls library
    create_x509_crt_from_csr(csr_buff, csr_buff_size, &crt);


    // TBD: the resulting "crt" should be equal to our origin certificate.
    //      currently we can't compare them since the "csr" on which we 
    //      we generate the "crt" uses auto-generated key pair as part of the
    //      calling sequence. Once integration is done we'll come back and
    //      establish that check by generating the resulting "crt" in python.


    free(csr_buff);
    mbedtls_x509_crt_free(&crt);
}

TEST(certificate_enrollment_tests, update_some_custom_certificate)
{
    ce_status_e ce_status;
    
    uint8_t *csr_buff = NULL;
    size_t csr_buff_size = 0;
    mbedtls_x509_crt crt;
    const char *certificate_name = "some-oem-custom-cert-name";


    // store some certificate
    store_certificate_and_private_key(certificate_name);
    
    // create CSR by the device
    ce_status = create_x509_csr(certificate_name, &csr_buff, &csr_buff_size);
    TEST_ASSERT_EQUAL(CE_STATUS_SUCCESS, ce_status);
    TEST_ASSERT_NOT_NULL(csr_buff);
    TEST_ASSERT_TRUE(csr_buff_size > 0);

    // convert the resulting CSR back to certificate using mbedtls library
    create_x509_crt_from_csr(csr_buff, csr_buff_size, &crt);


    // TBD: the resulting "crt" should be equal to our origin certificate.
    //      currently we can't compare them since the "csr" on which we 
    //      we generate the "crt" uses auto-generated key pair as part of the
    //      calling sequence. Once integration is done we'll come back and
    //      establish that check by generating the resulting "crt" in python.


    free(csr_buff);
    mbedtls_x509_crt_free(&crt);
}

TEST_GROUP_RUNNER(certificate_enrollment_tests)
{
    RUN_TEST_CASE(certificate_enrollment_tests, try_to_update_bootstrap_certificate);
    RUN_TEST_CASE(certificate_enrollment_tests, update_lwm2m_certificate);
    RUN_TEST_CASE(certificate_enrollment_tests, update_some_custom_certificate);
    RUN_TEST_CASE(certificate_enrollment_tests, try_to_update_some_custom_certificate_without_private_key_in_storage);
}
