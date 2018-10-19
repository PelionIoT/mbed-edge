//----------------------------------------------------------------------------
//   The confidential and proprietary information contained in this file may
//   only be used by a person authorised under and to the extent permitted
//   by a subsisting licensing agreement from ARM Limited or its affiliates.
//
//          (C) COPYRIGHT 2013-2018 ARM Limited or its affiliates.
//              ALL RIGHTS RESERVED
//
//   This entire notice must be reproduced on all copies of this file
//   and copies of this file may only be made by a person if such person is
//   permitted to do so under the terms of a subsisting license agreement
//   from ARM Limited or its affiliates.
//----------------------------------------------------------------------------

#include <stdio.h>
#include <assert.h>

#include "unity_fixture.h"
#include "factory_configurator_client.h"
#include "key_config_manager.h"
#include "testdata.h"
#include "pal.h"


void ce_tst_setup(void)
{
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;

    //init store
    fcc_status = fcc_init();
    TEST_ASSERT(fcc_status == FCC_STATUS_SUCCESS);

    fcc_status = fcc_storage_delete();
    TEST_ASSERT(fcc_status == FCC_STATUS_SUCCESS);
}

void ce_tst_tear_down(void)
{
    fcc_status_e fcc_status = FCC_STATUS_SUCCESS;
    int32_t pal_ref_count;

    fcc_status = fcc_storage_delete();
    TEST_ASSERT(fcc_status == FCC_STATUS_SUCCESS);

    //finalize store
    fcc_status = fcc_finalize();
    TEST_ASSERT(fcc_status == FCC_STATUS_SUCCESS);

    //When g_palIntialized = 0, pal_destroy() won't do anything and will return 0
    //When g_palIntialized = 1, pal_destroy() will close the pal and will return 0
    //When g_palIntialized > 1, pal_destroy() will decrease g_palIntialized by 1 and will return 1
    pal_ref_count = pal_destroy();
    TEST_ASSERT(pal_ref_count == 0);
}

void store_certificate_and_private_key(const char *certificate_name)
{
    kcm_status_e kcm_status;

    const char *_certificate_name = certificate_name;
    const char *_private_key_name = certificate_name;

    if (strcmp(certificate_name, "LWM2M") == 0) {
        _certificate_name = g_fcc_lwm2m_device_certificate_name;
        _private_key_name = g_fcc_lwm2m_device_private_key_name;
    }

    // store certificate
    kcm_status = kcm_item_store((const uint8_t *)_certificate_name, strlen(_certificate_name), KCM_CERTIFICATE_ITEM, false,
                                testdata_x509_crt_based_on_csr_pyth_cmp_cri_der, sizeof(testdata_x509_crt_based_on_csr_pyth_cmp_cri_der), NULL);

    TEST_ASSERT_EQUAL_INT(KCM_STATUS_SUCCESS, kcm_status);

    // store certificate's private key
    kcm_status = kcm_item_store((const uint8_t *)_private_key_name, strlen(_private_key_name), KCM_PRIVATE_KEY_ITEM, false,
                                testdata_priv_ecc_key1der, sizeof(testdata_priv_ecc_key1der), NULL);

    TEST_ASSERT_EQUAL_INT(KCM_STATUS_SUCCESS, kcm_status);
}
