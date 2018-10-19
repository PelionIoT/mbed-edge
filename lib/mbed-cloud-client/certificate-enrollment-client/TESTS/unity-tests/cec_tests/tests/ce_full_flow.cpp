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
#include "TestCertificateEnrollmentClient.h"
#include "ce_common_helper.h"
#include "MbedCloudClient.h"
#include "pal.h"
#include "key_config_manager.h"
#include "testdata.h"
#include "string.h"
#include "fcc_defs.h"
#include "pv_log.h"
#include "ce_tlv.h"


#define TEST_CERT_NAME "TestCertificate"
#define LAST_CHAR_OFFSET 'A'
#define LAST_CHAR_TO_ID(last_char) (last_char - LAST_CHAR_OFFSET)
#define ID_TO_LAST_CHAR(id) (id + LAST_CHAR_OFFSET)
#define CERT_NAME_TO_ID(cert_name) ( LAST_CHAR_TO_ID(cert_name[strlen(cert_name) - 1]) )
#define CE_TLV_TYPE_UNKNOWN_TYPE ((ce_tlv_type_e)999)


extern MbedCloudClient *g_mcc;

palSemaphoreID_t test_sem = 0;
static int32_t g_renewal_success_counter = 0;
static int32_t g_threads_finished = 0;
static bool g_test_status;
static uint8_t g_tlv_buf[TEST_TLV_MAX_SIZE];
static ce_tlv_encoder_s g_tlv_encoder;

static void certificate_renewal_cb_success(const char *cert_name, ce_status_e status, ce_initiator_e initiator)
{
    SA_PV_LOG_INFO("User callback. Certificate renewal completed:\n Certificate name: %s\nStatus: %d\nInitiator: %d\n", cert_name, status, initiator);
    pal_osSemaphoreRelease(test_sem);
    TEST_ASSERT_EQUAL_INT(CE_STATUS_SUCCESS, status);
}

static void certificate_renewal_cb_assert_tlv_error(const char *cert_name, ce_status_e status, ce_initiator_e initiator)
{
    SA_PV_LOG_INFO("User callback. Certificate renewal completed:\n Certificate name: %s\nStatus: %d\nInitiator: %d\n", cert_name, status, initiator);
    pal_osSemaphoreRelease(test_sem);
    TEST_ASSERT_EQUAL_INT(CE_STATUS_BAD_INPUT_FROM_SERVER, status);
}


TEST_GROUP(ce_full_flow);

TEST_SETUP(ce_full_flow)
{
    palStatus_t pal_status = PAL_SUCCESS;
    ce_tst_setup();
    TEST_SKIP_EXECUTION_ON_FAILURE();

    TestCertificateEnrollmentClient::test_init();
    TEST_SKIP_EXECUTION_ON_FAILURE();

    pal_status = pal_osSemaphoreCreate(1, &test_sem);
    TEST_ASSERT_EQUAL_INT(PAL_SUCCESS, pal_status);

    g_renewal_success_counter = 0;
    g_threads_finished = 0;
    g_test_status = true;

    ce_tlv_encoder_init(g_tlv_buf, sizeof(g_tlv_buf), &g_tlv_encoder);
}

TEST_TEAR_DOWN(ce_full_flow)
{
    palStatus_t pal_status = PAL_SUCCESS;

    ce_tst_tear_down();
    TEST_SKIP_EXECUTION_ON_FAILURE();

    pal_status = pal_osSemaphoreDelete(&test_sem);
    TEST_ASSERT_EQUAL_INT(PAL_SUCCESS, pal_status);

    TestCertificateEnrollmentClient::test_finalize();
}

TEST(ce_full_flow, simple_flow)
{
    ce_status_e ce_status;
    palStatus_t pal_status = PAL_SUCCESS;
    kcm_status_e kcm_status;

    store_certificate_and_private_key(TEST_CERT_NAME);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    g_mcc->on_certificate_renewal(certificate_renewal_cb_success);

    pal_status = pal_osSemaphoreWait(test_sem, PAL_RTOS_WAIT_FOREVER, NULL);
    TEST_ASSERT_EQUAL_INT(PAL_SUCCESS, pal_status);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    // Device initiated
    ce_status = g_mcc->certificate_renew(TEST_CERT_NAME);
    TEST_ASSERT_EQUAL_INT(CE_STATUS_SUCCESS, ce_status);

    // Wait to finish
    pal_status = pal_osSemaphoreWait(test_sem, PAL_RTOS_WAIT_FOREVER, NULL);
    TEST_ASSERT_EQUAL_INT(PAL_SUCCESS, pal_status);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    // Server initiated
    
    tlv_add_str(CE_TLV_TYPE_CERT_NAME, strlen(TEST_CERT_NAME) + 1, TEST_CERT_NAME, false, &g_tlv_encoder);

    TestCertificateEnrollmentClient::server_initiated_certificate_renewal(g_tlv_encoder.buf, g_tlv_encoder.encoded_length);

    // Wait to finish
    pal_status = pal_osSemaphoreWait(test_sem, PAL_RTOS_WAIT_FOREVER, NULL);
    TEST_ASSERT_EQUAL_INT(PAL_SUCCESS, pal_status);
}

TEST(ce_full_flow, tlv_has_an_optional_faulty_item)
{
    ce_status_e ce_status;
    palStatus_t pal_status = PAL_SUCCESS;
    kcm_status_e kcm_status;

    store_certificate_and_private_key(TEST_CERT_NAME);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    g_mcc->on_certificate_renewal(certificate_renewal_cb_success);

    pal_status = pal_osSemaphoreWait(test_sem, PAL_RTOS_WAIT_FOREVER, NULL);
    TEST_ASSERT_EQUAL_INT(PAL_SUCCESS, pal_status);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    // Server initiated

    //----------- TLV -------------
    // unknown TLV type | optional
    // known TLV type   | required
    //-----------------------------

    // Expected result: the optional should be skipped and the required should be parsed successfully

    tlv_add_str(CE_TLV_TYPE_UNKNOWN_TYPE, strlen("some_unknown_certificate") + 1, "some_unknown_certificate", false, &g_tlv_encoder);
    tlv_add_str(CE_TLV_TYPE_CERT_NAME, strlen(TEST_CERT_NAME) + 1, TEST_CERT_NAME, true, &g_tlv_encoder);

    TestCertificateEnrollmentClient::server_initiated_certificate_renewal(g_tlv_encoder.buf, g_tlv_encoder.encoded_length);

    // Wait to finish
    pal_status = pal_osSemaphoreWait(test_sem, PAL_RTOS_WAIT_FOREVER, NULL);
    TEST_ASSERT_EQUAL_INT(PAL_SUCCESS, pal_status);
}

TEST(ce_full_flow, tlv_has_a_required_faulty_item)
{
    ce_status_e ce_status;
    palStatus_t pal_status = PAL_SUCCESS;
    kcm_status_e kcm_status;

    store_certificate_and_private_key(TEST_CERT_NAME);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    g_mcc->on_certificate_renewal(certificate_renewal_cb_assert_tlv_error);

    pal_status = pal_osSemaphoreWait(test_sem, PAL_RTOS_WAIT_FOREVER, NULL);
    TEST_ASSERT_EQUAL_INT(PAL_SUCCESS, pal_status);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    // Server initiated

    //----------- TLV -------------
    // unknown TLV type | required
    // known TLV type   | optional
    //-----------------------------

    // Expected result: the first required element should yield an error

    tlv_add_str(CE_TLV_TYPE_UNKNOWN_TYPE, strlen("some_unknown_certificate") + 1, "some_unknown_certificate", true, &g_tlv_encoder);
    tlv_add_str(CE_TLV_TYPE_CERT_NAME, strlen(TEST_CERT_NAME) + 1, TEST_CERT_NAME, false, &g_tlv_encoder);

    TestCertificateEnrollmentClient::server_initiated_certificate_renewal(g_tlv_encoder.buf, g_tlv_encoder.encoded_length);

    // Wait to finish
    pal_status = pal_osSemaphoreWait(test_sem, PAL_RTOS_WAIT_FOREVER, NULL);
    TEST_ASSERT_EQUAL_INT(PAL_SUCCESS, pal_status);
}

TEST(ce_full_flow, tlv_has_two_optional_items)
{
    ce_status_e ce_status;
    palStatus_t pal_status = PAL_SUCCESS;
    kcm_status_e kcm_status;

    store_certificate_and_private_key(TEST_CERT_NAME);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    g_mcc->on_certificate_renewal(certificate_renewal_cb_success);

    pal_status = pal_osSemaphoreWait(test_sem, PAL_RTOS_WAIT_FOREVER, NULL);
    TEST_ASSERT_EQUAL_INT(PAL_SUCCESS, pal_status);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    // Server initiated

    //----------- TLV -------------
    // unknown TLV type | optional
    // known TLV type   | optional
    //-----------------------------

    // Expected result: the unknown type optional element should be skipped and the second optional (known type) should be parsed successfully

    tlv_add_str(CE_TLV_TYPE_UNKNOWN_TYPE, strlen("some_unknown_certificate") + 1, "some_unknown_certificate", false, &g_tlv_encoder);
    tlv_add_str(CE_TLV_TYPE_CERT_NAME, strlen(TEST_CERT_NAME) + 1, TEST_CERT_NAME, false, &g_tlv_encoder);

    TestCertificateEnrollmentClient::server_initiated_certificate_renewal(g_tlv_encoder.buf, g_tlv_encoder.encoded_length);

    // Wait to finish
    pal_status = pal_osSemaphoreWait(test_sem, PAL_RTOS_WAIT_FOREVER, NULL);
    TEST_ASSERT_EQUAL_INT(PAL_SUCCESS, pal_status);
}

TEST(ce_full_flow, tlv_has_two_required_items)
{
    ce_status_e ce_status;
    palStatus_t pal_status = PAL_SUCCESS;
    kcm_status_e kcm_status;

    store_certificate_and_private_key(TEST_CERT_NAME);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    g_mcc->on_certificate_renewal(certificate_renewal_cb_assert_tlv_error);

    pal_status = pal_osSemaphoreWait(test_sem, PAL_RTOS_WAIT_FOREVER, NULL);
    TEST_ASSERT_EQUAL_INT(PAL_SUCCESS, pal_status);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    // Server initiated

    //----------- TLV -------------
    // unknown TLV type | required
    // known TLV type   | required
    //-----------------------------

    // Expected result: the first required element should yield an error

    tlv_add_str(CE_TLV_TYPE_UNKNOWN_TYPE, strlen("some_unknown_certificate") + 1, "some_unknown_certificate", true, &g_tlv_encoder);
    tlv_add_str(CE_TLV_TYPE_CERT_NAME, strlen(TEST_CERT_NAME) + 1, TEST_CERT_NAME, true, &g_tlv_encoder);

    TestCertificateEnrollmentClient::server_initiated_certificate_renewal(g_tlv_encoder.buf, g_tlv_encoder.encoded_length);

    // Wait to finish
    pal_status = pal_osSemaphoreWait(test_sem, PAL_RTOS_WAIT_FOREVER, NULL);
    TEST_ASSERT_EQUAL_INT(PAL_SUCCESS, pal_status);
}

#define NUMBER_OF_THREADS 8
#if defined(PTHREAD_STACK_MIN)
#define CEC_TEST_THREAD_STACK_SIZE PTHREAD_STACK_MIN * 6
#else
#define CEC_TEST_THREAD_STACK_SIZE 1024
#endif

struct thread_data_s {
public:
    char cert_name[25];
    ce_initiator_e initiator;
    palSemaphoreID_t sem;
    palThreadID_t thread;
    ce_status_e status;

    thread_data_s() : initiator(CE_INITIATOR_DEVICE), thread(0), sem(0), status(CE_MAX_STATUS) { }

    bool init()
    {
        palStatus_t pal_status;

        pal_status = pal_osSemaphoreCreate(1, &sem);
        if (pal_status != PAL_SUCCESS) {
            return false;
        }

        pal_status = pal_osSemaphoreWait(sem, PAL_RTOS_WAIT_FOREVER, NULL);
        assert(pal_status == PAL_SUCCESS);
        return true;
    }

    bool start_thread(palThreadFuncPtr thread_func)
    {
        palStatus_t pal_status;
        pal_status = pal_osThreadCreateWithAlloc(thread_func, (void *)this, PAL_osPriorityNormal,
                                                 CEC_TEST_THREAD_STACK_SIZE, NULL, &thread);
        assert(pal_status == PAL_SUCCESS);
        if (pal_status != PAL_SUCCESS) {
            return false;
        }
        return true;
    }

    ce_status_e test_cert_renewal_blocking(uint8_t cert_name_id)
    {
        palStatus_t pal_status;
        ce_status_e ce_status;
        strcpy(cert_name, TEST_CERT_NAME);
        cert_name[sizeof(TEST_CERT_NAME) - 1] = ID_TO_LAST_CHAR(cert_name_id);
        cert_name[sizeof(TEST_CERT_NAME)] = '\0';
        if (initiator == CE_INITIATOR_DEVICE) {
            // Device initiated
            ce_status = g_mcc->certificate_renew(cert_name);
            if (ce_status != CE_STATUS_SUCCESS) {
                return ce_status;
            }

        } else {
            // Server initiated

            tlv_add_str(CE_TLV_TYPE_CERT_NAME, strlen(cert_name) + 1, cert_name, false, &g_tlv_encoder);

            TestCertificateEnrollmentClient::server_initiated_certificate_renewal(g_tlv_encoder.buf, g_tlv_encoder.encoded_length);
        }
        pal_status = pal_osSemaphoreWait(sem, PAL_RTOS_WAIT_FOREVER, NULL);
        assert(pal_status == PAL_SUCCESS);
        
        return status;
    }

    // By default, use cert_name. 
    ce_status_e test_cert_renewal_blocking()
    {
        return test_cert_renewal_blocking(CERT_NAME_TO_ID(cert_name));
    }

    bool release()
    {
        palStatus_t pal_status;

        if (thread) {
            pal_status = pal_osThreadTerminate(&thread);
            assert(pal_status == PAL_SUCCESS);
        }

        pal_status = pal_osSemaphoreDelete(&sem);
        assert(pal_status == PAL_SUCCESS);
        return true;
    }

};



thread_data_s g_thread_data[NUMBER_OF_THREADS];

static void certificate_renewal_multiple_threads_cb(const char *cert_name, ce_status_e status, ce_initiator_e initiator)
{
    palStatus_t pal_status = PAL_SUCCESS;
    
    printf("User callback. Certificate renewal completed:\n Certificate name: %s\nStatus: %d\nInitiator: %d\n", cert_name, status, initiator);

    int id = CERT_NAME_TO_ID(cert_name);
    g_thread_data[id].status = status;
    pal_osSemaphoreRelease(g_thread_data[id].sem);
}



static void thread_renew_cert(void const *arg)
{
    palStatus_t pal_status = PAL_SUCCESS;
    thread_data_s *thread_args = (thread_data_s *)arg;
    ce_status_e ce_status;
    int32_t threads_completed;

    int id = CERT_NAME_TO_ID(thread_args->cert_name);

    while (true) {
        ce_status = thread_args->test_cert_renewal_blocking();
        if (ce_status == CE_STATUS_SUCCESS) { // If success - increment the success counter
            // Atomic update is required since once the user callback is called, new threads may renew
            (void)pal_osAtomicIncrement(&g_renewal_success_counter, 1);
            break;
        } else if (ce_status == CE_STATUS_DEVICE_BUSY) { // If device busy - try again
            pal_osDelay(1000);
            continue;
        } else {
            TEST_ASSERT_MESSAGE(false, "renewal operation returned returned status that is neither CE_STATUS_SUCCESS nor CE_STATUS_DEVICE_BUSY");
            break;
        }
    }

    // Increment the thread finished counter
    threads_completed = pal_osAtomicIncrement(&g_threads_finished, 1);

    // If this is the last thread finished - signal the test semaphore
    if (threads_completed == NUMBER_OF_THREADS) {
        pal_osSemaphoreRelease(test_sem);
    }
}

// FIXME: Ignore test until cleanup and review
IGNORE_TEST(ce_full_flow, simple_flow_sync_test_apis)
{
    ce_status_e ce_status;
    size_t len = 0;
    palStatus_t pal_status = PAL_SUCCESS;
    kcm_status_e kcm_status;
    bool status;

    // Id 0 is TEST_CERT_NAME "A", id 1 is TEST_CERT_NAME "B", etc...
    store_certificate_and_private_key(TEST_CERT_NAME "A");

    g_mcc->on_certificate_renewal(certificate_renewal_multiple_threads_cb);
    
    status = g_thread_data[0].init();
    TEST_ASSERT_EQUAL_INT(true, status);

    g_thread_data[0].initiator = CE_INITIATOR_DEVICE;
    ce_status = g_thread_data[0].test_cert_renewal_blocking(0);
    TEST_ASSERT_EQUAL_INT(CE_STATUS_SUCCESS, ce_status);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    g_thread_data[0].initiator = CE_INITIATOR_SERVER;
    g_thread_data[0].test_cert_renewal_blocking(0);
    TEST_ASSERT_EQUAL_INT(CE_STATUS_SUCCESS, ce_status);
    TEST_SKIP_EXECUTION_ON_FAILURE();
}

// FIXME: Ignore test until cleanup and review
IGNORE_TEST(ce_full_flow, multiple_thread_renewal)
{
    int i;
    palStatus_t pal_status = PAL_SUCCESS;
    bool status = true;

    pal_status = pal_osSemaphoreWait(test_sem, PAL_RTOS_WAIT_FOREVER, NULL);
    TEST_ASSERT_EQUAL_INT(PAL_SUCCESS, pal_status);


    g_mcc->on_certificate_renewal(certificate_renewal_multiple_threads_cb);

    for (i = 0; i < NUMBER_OF_THREADS; i++) {
        strcpy(g_thread_data[i].cert_name, TEST_CERT_NAME);
        g_thread_data[i].cert_name[sizeof(TEST_CERT_NAME) - 1] = ID_TO_LAST_CHAR(i);
        g_thread_data[i].cert_name[sizeof(TEST_CERT_NAME)] = '\0';
        if (i % 2 == 0){
            g_thread_data[i].initiator = CE_INITIATOR_DEVICE;
        } else {
            g_thread_data[i].initiator = CE_INITIATOR_SERVER;
        }
        
        store_certificate_and_private_key(g_thread_data[i].cert_name);
        status = g_thread_data[i].init();
        TEST_ASSERT_EQUAL_INT(true, status);

        // Start thread that tries renewing until successful or error other than device busy
        status = g_thread_data[i].start_thread(thread_renew_cert);
        TEST_ASSERT_EQUAL_INT(true, status);
    }

    // Wait for all threads to complete their work. Last one will signal the test_sem
    pal_status = pal_osSemaphoreWait(test_sem, PAL_RTOS_WAIT_FOREVER, NULL);
    TEST_SKIP_EXECUTION_ON_FAILURE();

    // Make sure all threads have updated successfully
    TEST_ASSERT_EQUAL_INT(NUMBER_OF_THREADS, g_renewal_success_counter);
    TEST_ASSERT_EQUAL_INT(PAL_SUCCESS, pal_status);
}

TEST_GROUP_RUNNER(ce_full_flow)
{
    RUN_TEST_CASE(ce_full_flow, simple_flow);
    RUN_TEST_CASE(ce_full_flow, simple_flow_sync_test_apis);
    RUN_TEST_CASE(ce_full_flow, multiple_thread_renewal);
    RUN_TEST_CASE(ce_full_flow, tlv_has_an_optional_faulty_item);
    RUN_TEST_CASE(ce_full_flow, tlv_has_a_required_faulty_item);
    RUN_TEST_CASE(ce_full_flow, tlv_has_two_optional_items);
    RUN_TEST_CASE(ce_full_flow, tlv_has_two_required_items);
}
