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

#include <string.h>
#include "unity_fixture.h"
#include "sda_status.h"
#include "sda_nonce_mgr.h"
#include "string.h"

TEST_GROUP(NonceMgrSelftest);

TEST_SETUP(NonceMgrSelftest)
{
    fcc_tst_setup(); // Need entropy for nonce generation
    TEST_SKIP_EXECUTION_ON_FAILURE();

    sda_status_e status = sda_nonce_init();
    TEST_ASSERT_EQUAL(SDA_STATUS_SUCCESS, status);
}

TEST_TEAR_DOWN(NonceMgrSelftest)
{
    sda_nonce_fini();
    fcc_tst_tear_down();
    TEST_SKIP_EXECUTION_ON_FAILURE();
}


TEST(NonceMgrSelftest, sanity)
{
    bool success;
    sda_status_e status;
    uint64_t temp_nonce = 0;

    status = sda_nonce_get(&temp_nonce);
    TEST_ASSERT_EQUAL(SDA_STATUS_SUCCESS, status);

    success = sda_nonce_verify_and_delete(temp_nonce);
    TEST_ASSERT_TRUE(success);

    // circ. buffer is empty - should fail
    
    success = sda_nonce_verify_and_delete(temp_nonce);
    TEST_ASSERT_FALSE(success);
}

TEST(NonceMgrSelftest, get_nonce_when_one_entry_left)
{
    int i;
    bool success;
    sda_status_e status;
    uint64_t nonce_backlog[SDA_CYCLIC_BUFFER_MAX_SIZE];

    memset(nonce_backlog, 0, sizeof(nonce_backlog));

    for (i = 0; i < SDA_CYCLIC_BUFFER_MAX_SIZE; i++) {
        status = sda_nonce_get(&nonce_backlog[i]);
        TEST_ASSERT_EQUAL(SDA_STATUS_SUCCESS, status);
    }

    // cause circ. buffer to fetch-and-delete nonce from the middle
    success = sda_nonce_verify_and_delete(nonce_backlog[SDA_CYCLIC_BUFFER_MAX_SIZE / 2]);
    TEST_ASSERT_TRUE(success);

    // get additional nonce - there is only one entry left (in the middle)
    status = sda_nonce_get(&nonce_backlog[SDA_CYCLIC_BUFFER_MAX_SIZE / 2]);
    TEST_ASSERT_EQUAL(SDA_STATUS_SUCCESS, status);

    // verify all nonce values in backlog - should succeed
    for (i = 0; i < SDA_CYCLIC_BUFFER_MAX_SIZE; i++) {
        success = sda_nonce_verify_and_delete(nonce_backlog[i]);
        TEST_ASSERT_TRUE(success);

        success = sda_nonce_verify_and_delete(nonce_backlog[i]);
        TEST_ASSERT_FALSE(success);
    }
}

TEST(NonceMgrSelftest, check_chronologic_get_nonce_order)
{
    int i;
    bool success;
    sda_status_e status;
    uint64_t nonce_backlog[SDA_CYCLIC_BUFFER_MAX_SIZE];
    uint64_t additional_nonce = 0;

    memset(nonce_backlog, 0, sizeof(nonce_backlog));

    for (i = 0; i < SDA_CYCLIC_BUFFER_MAX_SIZE; i++) {
        status = sda_nonce_get(&nonce_backlog[i]);
        TEST_ASSERT_EQUAL(SDA_STATUS_SUCCESS, status);
    }

    // verify nonce_backlog[0] - should succeed
    success = sda_nonce_verify_and_delete(nonce_backlog[0]);
    TEST_ASSERT_TRUE(success);

    // verify nonce_backlog[0] again - should fail
    success = sda_nonce_verify_and_delete(nonce_backlog[0]);
    TEST_ASSERT_FALSE(success);

    // currently the circ. buffer has only slot 0 free
    // requesting additional nonce should take slot 0
    status = sda_nonce_get(&additional_nonce);
    TEST_ASSERT_EQUAL(SDA_STATUS_SUCCESS, status);

    // Make sure it's the same as the prior one...
    TEST_ASSERT_NOT_EQUAL(nonce_backlog[0], additional_nonce);

    // copy to the nonce backlog buffer (so the backlog and the circ. buffer are equal now)
    nonce_backlog[0] = additional_nonce;

    // at this point the oldest nonce in the circ. buffer is g_nonce_array[1]
    // getting additional nonce should drop g_nonce_array[1] and *NOT* g_nonce_array[0]
    status = sda_nonce_get(&additional_nonce);
    TEST_ASSERT_EQUAL(SDA_STATUS_SUCCESS, status);

    // copy to the nonce backlog buffer (so the backlog and the circ. buffer are equal now)
    nonce_backlog[1] = additional_nonce;

    // getting additional nonce (again) should occupy g_nonce_array[2] - because it is the oldest one
    status = sda_nonce_get(&additional_nonce);
    TEST_ASSERT_EQUAL(SDA_STATUS_SUCCESS, status);

    // copy to the nonce backlog buffer (so the backlog and the circ. buffer are equal now)
    nonce_backlog[2] = additional_nonce;

    // verify all nonce values in backlog - should succeed
    for (i = 0; i < SDA_CYCLIC_BUFFER_MAX_SIZE; i++) {
        success = sda_nonce_verify_and_delete(nonce_backlog[i]);
        TEST_ASSERT_TRUE(success);

        success = sda_nonce_verify_and_delete(nonce_backlog[i]);
        TEST_ASSERT_FALSE(success);
    }
}

TEST_GROUP_RUNNER(NonceMgrSelftest)
{
    RUN_TEST_CASE(NonceMgrSelftest, sanity);
    RUN_TEST_CASE(NonceMgrSelftest, get_nonce_when_one_entry_left);
    RUN_TEST_CASE(NonceMgrSelftest, check_chronologic_get_nonce_order);
}
