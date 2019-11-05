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

/* "Selftest" for the Unity infrastructure for TEE */
#include "stdbool.h"
#include "unity_fixture.h"
#include "sda_log.h"

TEST_GROUP(UnitySelftest);

TEST_SETUP(UnitySelftest)
{
    /* INTERNAL UNITY CODE - Do NOT use these functions for the test code */
    UnityPrint("At UnitySelftest::setup");
    UNITY_OUTPUT_CHAR('\n');
}

TEST_TEAR_DOWN(UnitySelftest)
{
    /* INTERNAL UNITY CODE - Do NOT use these functions for the test code */
    UnityPrint("At UnitySelftest::teardown");
    UNITY_OUTPUT_CHAR('\n');
}

TEST(UnitySelftest, UnityBasicAsserts)
{
    int a = 7;
    const char *bar = "This is Bar";
    unsigned int myArray1[3] = { 1, 5, 9 };
    unsigned int myArray2[3] = { 1, 5, 9 };

    SDA_LOG_INFO("UnitySelftest::UnityBasicAsserts");
    TEST_ASSERT_TRUE(1);
    TEST_ASSERT_FALSE(0);
    TEST_ASSERT_TRUE(true);
    TEST_ASSERT_FALSE(false);
    TEST_ASSERT(a == 7);
    TEST_ASSERT_UNLESS(a != 7);
    TEST_ASSERT_EQUAL_INT(7, a);
    TEST_ASSERT_INT_WITHIN(5, 10, a);
    TEST_ASSERT_EQUAL_STRING("This is Bar", bar);
    TEST_ASSERT_EQUAL_UINT_ARRAY(myArray1, myArray2, sizeof(myArray1) / sizeof(unsigned int));
    SDA_LOG_INFO("Completed UnitySelftest::UnityBasicAsserts");
}

TEST_GROUP_RUNNER(UnitySelftest)
{
    RUN_TEST_CASE(UnitySelftest, UnityBasicAsserts);
}
