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


#include "general_tests_runner.h"
#include "unity_fixture.h"

void RunAllGeneralTests(void)
{
    RUN_TEST_GROUP(UnitySelftest);
    RUN_TEST_GROUP(cwt_handler_test);
    RUN_TEST_GROUP(sda_test);
    RUN_TEST_GROUP(audience_test);
    RUN_TEST_GROUP(NonceMgrSelftest);
    RUN_TEST_GROUP(data_token_test);
    RUN_TEST_GROUP(function_parameters);
    RUN_TEST_GROUP(trust_anchor_test);
    RUN_TEST_GROUP(sda_cbor_test);
}
