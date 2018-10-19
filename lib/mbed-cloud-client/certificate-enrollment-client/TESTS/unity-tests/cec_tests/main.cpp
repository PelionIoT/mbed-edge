// ----------------------------------------------------------------------------
// Copyright 2018 ARM Ltd.
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


#include <stdlib.h>

#include "mcc_common_setup.h"
#include "pal.h"

#include "unity_fixture.h"
#include "ce_test_runner.h"

#include "mbed-trace/mbed_trace.h"
#include "mbed-trace-helper.h"


#define TRACE_GROUP     "ce"  // Maximum 4 characters

static int g_unity_status = EXIT_FAILURE;

/**
*
* Runs all tests in a task of its own
*/
static void run_ce_component_tests_task()
{
    int rc = 0;
    bool success = 0;
    bool is_mutex_used = false;

    int myargc = 2;
    const char **myargv = (const char **)calloc(myargc, sizeof(char *));
    if (myargv == NULL) {
        goto cleanup;
    }
    myargv[0] = "ce_component_tests";
    myargv[1] = "-v";

    // Wait before start for k64f RaaS devices to prevent reset while working on SD
#ifndef SA_PV_OS_LINUX
    mcc_platform_do_wait(3000);
#endif

    //Initialize mbed-trace
    success = mbed_trace_helper_init(TRACE_ACTIVE_LEVEL_ALL, is_mutex_used);
    if (success != true) {
        goto cleanup;
    }


    mcc_platform_sw_build_info();

    // Initialize storage
    success = mcc_platform_storage_init() == 0;
    if (success != true) {
        goto cleanup;
    }

    //DO NOT INIITALIZE PAL HERE

    setvbuf(stdout, (char *)NULL, _IONBF, 0); /* Avoid buffering on test output */
    tr_info("ce_component_tests: Starting component tests...\n");
    

    tr_cmdline("----< Test - Start >----\n");
    rc = UnityMain(myargc, myargv, RunAllCertificateEnrollmentTests);
    tr_cmdline("----< Test - End >----\n");

    if (rc > 0) {
        tr_error("ce_component_tests: Test failed.\n");
    } else {
        g_unity_status = EXIT_SUCCESS;
        tr_info("ce_component_tests: Test passed.\n");
    }

cleanup:
    // This is detected by test runner app, so that it can know when to terminate without waiting for timeout.
    tr_cmdline("***END OF TESTS**\n");
    tr_cmdline("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    tr_cmdline("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    tr_cmdline("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

    mbed_trace_helper_finish();
    free(myargv);
    fflush(stdout);
}

int main(int argc, char * argv[])
{
    bool success = false;

    // Do not use argc/argv as those are not initialized
    // for armcc and may cause allocation failure.
    (void)argc;
    (void)argv;

    success = (mcc_platform_init() == 0);
    if (success) {
        success = mcc_platform_run_program(&run_ce_component_tests_task);
    }

    return success ? g_unity_status : EXIT_FAILURE;
}
