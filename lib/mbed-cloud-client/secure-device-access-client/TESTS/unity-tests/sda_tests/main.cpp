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


// Note: this macro is needed on armcc to get the the PRI*32 macros
// from inttypes.h in a C++ code.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <stdlib.h>

#include "pal.h"
#include "mcc_common_setup.h"
#include "sotp.h"

#include "unity_fixture.h"
#include "sda_log.h"
#include "sda_component_tests_runner.h"
#include "sda_malloc.h"

#include "mbed-trace/mbed_trace.h"
#include "mbed-trace-helper.h"

#include "sda_testdata.h"
#include "esfs.h"

#include "factory_configurator_client.h"
#include "pv_error_handling.h"



#define TRACE_GROUP     "sda"  // Maximum 4 characters


static int g_unity_status = EXIT_FAILURE;

static bool storage_delete(void)
{
    fcc_status_e status;

    status = fcc_init();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((status != FCC_STATUS_SUCCESS), false, "Failed initializing FCC (status %u)", status);

    status = fcc_storage_delete();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((status != FCC_STATUS_SUCCESS), false, "Failed clearing storage (status %u)", status);

    status = fcc_finalize();
    SA_PV_ERR_RECOVERABLE_RETURN_IF((status != FCC_STATUS_SUCCESS), false, "Failed finalizing FCC (status %u)", status);

    return true;
}


/**
*
* Runs all tests in a task of its own
*/
static void run_component_tests_task()
{
    int rc = 0;
    bool success = 0;
    palStatus_t pal_status;

    int myargc = 2;
    const char **myargv = (const char **)calloc(myargc, sizeof(char *));
    if (myargv == NULL) {
        goto cleanup;
    }
    myargv[0] = "sda_component_tests";
    myargv[1] = "-v";

    // Wait before start for k64f RaaS devices to prevent reset while working on SD
#ifndef SDA_OS_LINUX
    mcc_platform_do_wait(3000);
#endif


    mcc_platform_sw_build_info();

    // Initialize storage
    success = mcc_platform_storage_init() == 0;
    if (success != true) {
        goto cleanup;
    }

    // This will clear SD/Flash store and internal storage before launching our test cases.
    // It is specifically essential when switching OS's and binary images
    success = storage_delete();
    assert(success);

    // Initialize PAL
    pal_status = pal_init();
    if (pal_status != PAL_SUCCESS) {
        tr_error("Error initializing pal");
        goto cleanup;
    }
  
    pal_status = pal_osSetTime(g_current_time);
    if (pal_status != PAL_SUCCESS) {
        tr_error("Error initializing pal");
        goto cleanup;
    }

    setvbuf(stdout, (char *)NULL, _IONBF, 0); /* Avoid buffering on test output */
    tr_cmdline("component_tests: Starting component tests...");
    tr_cmdline("----< Test - Start >----");
    rc = UnityMain(myargc, myargv, RunAllComponentTests);
    tr_cmdline("----< Test - End >----");

    sda_display_mem_usage_results();

    if (rc > 0) {
        tr_cmdline("component_tests: Test failed.");
    } else {
        g_unity_status = EXIT_SUCCESS;
        tr_cmdline("component_tests: Test passed.");
    }

cleanup:
    // This is detected by test runner app, so that it can know when to terminate without waiting for timeout.
    tr_cmdline("***END OF TESTS**");
    tr_cmdline("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    tr_cmdline("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    tr_cmdline("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

    mbed_trace_helper_finish();
    pal_destroy();
    free(myargv);
    fflush(stdout);
}

int main(int argc, char * argv[])
{
    bool success;

    // Do not use argc/argv as those are not initialized
    // for armcc and may cause allocation failure.
    (void)argc;
    (void)argv;

    // careful, mbed-trace initialization may happen at this point if and only if we 
    // do NOT use mutex by passing "true" at the second param for this functions.
    // In case mutex is used, this function MUST be moved *after* pal_init()
    success = mbed_trace_helper_init(TRACE_ACTIVE_LEVEL_ALL | TRACE_MODE_COLOR, false);
    if (!success) {
        // Nothing much can be done here, trace module should be initialized before file system
        // and if failed - no tr_* print is eligible.
        return EXIT_FAILURE;
    }

    success = (mcc_platform_init() == 0);
    if (success) {
        success = mcc_platform_run_program(&run_component_tests_task);
    }
    return success ? g_unity_status : EXIT_FAILURE;
}
