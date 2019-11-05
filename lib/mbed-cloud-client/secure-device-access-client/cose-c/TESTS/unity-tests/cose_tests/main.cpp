//----------------------------------------------------------------------------
//   The confidential and proprietary information contained in this file may
//   only be used by a person authorised under and to the extent permitted
//   by a subsisting licensing agreement from ARM Limited or its affiliates.
//
//          (C) COPYRIGHT 2017-2018 ARM Limited or its affiliates.
//              ALL RIGHTS RESERVED
//
//   This entire notice must be reproduced on all copies of this file
//   and copies of this file may only be made by a person if such person is
//   permitted to do so under the terms of a subsisting license agreement
//   from ARM Limited or its affiliates.
//----------------------------------------------------------------------------

#include <stdlib.h>

#include "mcc_common_setup.h"
#include "pal.h"

#include "unity_fixture.h"
#include "cose_test_runner.h"

#include "mbed-trace/mbed_trace.h"
#include "mbed-trace-helper.h"
#include "cn-cbor.h"

#define TRACE_GROUP     "cose"  // Maximum 4 characters

static int g_unity_status = EXIT_FAILURE;

/**
*
* Runs all tests in a task of its own
*/
static void run_cose_component_tests_task()
{
    int rc = 0;
    bool success = 0;

    bool is_mutex_used = false;
#ifdef USE_CBOR_CONTEXT
    cn_cbor_context *cbor_ctx;
#endif

    int myargc = 2;
    const char **myargv = (const char **)calloc(myargc, sizeof(char *));
    if (myargv == NULL) {
        goto cleanup;
    }
    myargv[0] = "cose_component_tests";
    myargv[1] = "-v";

    //Initialize mbed-trace
    success = mbed_trace_helper_init(TRACE_ACTIVE_LEVEL_ALL, is_mutex_used);
    if (success != true) {
        goto cleanup;
    }

#ifndef SDA_OS_LINUX
    mcc_platform_do_wait(3000);
#endif

    mcc_platform_sw_build_info();

    setvbuf(stdout, (char *)NULL, _IONBF, 0); /* Avoid buffering on test output */
    tr_info("cose_component_tests: Starting component tests...\n");
    
#ifdef USE_CBOR_CONTEXT
    cbor_ctx = cn_cbor_init_context(40);
    if (cbor_ctx == NULL) {
        goto cleanup;
    }
#endif

    tr_cmdline("----< Test - Start >----\n");
    rc = UnityMain(myargc, myargv, RunAllCoseTests);
    tr_cmdline("----< Test - End >----\n");

#if defined(USE_CBOR_CONTEXT)
    cn_cbor_context_print_stats();
    cn_cbor_free_context(cbor_ctx);
#endif

    if (rc > 0) {
        tr_error("cose_component_tests: Test failed.\n");
    } else {
        g_unity_status = EXIT_SUCCESS;
        tr_info("cose_component_tests: Test passed.\n");
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
    bool success = 0;

    // Do not use argc/argv as those are not initialized
    // for armcc and may cause allocation failure.
    (void)argc;
    (void)argv;

    success = (mcc_platform_init() == 0);
    if (success) {
        success = mcc_platform_run_program(&run_cose_component_tests_task);
    }

    return success ? g_unity_status : EXIT_FAILURE;
}
