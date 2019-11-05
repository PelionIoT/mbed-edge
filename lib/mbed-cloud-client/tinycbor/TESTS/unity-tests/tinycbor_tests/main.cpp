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

#include <stdlib.h>
#include <stdio.h>
#include "unity_fixture.h"
#include "tiny_cbor_test_runner.h"
#include "mcc_common_setup.h"

static int g_unity_status = EXIT_FAILURE;


int main(int argc, const char * argv[])
{    
    int rc = 0;
    const char **myargv = (const char **)calloc(2, sizeof(char *));
    if (myargv == NULL) {
        goto cleanup;
    }
    setvbuf(stdout, (char *)NULL, _IONBF, 0); /* Avoid buffering on test output */
    printf("tiny_cbor_component_tests: Starting component tests...\n");

    myargv[0] = "tinycbor_tests";
    myargv[1] = "-v";
    
    printf("----< Test - Start >----\n");

    rc = UnityMain(2, myargv, RunAllTinyCborTests);
    printf("----< Test - End >----\n");


    if (rc > 0) {
        printf("tiny_cbor_component_tests: Test failed.\n");
    }
    else {
        g_unity_status = EXIT_SUCCESS;
        printf("tiny_cbor_component_tests: Test passed.\n");
    }

cleanup:
    // This is detected by test runner app, so that it can know when to terminate without waiting for timeout.
    printf("***END OF TESTS**\n");
    printf("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    printf("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    printf("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
    free(myargv);
    fflush(stdout);
    return rc;
}
