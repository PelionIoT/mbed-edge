/* SPDX-License-Identifier: Apache-2.0
 * Native rollback fixture: accepts --version but fails under real SCM.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "edge_service.h"
bool edge_core_request_stop(void) { return true; }
int edge_core_run(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--version")) {
        puts("Windows updater failure fixture");
        return 0;
    }
    return 42;
}
