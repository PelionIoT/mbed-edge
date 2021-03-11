// ----------------------------------------------------------------------------
// Copyright 2020 ARM Ltd.
//
// SPDX-License-Identifier: Apache-2.0
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

#include "fota/fota_base.h"

#ifdef MBED_CLOUD_CLIENT_FOTA_ENABLE

#define TRACE_GROUP "FOTA"

#include "fota/fota_app_ifs.h"    // required for implementing custom install callback for Linux like targets
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#define ACTIVATE_SCRIPT_LENGTH 512

int fota_app_on_install_candidate(const char *candidate_fs_name, const manifest_firmware_info_t *firmware_info)
{
    int ret = FOTA_STATUS_SUCCESS;
    int rc;
    char command[ACTIVATE_SCRIPT_LENGTH] = {0};

    int length = snprintf(command,
                          ACTIVATE_SCRIPT_LENGTH,
                          "%s %s %s",
                          "/opt/pelion/fota_update_activate.sh",  candidate_fs_name, MBED_CLOUD_CLIENT_FOTA_LINUX_HEADER_FILENAME);
    FOTA_ASSERT(length < ACTIVATE_SCRIPT_LENGTH);

    FOTA_TRACE_INFO( "shell command from fota install calback %s", command );

    /* execute script command */
    rc = system(command);
    if( rc ) {
        ret = FOTA_STATUS_FW_INSTALLATION_FAILED;
        if( rc == -1 ) {
         FOTA_TRACE_ERROR( "shell could not be run" );
        } else {
            FOTA_TRACE_ERROR( "result of running command is %d", WEXITSTATUS(rc) );
        }
    }
    return ret;
}

#endif // MBED_CLOUD_CLIENT_FOTA_ENABLE