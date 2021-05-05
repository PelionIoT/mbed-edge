/*
 * Copyright (c) 2020 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef MBED_EDGE_SUBDEVICE_FOTA

#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include "mbed-cloud-client/MbedCloudClientConfig.h"
#include "mbed-cloud-client/MbedCloudClient.h"
#include "mbed-cloud-client/SimpleM2MResource.h"

#include "update-client-hub/modules/common/update-client-common/arm_uc_error.h"
#include "update-client-hub/modules/common/update-client-common/arm_uc_types.h"

#include "CppUTestExt/MockSupport.h"
#include "cpputest-custom-types/value_pointer.h"


M2MInterface *MbedCloudClient::get_m2m_interface()
{
    return NULL;
}

#endif // MBED_EDGE_SUBDEVICE_FOTA