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

#include "update-client-hub/modules/common/update-client-common/arm_uc_error.h"
#include "update-client-hub/modules/common/update-client-common/arm_uc_types.h"

#include "CppUTestExt/MockSupport.h"
#include "cpputest-custom-types/value_pointer.h"

#define TRACE_GROUP "mClt"

extern "C" {
arm_uc_error_t ARM_UC_mmGetCertificateId(arm_uc_buffer_t *buffer, uint32_t sigIdx, arm_uc_buffer_t *val)
{
    mock().actualCall("ARM_UC_mmGetCertificateId");
    return (arm_uc_error_t){ERR_NONE};
}

arm_uc_error_t ARM_UC_certificateFetch(arm_uc_buffer_t *certificate,
                                       const arm_uc_buffer_t *fingerprint,
                                       const arm_uc_buffer_t *DERCertificateList,
                                       void (*callback)(arm_uc_error_t,
                                                        const arm_uc_buffer_t *,
                                                        const arm_uc_buffer_t *))
{
    mock().actualCall("ARM_UC_certificateFetch");
    return (arm_uc_error_t){ERR_NONE};
}

arm_uc_error_t ARM_UC_mmGetFwSize(arm_uc_buffer_t *buffer, uint32_t *val)
{
    mock().actualCall("ARM_UC_mmGetFwSize");
    return (arm_uc_error_t){ERR_NONE};
}

arm_uc_error_t ARM_UC_mmGetTimestamp(arm_uc_buffer_t *buffer, uint64_t *val)
{
    mock().actualCall("ARM_UC_mmGetTimestamp");
    return (arm_uc_error_t){ERR_NONE};
}

arm_uc_error_t ARM_UC_mmGetFwUri(arm_uc_buffer_t *buffer, arm_uc_buffer_t *val)
{
    mock().actualCall("ARM_UC_mmGetFwUri");
    return (arm_uc_error_t){ERR_NONE};
}

arm_uc_error_t ARM_UC_mmGetFwHash(arm_uc_buffer_t *buffer, arm_uc_buffer_t *val)
{
    mock().actualCall("ARM_UC_mmGetFwHash");
    return (arm_uc_error_t){ERR_NONE};
}

arm_uc_error_t ARM_UC_mmGetVendorGuid(arm_uc_buffer_t *buffer, arm_uc_buffer_t *guid)
{
    mock().actualCall("ARM_UC_mmGetVendorGuid");
    return (arm_uc_error_t) {ERR_NONE};
}
arm_uc_error_t ARM_UC_mmGetClassGuid(arm_uc_buffer_t *buffer, arm_uc_buffer_t *guid)
{
    mock().actualCall("ARM_UC_mmGetVendorGuid");
    return (arm_uc_error_t) {ERR_NONE};
}
}

#endif // MBED_EDGE_SUBDEVICE_FOTA