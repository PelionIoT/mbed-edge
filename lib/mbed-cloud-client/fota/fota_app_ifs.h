// ----------------------------------------------------------------------------
// Copyright 2018-2020 ARM Ltd.
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

#ifndef __FOTA_APP_IFS_H_
#define __FOTA_APP_IFS_H_

#include "fota/fota_config.h"

#if defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#include "fota/fota_status.h"
#include "fota/fota_header_info.h"
#include "fota/fota_manifest.h"
#include "fota/fota_component.h"

#ifdef __cplusplus
extern "C" {
#endif

// TODO: remove this enum definition
typedef enum {
    FOTA_APP_AUTHORIZATION_TYPE_DOWNLOAD,  /**< Request authorization for downloading update payload. */
    FOTA_APP_AUTHORIZATION_TYPE_INSTALL,   /**< Request authorization for installing update. */
} fota_app_request_type_e;

/**
 * FOTA download authorization callback to be implemented by an application.
 *
 * Application authorization is required by FOTA client to start downloading the update.
 *
 * The callback implementation is expected to call one of the APIs listed below:
 *   - fota_app_authorize() - authorize FOTA request.
 *   - fota_app_reject() - reject FOTA request and discard the update. The update will not be reprompted.
 *   - fota_app_defer() - defer the update to a later phase. This will abort current update attempt, while preserving update manifest.
 *      Update will be restarted on next boot. Alternatively update can be restarted by calling fota_app_resume().
 *
 * \note only required if MBED_CLOUD_CLIENT_FOTA_ENABLE build flag is specified
 * \note the FW versions in this callback are in internal library format and should be converted to string using fota_component_version_int_to_semver() before use.
 * \param[in] token (unused)
 * \param[in] candidate_info update candidate descriptor
 * \param[in] curr_fw_version current component FW version
 * \return FOTA_STATUS_SUCCESS for acknowledgment that authorization callback was received properly by the application.
 */
int fota_app_on_download_authorization(
    uint32_t token,
    const manifest_firmware_info_t *candidate_info,
    fota_component_version_t curr_fw_version
);


/**
 * FOTA install authorization callback to be implemented by an application.
 *
 * Application authorization is required by FOTA client to apply the update.
 * The implementation expected to call one of the APIs listed below:
 *   - fota_app_authorize() - authorize FOTA install the update candidate - reboot or connectivity lost may occur during candidate installation operation.
 *                            This phase considered as a critical section - powerloss can potentially brick the device.
 *   - fota_app_reject() - reject FOTA request and discard the update.  The update will not be reprompted.
 *   - fota_app_defer() - defer the install to a later later phase. This will mark the candidate as valid but will not perform reboot
 *
 * \note only required if MBED_CLOUD_CLIENT_FOTA_ENABLE build flag is specified
 * \note after deferring the installation by fota_app_defer() call - fota_app_resume() call will have no effect - reboot is required for installing the candidate.
 *
 * \param[in] token (unused)
 * \return FOTA_STATUS_SUCCESS for acknowledgment that authorization callback was received properly by the application.
 */
int fota_app_on_install_authorization(uint32_t token);

/**
 * Pelion FOTA complete callback to be implemented by an application.
 *
 * Pelion FOTA client notifies the application that update process is done/terminated.
 * Update result can be determined based in status argument.
 *
 * \param[in] status pelion FOTA status code. FOTA_STATUS_SUCCESS in case update deployed successfully.
 * \return FOTA_STATUS_SUCCESS for acknowledgment that authorization callback was received properly by the application.
 */
int fota_app_on_complete(int32_t status);

/**
 * Resume Pelion FOTA update.
 *
 * In case update process was interupted - application can restart it by calling this function.
  */
void fota_app_resume(void);

/**
 * Authorize Pelion FOTA client to proceed with an update
 *
 * This API expected to be called from fota_app_on_authorization_request() application callback.
 *
 * \param[in] token request token as received in fota_app_on_authorization_request().
 * \note unexpected token considered as unrecoverable programming error and will cause panic.
 *
 *  \deprecated Use the fota_app_authorize_update
 */
void fota_app_authorize(uint32_t token) fota_deprecated;

/**
 * Reject Pelion FOTA update
 *
 * This API expected to be called from fota_app_on_authorization_request() application callback.
 *
 * \param[in] token  request token as received in fota_app_on_authorization_request().
 * \param[in] reason reject reason code.
 * \note unexpected token considered as unrecoverable programming error and will cause panic.
 *
 *  \deprecated Use the fota_app_reject_update
 *
 */
void fota_app_reject(uint32_t token, int32_t reason) fota_deprecated;

/**
 * Defer Pelion FOTA update
 *
 * FOTA client resources will be released and update will be reattempted on next boot or by
 * calling fota_app_resume() API.
 * This API expected to be called from fota_app_on_authorization_request() application callback.
 *
 * \param[in] token request token as received in fota_app_on_authorization_request().
 * \note unexpected token considered as unrecoverable programming error and will cause panic.
 *
 *  \deprecated Use the fota_app_defer_update
 */
void fota_app_defer(uint32_t token) fota_deprecated;


/**
 * Authorize Pelion FOTA client to proceed with an update.
 *
 * This API expected to be called from fota_app_on_authorization_request() application callback.
 *
 * \param[in] token request token as received in fota_app_on_authorization_request().
 * \note unexpected token considered as unrecoverable programming error and will cause panic.
 */
void fota_app_authorize_update(void);

/**
 * Reject Pelion FOTA update.
 *
 * This API expected to be called from fota_app_on_authorization_request() application callback.
 *
 * \param[in] reason reject reason code.
 */
void fota_app_reject_update(int32_t reason);

/**
 * Defer Pelion FOTA update.
 *
 * FOTA client resources will be released and update will be reattempted on next boot or by
 * calling fota_app_resume() API.
 * This API expected to be called from fota_app_on_authorization_request() application callback.
 */
void fota_app_defer_update(void);


/**
 * Progress bar support for Pelion FOTA update.
 *
 * This API expected to be implemented by application.(Optional)
 * It called approximately on every 5 percent download progress.
 *
 * \param[in] already downloaded image size in bytes
 * \param[in] current downloaded chunk size in bytes
 * \param[in] total image size in bytes
 */
void fota_app_on_download_progress(size_t downloaded_size, size_t current_chunk_size, size_t total_size);


#if defined(TARGET_LIKE_LINUX)

/**
 * Pelion FOTA install callback to be implemented by application.
 *
 * The callback is expected to install the candidate and return FOTA_STATUS_SUCCESS or reboot the system.
 *
 * \param[in] candidate_fs_name candidate file name
 * \param[in] firmware_info parsed update manifest
 *
 * \return FOTA_STATUS_SUCCESS for successful installation or error code.
 */

int fota_app_on_install_candidate(const char *candidate_fs_name, const manifest_firmware_info_t *firmware_info);

#endif // defined(TARGET_LIKE_LINUX)

#ifdef __cplusplus
}
#endif

#endif  // defined(MBED_CLOUD_CLIENT_FOTA_ENABLE)

#endif // __FOTA_APP_IFS_H_
