/*
 * ----------------------------------------------------------------------------
 * Copyright 2020 ARM Ltd.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ----------------------------------------------------------------------------
 */

#ifdef MBED_EDGE_SUBDEVICE_FOTA

#ifndef PT_FIRMWARE_DOWNLOAD_API_INTERNAL_H
#define PT_FIRMWARE_DOWNLOAD_API_INTERNAL_H

#include "pt-client-2/pt_common_api_internal.h"
#include "arm_uc_public.h"

typedef struct pt_manifest_context_s {
    char url[256];
    char hash[65];
    char device_id[256];
    char version[11];
    uint32_t size;
    void *userdata;
} pt_manifest_context_t;

typedef void (*pt_download_cb)(connection_id_t connection_id, const char *filename, int error_code, void *userdata);

typedef pt_status_t (*manifest_download_handler)(const connection_id_t connection_id,
                                                 const char *device_id,
                                                 const uint16_t object_id,
                                                 const uint16_t instance_id,
                                                 const uint16_t resource_id,
                                                 const uint8_t operation,
                                                 const uint8_t *value,
                                                 const uint32_t value_size,
                                                 void *userdata);

pt_status_t pt_device_update_firmware_update_resources(connection_id_t connection_id,
                                                       const char *device_id,
                                                       char *asset_hash,
                                                       char *asset_version);

pt_status_t pt_device_init_firmware_update_resources(connection_id_t connection_id,
                                                     const char *device_id,
                                                     manifest_download_handler manifest_handler);

void pt_manifest_context_free(pt_manifest_context_t *ctx);

pt_status_t pt_download_asset_internal(const connection_id_t connection_id,
                                       const char *device_id,
                                       const char *url,
                                       const char *hash,
                                       uint32_t size,
                                       pt_download_cb success_handler,
                                       pt_download_cb failure_handler,
                                       void *userdata);

pt_status_t pt_parse_manifest(const uint8_t *manifest_payload,
                              const uint32_t manifest_payload_size,
                              pt_manifest_context_t *manifest_context,
                              arm_uc_update_result_t *error_manifest);

#endif // PT_FIRMWARE_DOWNLOAD_API_INTERNAL_H

#endif // MBED_EDGE_SUBDEVICE_FOTA
