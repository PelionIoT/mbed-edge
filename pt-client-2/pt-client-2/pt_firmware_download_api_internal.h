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

#define COMPONENT 14
#define COMPONENT_INSTANCE 0
#define COMPONENT_NAME 0
#define COMPONENT_VERSION 2

#define COMPONENT_NAME_STR "MAIN"
#define VERSION_NAME_STR "0.0.0"
#define MANIFEST_VENDOR_STR "SUBDEVICE-VENDOR"
#define MANIFEST_VENDOR_STR_SIZE strlen(MANIFEST_VENDOR_STR)
#define MANIFEST_CLASS_STR "SUBDEVICE--CLASS"
#define MANIFEST_CLASS_STR_SIZE strlen(MANIFEST_CLASS_STR)

typedef struct pt_manifest_context_s {
    char device_id[256];
    char version[12];
    uint64_t size;
    void *userdata;
} pt_manifest_context_t;

typedef void (*pt_download_cb)(connection_id_t connection_id, const char *filename, int error_code, void *userdata);

typedef pt_status_t (*manifest_metadata_handler)(const connection_id_t connection_id,
                                                 const char *device_id,
                                                 const uint8_t operation,
                                                 const uint8_t *class_id,
                                                 const uint32_t class_size,
                                                 const uint8_t *vendor_id,
                                                 const uint32_t vendor_size,
                                                 const char* version,
                                                 uint32_t size,
                                                 void *userdata);

pt_status_t pt_device_update_firmware_update_resources(connection_id_t connection_id,
                                                       const char *device_id,
                                                       char* asset_version);

pt_status_t pt_device_init_firmware_update_resources(connection_id_t connection_id,
                                                     const char *device_id,
                                                     manifest_metadata_handler manifest_meta_data_handler);

void pt_manifest_context_free(pt_manifest_context_t *ctx);

pt_status_t pt_download_asset_internal(const connection_id_t connection_id,
                                       const char *device_id,
                                       uint64_t size,
                                       pt_download_cb success_handler,
                                       pt_download_cb failure_handler,
                                       void *userdata);
#endif // PT_FIRMWARE_DOWNLOAD_API_INTERNAL_H

#endif // MBED_EDGE_SUBDEVICE_FOTA
