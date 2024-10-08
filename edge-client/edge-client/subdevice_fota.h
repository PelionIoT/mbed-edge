/*
 * ----------------------------------------------------------------------------
 * Copyright 2021 Pelion Ltd.
 * Copyright 2022-2024 Izuma Networks
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

#ifndef __SUBDEVICE_FOTA_H__
#define __SUBDEVICE_FOTA_H__

#ifdef MBED_EDGE_SUBDEVICE_FOTA

#include "fota/fota_source.h"
#include "fota/fota_source_defs.h"
#include "fota/fota_crypto_defs.h"
#include "fota/fota_crypto.h"
#include "fota/fota_status.h"
#include "fota/fota_internal.h"
#include "fota/fota.h"
#include "fota/fota_manifest.h"
#include "fota/fota_event_handler.h"
#include "fota/fota_component_defs.h"
#include "fota/fota_component_internal.h"
#include "fota/fota_internal.h"
#include "fota/fota_fw_download.h"
#include "mbed-trace/mbed_trace.h"
#include "mbed-client/m2minterfacefactory.h"
#include "mbed-client/m2mresource.h"
#include "edge-client/edge_client_internal.h"
#include "edge-client/edge_manifest_object.h"
#include <stdint.h>
#include <stddef.h>
#include <curl/curl.h>

#define TRACE_GROUP "subdev"
#define ENDPOINT_SIZE 256
#define MANIFEST_URI_SIZE 256
#if !defined(SUBDEVICE_FIRMWARE_DOWNLOAD_LOCATION)
#define SUBDEVICE_FIRMWARE_DOWNLOAD_LOCATION "/tmp"
#endif
int fota_is_ready(uint8_t *data, size_t size, fota_state_e *fota_state);
int fota_manifest_parse(const uint8_t *input_data, size_t input_size, manifest_firmware_info_t *fw_info);
int fota_component_name_to_id(const char *name, unsigned int *comp_id);
void fota_component_get_desc(unsigned int comp_id, const fota_component_desc_t * *comp_desc);
void fota_component_get_curr_version(unsigned int comp_id, fota_component_version_t *version);
void subdevice_fota_on_manifest(uint8_t* data, size_t data_size, M2MResource* resource);
int update_result_resource(char* device_id, uint8_t err_mccp);
int update_state_resource(char* device_id, uint8_t val);
void get_endpoint(char* endpoint,const char* uri_path);
int subdevice_init_buff();
#ifndef MBED_EDGE_UNIT_TEST_BUILD
int copy_buff(manifest_firmware_info_t* buff);
#endif
#ifdef __cplusplus
extern "C" {
    #endif
    int get_component_name(char* c_name);
    void free_subdev_context_buffers(void);
    unsigned int get_component_id();
    void get_version(fota_component_version_t *version);
    void get_vendor_id(uint8_t* v_id);
    void get_class_id(uint8_t* c_id);
    void get_uri(char* c_url);
    int start_download(char* path);
    void subdevice_abort_update(int err, const char* msg = NULL);
    size_t get_manifest_fw_size();
#ifdef __cplusplus
}
#endif
#endif
#endif //__SUBDEVICE_FOTA_H__
