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

#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "pt-client-2/pt_firmware_download_api_internal.h"
#include "pt-client-2/pt_api_internal.h"
#include "pt-client-2/pt_api.h"
#include "edge-rpc/rpc.h"
#include "mbed-trace/mbed_trace.h"

#include "update-client-common/arm_uc_error.h"
#include "arm_uc_mmDerManifestAccessors.h"

#define TRACE_GROUP "ptfota"

#define MANIFEST_OBJECT 10252
#define DEVICE_META_OBJECT 10255

#define MANIFEST_INSTANCE                   0
#define MANIFEST_RESOURCE_PAYLOAD           1
#define MANIFEST_RESOURCE_STATE             2
#define MANIFEST_RESOURCE_RESULT            3
#define MANIFEST_RESOURCE_HASH              5
#define MANIFEST_RESOURCE_VERSION           6
#define MANIFEST_RESOURCE_PROTOCOL          0
#define MANIFEST_RESOURCE_BOOT_HASH         1
#define MANIFEST_RESOURCE_OEMBOOT_HASH      2
#define MANIFEST_RESOURCE_VENDOR            3
#define MANIFEST_RESOURCE_CLASS             4
#define MANIFEST_DEFAULT_PROTOCOL           3
#define MANIFEST_PROTOCOL_V2                4
#define MANIFEST_DEFAULT_INT                "-1"
#define MANIFEST_DEFAULT_INT_SIZE strlen(MANIFEST_DEFAULT_INT)
#define MANIFEST_DEFAULT_STR                "INVALID"
#define MANIFEST_DEFAULT_STR_SIZE strlen(MANIFEST_DEFAULT_STR)

void reverse(char s[], uint32_t length)
{
    uint32_t i, j;
    char c;
    for (i = 0, j = length-1; i<j; i++, j--) {
        c = s[i];
        s[i] = s[j];
        s[j] = c;
    }
}
uint32_t itoa_c (int64_t n, char s[])
{
    int64_t sign;
    uint32_t i;
    if ((sign = n) < 0)
        n = -n;
    i = 0;
    do {
        s[i++] = n % 10 + '0';
    }
    while ((n /= 10) > 0);
    if (sign < 0)
        s[i++] = '-';
    s[i] = '\0';
    reverse(s, i);
    return i;
}
pt_status_t pt_device_update_firmware_update_resources(connection_id_t connection_id,
                                                       const char *device_id,
                                                       char* fw_version)
{
    // Check if device exists
    if (device_id == NULL) {
        return PT_STATUS_INVALID_PARAMETERS;
    }

    pt_status_t status = PT_STATUS_SUCCESS;

    char* version = (char*)calloc(12,sizeof(char));
    memcpy(version, fw_version, strlen(fw_version));

    tr_info("New firmware Version: %s", version);
    status = pt_device_set_resource_value(connection_id,
                                          device_id,
                                          COMPONENT,
                                          COMPONENT_INSTANCE,
                                          COMPONENT_VERSION,
                                          version,
                                          strlen(version),
                                          free);
    if (status != PT_STATUS_SUCCESS) {
        tr_err("Could not create firmware update resource %d! Error was %d", COMPONENT_VERSION, status);
        return status;
    }

    return PT_STATUS_SUCCESS;
}

pt_status_t pt_device_init_firmware_update_resources(connection_id_t connection_id,
                                                     const char *device_id,
                                                     manifest_metadata_handler manifest_meta_data_handler)
{
    // Check if device exists
    if (device_id == NULL || pt_device_exists(connection_id, device_id) == false) {
        return PT_STATUS_INVALID_PARAMETERS;
    }

    // Check if device flags exist
    uint32_t flags = 0;
    pt_status_t status = pt_device_get_feature_flags(connection_id, device_id, &flags);
    if (status != PT_STATUS_SUCCESS) {
        return status;
    }

    // Check if device flags match firmware update
    if ((flags & PT_DEVICE_FEATURE_FIRMWARE_UPDATE) == 0) {
        tr_err("Trying to create certificate renewal resources but the feature is disabled.");
        return PT_STATUS_INVALID_PARAMETERS;
    }

    // Check if object already exists
    if (pt_device_resource_exists(connection_id, device_id, MANIFEST_OBJECT, MANIFEST_INSTANCE, MANIFEST_RESOURCE_PAYLOAD)) {
        tr_err("Firmware Update resources already exist!");
        return PT_STATUS_INVALID_PARAMETERS;
    }

    // Verify that the manifest_meta_data_handler callback is set
    if (manifest_meta_data_handler == NULL) {
        tr_warn("Manifest handler not set for device id:%s",device_id);
        status = pt_device_add_resource_with_callback(connection_id,
                                                  device_id,
                                                  MANIFEST_OBJECT,
                                                  MANIFEST_INSTANCE,
                                                  MANIFEST_RESOURCE_PAYLOAD,
                                                  /* resource name */ NULL,
                                                  LWM2M_STRING,
                                                  OPERATION_EXECUTE,
                                                  NULL,
                                                  0,
                                                  NULL,
                                                  NULL);
    }
    else {
        status = pt_device_add_resource_with_callback(connection_id,
                                                device_id,
                                                MANIFEST_OBJECT,
                                                MANIFEST_INSTANCE,
                                                MANIFEST_RESOURCE_PAYLOAD,
                                                /* resource name */ NULL,
                                                LWM2M_STRING,
                                                OPERATION_EXECUTE,
                                                NULL,
                                                0,
                                                NULL,
                                                manifest_meta_data_handler);
    }
    if (status != PT_STATUS_SUCCESS) {
        tr_err("Could not create firmware update resource %d! Error was %d", MANIFEST_RESOURCE_PAYLOAD, status);
        return status;
    }

    char *component_name = calloc(12, sizeof(char));
    memcpy(component_name, COMPONENT_NAME_STR, strlen(COMPONENT_NAME_STR));
    status = pt_device_add_resource(connection_id,
                                    device_id,
                                    COMPONENT,
                                    COMPONENT_INSTANCE,
                                    COMPONENT_NAME,
                                    NULL,
                                    LWM2M_STRING,
                                    component_name,
                                    strlen(component_name),
                                    free);
    component_name = NULL;
    char* component_version = calloc(12, sizeof(char));
    memcpy(component_version, VERSION_NAME_STR, strlen(VERSION_NAME_STR));
    status = pt_device_add_resource(connection_id,
                                    device_id,
                                    COMPONENT,
                                    COMPONENT_INSTANCE,
                                    COMPONENT_VERSION,
                                    NULL,
                                    LWM2M_STRING,
                                    component_version,
                                    strlen(component_version),
                                    free);
    component_version = NULL;
    uint8_t *status_version = (uint8_t*)malloc(sizeof(uint8_t));
    *status_version = -1;
    status = pt_device_add_resource(connection_id,
                                    device_id,
                                    MANIFEST_OBJECT,
                                    MANIFEST_INSTANCE,
                                    MANIFEST_RESOURCE_STATE,
                                    /* resource name */ NULL,
                                    LWM2M_INTEGER,
                                    status_version,
                                    1,
                                    free);
    if (status != PT_STATUS_SUCCESS) {
        tr_err("Could not create manifest state resource %d! Error was %d", MANIFEST_RESOURCE_STATE, status);
        return status;
    }
    uint8_t *manifest_status = (uint8_t*)malloc(sizeof(uint8_t));
    *manifest_status = -1;
    status = pt_device_add_resource(connection_id,
                                    device_id,
                                    MANIFEST_OBJECT,
                                    MANIFEST_INSTANCE,
                                    MANIFEST_RESOURCE_RESULT,
                                    /* resource name */ NULL,
                                    LWM2M_INTEGER,
                                    manifest_status,
                                    1,
                                    free);
    if (status != PT_STATUS_SUCCESS) {
        tr_err("Could not create manifest result resource %d! Error was %d", MANIFEST_RESOURCE_RESULT, status);
        return status;
    }
    uint8_t *protocol_version = (uint8_t*)malloc(sizeof(uint8_t));
    *protocol_version = MANIFEST_PROTOCOL_V2;
    status = pt_device_add_resource(connection_id,
                                    device_id,
                                    DEVICE_META_OBJECT,
                                    MANIFEST_INSTANCE,
                                    MANIFEST_RESOURCE_PROTOCOL,
                                    /* resource name */ NULL,
                                    LWM2M_INTEGER,
                                    protocol_version,
                                    1,
                                    free);
    if (status != PT_STATUS_SUCCESS) {
        tr_err("Could not create firmware update resource %d! Error was %d", MANIFEST_RESOURCE_PROTOCOL, status);
        return status;
    }

    uint8_t *boot_hash = (uint8_t*)malloc( (MANIFEST_DEFAULT_STR_SIZE + 1) * sizeof(uint8_t) );
    memcpy(boot_hash, MANIFEST_DEFAULT_STR, MANIFEST_DEFAULT_STR_SIZE);
    boot_hash[MANIFEST_DEFAULT_STR_SIZE] = 0;
    status = pt_device_add_resource(connection_id,
                                    device_id,
                                    DEVICE_META_OBJECT,
                                    MANIFEST_INSTANCE,
                                    MANIFEST_RESOURCE_BOOT_HASH,
                                    /* resource name */ NULL,
                                    LWM2M_STRING,
                                    boot_hash,
                                    strlen(boot_hash),
                                    free);
    if (status != PT_STATUS_SUCCESS) {
        tr_err("Could not create firmware update resource %d! Error was %d", MANIFEST_RESOURCE_BOOT_HASH, status);
        return status;
    }

    uint8_t *oem_boot_hash = (uint8_t*)malloc( (MANIFEST_DEFAULT_STR_SIZE + 1) * sizeof(uint8_t) );
    memcpy(oem_boot_hash, MANIFEST_DEFAULT_STR, MANIFEST_DEFAULT_STR_SIZE);
    oem_boot_hash[MANIFEST_DEFAULT_STR_SIZE] = 0;
    status = pt_device_add_resource(connection_id,
                                    device_id,
                                    DEVICE_META_OBJECT,
                                    MANIFEST_INSTANCE,
                                    MANIFEST_RESOURCE_OEMBOOT_HASH,
                                    /* resource name */ NULL,
                                    LWM2M_STRING,
                                    oem_boot_hash,
                                    strlen(oem_boot_hash),
                                    free);
    if (status != PT_STATUS_SUCCESS) {
        tr_err("Could not create firmware update resource %d! Error was %d", MANIFEST_RESOURCE_OEMBOOT_HASH, status);
        return status;
    }

    uint8_t *vendor_id = (uint8_t*)malloc( (MANIFEST_VENDOR_STR_SIZE + 1) * sizeof(uint8_t) );
    memcpy(vendor_id, MANIFEST_VENDOR_STR, MANIFEST_VENDOR_STR_SIZE);
    vendor_id[MANIFEST_VENDOR_STR_SIZE] = 0;
    status = pt_device_add_resource(connection_id,
                                    device_id,
                                    DEVICE_META_OBJECT,
                                    MANIFEST_INSTANCE,
                                    MANIFEST_RESOURCE_VENDOR,
                                    /* resource name */ NULL,
                                    LWM2M_STRING,
                                    vendor_id,
                                    strlen(vendor_id),
                                    free);
    if (status != PT_STATUS_SUCCESS) {
        tr_err("Could not create firmware update resource %d! Error was %d", MANIFEST_RESOURCE_VENDOR, status);
        return status;
    }

    uint8_t *class_id = (uint8_t*)malloc( (MANIFEST_CLASS_STR_SIZE + 1) * sizeof(uint8_t) );
    memcpy(class_id, MANIFEST_CLASS_STR, MANIFEST_CLASS_STR_SIZE);
    class_id[MANIFEST_CLASS_STR_SIZE] = 0;
    status = pt_device_add_resource(connection_id,
                                    device_id,
                                    DEVICE_META_OBJECT,
                                    MANIFEST_INSTANCE,
                                    MANIFEST_RESOURCE_CLASS,
                                    /* resource name */ NULL,
                                    LWM2M_STRING,
                                    class_id,
                                    strlen(class_id),
                                    free);
    if (status != PT_STATUS_SUCCESS) {
        tr_err("Could not create firmware update resource %d! Error was %d", MANIFEST_RESOURCE_CLASS, status);
        return status;
    }

    return PT_STATUS_SUCCESS;
}

void pt_manifest_context_free(pt_manifest_context_t *ctx)
{
    if (ctx) free(ctx);
}

void pt_handle_download_request_failure(json_t *response, void *callback_data)
{
    tr_error("asset request incomplete. Passing off to customer error callback");
    pt_asset_download_callback_t *customer_callback = (pt_asset_download_callback_t *) callback_data;
    customer_callback->failure_handler(customer_callback->connection_id, NULL, -1, customer_callback->userdata);
}

void pt_handle_manifest_status_success(json_t *response, void *callback_data)
{
    tr_info("Manifest Status Send");
}
void pt_handle_manifest_status_failure(json_t *response, void *callback_data)
{
    tr_info("Manifest Status Send Fail");
}
 void pt_handle_download_request_success(json_t *response, void *callback_data)
{
    tr_debug("asset request complete. Passing off to customer callback");

    pt_asset_download_callback_t *customer_callback = (pt_asset_download_callback_t *) callback_data;

    json_t *result_handle = json_object_get(response, "result");
    json_t *filename_handle = json_object_get(result_handle, "filename");
    json_t *error_handle = json_object_get(result_handle, "error");
    if (filename_handle == NULL) {
        customer_callback->failure_handler(customer_callback->connection_id, NULL, -2, customer_callback->userdata);
        return;
    }

    const char *filename = json_string_value(filename_handle);
    int error_code = json_integer_value(error_handle);

    tr_debug("Download result, (filename '%s', error code %d)", filename, error_code);

    customer_callback->success_handler(customer_callback->connection_id, filename, error_code, customer_callback->userdata);
}

pt_status_t pt_download_asset_internal(const connection_id_t connection_id,
                                       const char *device_id,
                                       uint64_t size,
                                       pt_download_cb success_handler,
                                       pt_download_cb failure_handler,
                                       void *userdata)
{
    if (success_handler == NULL || failure_handler == NULL) {
        return PT_STATUS_INVALID_PARAMETERS;
    }
    tr_info("Sending download request");
    json_t *message = allocate_base_request("download_asset");
    json_t *params = json_object_get(message, "params");
    json_object_set_new(params, "size", json_integer(size));
    json_object_set_new(params, "deviceId", json_string(device_id));

    pt_asset_download_callback_t *customer_callback = (pt_asset_download_callback_t*)allocate_customer_callback(connection_id,
                                                                                                                (pt_response_handler)success_handler,
                                                                                                                (pt_response_handler)failure_handler,
                                                                                                                userdata);
    if (message == NULL || params == NULL || customer_callback == NULL ) {
        tr_error("error in sending download request");
        json_decref(message);
        pt_manifest_context_free(userdata);
        customer_callback_free_func((rpc_request_context_t *) customer_callback);
        return PT_STATUS_ALLOCATION_FAIL;
    }

    return construct_and_send_outgoing_message(connection_id,
                                               message,
                                               pt_handle_download_request_success,
                                               pt_handle_download_request_failure,
                                               (rpc_free_func) customer_callback_free_func,
                                               PT_CUSTOMER_CALLBACK_T,
                                               customer_callback);
}

pt_status_t pt_subdevice_manifest_status(const connection_id_t connection_id,
                                       const char *device_id,
                                       arm_uc_update_result_t *error_manifest,
                                       pt_download_cb success_handler,
                                       pt_download_cb failure_handler,
                                       void *userdata)
{
    tr_info("pt_subdevice_manifest_status %d",*error_manifest);
    char err_str[10];
    json_t *message = allocate_base_request("subdevice_manifest_status");
    itoa_c(*error_manifest, err_str);
    json_t *params = json_object_get(message, "params");
    json_t *json_name = json_string(err_str);
    json_t *json_device_id = json_string(device_id);
    pt_customer_callback_t *customer_callback = allocate_customer_callback(connection_id,
                                                                           (pt_response_handler) success_handler,
                                                                           (pt_response_handler) failure_handler,
                                                                           userdata);
    if (message == NULL || params == NULL || customer_callback == NULL || json_name == NULL || json_device_id==NULL) {
        json_decref(message);
        json_decref(json_name);
        json_decref(json_device_id);
        customer_callback_free_func((rpc_request_context_t *) customer_callback);
        return PT_STATUS_ALLOCATION_FAIL;
    }
    json_object_set_new(params, "error_manifest", json_name);
    json_object_set_new(params, "device_id", json_device_id);
    return construct_and_send_outgoing_message(connection_id,
                                               message,
                                               pt_handle_manifest_status_success,
                                               pt_handle_manifest_status_failure,
                                               (rpc_free_func) customer_callback_free_func,
                                               PT_CUSTOMER_CALLBACK_T,
                                               customer_callback);
}


#endif // MBED_EDGE_SUBDEVICE_FOTA