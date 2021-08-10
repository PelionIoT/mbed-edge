/*
 * ----------------------------------------------------------------------------
 * Copyright 2021 Pelion Ltd.
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

#include "edge-client/subdevice_fota.h"

static fota_context_t* fota_ctx = NULL;
static char *endpoint = NULL;

int subdevice_init_buff() {
    fota_ctx = (fota_context_t*) calloc(1, sizeof(fota_context_t));
    if(fota_ctx == NULL) {
        FOTA_TRACE_ERROR("Unable to allocate FOTA ctx.");
        return FOTA_STATUS_OUT_OF_MEMORY;

    }
    fota_ctx->fw_info = (manifest_firmware_info_t*) calloc(1, sizeof(manifest_firmware_info_t));
    if (!fota_ctx->fw_info) {
        FOTA_TRACE_ERROR("Unable to allocate FW info.");
        return FOTA_STATUS_OUT_OF_MEMORY;
    }
    endpoint = (char*) calloc(ENDPOINT_SIZE,1*sizeof(char));
    if(!endpoint) {
        FOTA_TRACE_ERROR("Unable to allocate memory for endpoint");
        return FOTA_STATUS_OUT_OF_MEMORY;      
    }
    return 0;
}

int get_component_name(char* c_name) {
    if(fota_ctx) {
        memcpy(c_name, fota_ctx->fw_info->component_name, FOTA_COMPONENT_MAX_NAME_SIZE);
        return 0;
    }
    return -1;
}

int update_result_resource(char* device_id, uint8_t val) {

    return edgeclient_set_resource_value(device_id,
                                MANIFEST_OBJECT,
                                MANIFEST_INSTANCE,
                                MANIFEST_RESOURCE_RESULT,
                                "",
                                &val,
                                sizeof(val),
                                LWM2M_INTEGER,
                                1,
                                NULL);

}

int update_state_resource(char* device_id, uint8_t val) {
    return edgeclient_set_resource_value(device_id,
                                MANIFEST_OBJECT,
                                MANIFEST_INSTANCE,
                                MANIFEST_RESOURCE_STATE,
                                "",
                                &val,
                                sizeof(val),
                                LWM2M_INTEGER,
                                1,
                                NULL);
}

void get_endpoint(char* endpoint, const char* uri) {
    char *uri_path = strdup(uri); // URI : d/device_id/10252/0/1
    char *left_string = NULL;
    char *manifest_res = NULL;
    strtok_r(uri_path, "/", &left_string); // left_string : device_id/10252/0/1
    char *device_id = strtok_r(left_string, "/", &manifest_res);
    memcpy(endpoint, device_id, strlen(device_id));
    if(uri_path) {
        free(uri_path);
        uri_path = NULL;
    }
}

void get_vendor_id(uint8_t* v_id) {
    if(fota_ctx) {
        memcpy(v_id, fota_ctx->fw_info->vendor_id, FOTA_VENDOR_ID_LEN);
    }
}
void get_class_id(uint8_t* c_id) {
    if(fota_ctx) {
        memcpy(c_id, fota_ctx->fw_info->class_id, FOTA_CLASS_ID_LEN);
    }
}

void get_uri(char* c_url) {
    if(fota_ctx) {
        memcpy(c_url, fota_ctx->fw_info->uri, FOTA_MANIFEST_URI_SIZE);
    }
}


unsigned int get_component_id() {
    if(fota_ctx) {
        return fota_ctx->comp_id;
    }
    return 0;
}

void free_subdev_context_buffers(void)
{
    if(fota_ctx->fw_info) {
        free(fota_ctx->fw_info);
        fota_ctx->fw_info = NULL;
    }
    if(fota_ctx) {
        free(fota_ctx);
        fota_ctx = NULL;
    }
    if(endpoint){
        free(endpoint);
        endpoint = NULL;
    }
}
size_t get_manifest_fw_size() {
    if(fota_ctx) {
        return fota_ctx->fw_info->payload_size;
    }
    return 0;
}

void subdevice_fota_on_manifest(uint8_t* data, size_t data_size, M2MResource* resource) {
    tr_info("subdevice_fota_on_manifest");
    const fota_component_desc_t *comp_desc;
    fota_component_version_t curr_fw_version;
    uint8_t curr_fw_digest[FOTA_CRYPTO_HASH_SIZE] = {0};
    int ret = subdevice_init_buff();
    if (ret) {
        FOTA_TRACE_DEBUG("Initialising buffer failed");
        goto fail;
    }
    get_endpoint(endpoint, resource->uri_path());
    ret = fota_manifest_parse(data, data_size,fota_ctx->fw_info);
    if (ret) {
        FOTA_TRACE_DEBUG("Pelion FOTA manifest rejected %d", ret);
        goto fail;
    }

    FOTA_TRACE_DEBUG("Pelion FOTA manifest is valid");

    ret = fota_component_name_to_id(fota_ctx->fw_info->component_name, &fota_ctx->comp_id);
    if (ret) {
        FOTA_TRACE_ERROR("Manifest addresses unknown component %s", fota_ctx->fw_info->component_name);
        ret = FOTA_STATUS_UNEXPECTED_COMPONENT;
        goto fail;
    }
    
    fota_component_get_desc(fota_ctx->comp_id, &comp_desc);

    if (comp_desc->desc_info.curr_fw_get_digest) {
        comp_desc->desc_info.curr_fw_get_digest(curr_fw_digest);
    }

    fota_component_get_curr_version(fota_ctx->comp_id, &curr_fw_version);
    FOTA_FI_SAFE_COND(fota_ctx->fw_info->version > curr_fw_version,
                      FOTA_STATUS_MANIFEST_VERSION_REJECTED, "Manifest payload-version rejected - too old");

    tr_info("Handle manifest: component %s, curr version %" PRIu64 ", new version %" PRIu64 "",
                     fota_ctx->fw_info->component_name, curr_fw_version, fota_ctx->fw_info->version);

    if (fota_ctx->fw_info->payload_format == FOTA_MANIFEST_PAYLOAD_FORMAT_DELTA) {
    #if defined(FOTA_DISABLE_DELTA)
        ret = FOTA_STATUS_MANIFEST_PAYLOAD_UNSUPPORTED;
        goto fail;
    #else  // defined(FOTA_DISABLE_DELTA)
        if (!comp_desc->desc_info.support_delta) {
            ret = FOTA_STATUS_MANIFEST_PAYLOAD_UNSUPPORTED;
            FOTA_TRACE_ERROR("Delta payload unsupported.");
            goto fail;
        }

    FOTA_FI_SAFE_MEMCMP(curr_fw_digest, fota_ctx->fw_info->precursor_digest, FOTA_CRYPTO_HASH_SIZE,
                            FOTA_STATUS_MANIFEST_PRECURSOR_MISMATCH,
                            "Precursor digest mismatch");
#endif  // defined(FOTA_DISABLE_DELTA)
    } else {
        // If we have the current fw digest, place it in precursor for the case the installer needs it
        memcpy(fota_ctx->fw_info->precursor_digest, curr_fw_digest, FOTA_CRYPTO_HASH_SIZE);
    }

    fota_ctx->state = FOTA_STATE_AWAIT_DOWNLOAD_AUTHORIZATION;
    return;

fail:
    // Reset buffer received from network and failed authorization/verification
    memset(data, 0,data_size);
    resource->set_manifest_check_status(false);
    subdevice_abort_update(ret,"manifest not parsed");
}

void get_version(fota_component_version_t *version) {
    if(fota_ctx)
        *version = fota_ctx->fw_info->version;
    else
        *version = 0;
}

static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
  size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
  return written;
}

int start_download(char* downloaded_path) {
    char filename[FILENAME_MAX] = "";
    sprintf(filename,"%s/%s-%" PRIu64 ".bin",SUBDEVICE_FIRMWARE_DOWNLOAD_LOCATION,fota_ctx->fw_info->component_name, fota_ctx->fw_info->version);
    tr_info("File location: %s", filename);
    fota_ctx->state = FOTA_STATE_DOWNLOADING;
    CURL *curl_handle;
    FILE *fwfile;
    curl_global_init(CURL_GLOBAL_ALL);
    curl_handle = curl_easy_init();
    curl_easy_setopt(curl_handle, CURLOPT_URL,fota_ctx->fw_info->uri);
    curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 0L);
    curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_data);
    fwfile = fopen(filename, "wb");
    if(fwfile) {
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, fwfile);
        if(curl_easy_perform(curl_handle) != 0) {
            curl_easy_cleanup(curl_handle);
            curl_global_cleanup();
            fclose(fwfile);
            subdevice_abort_update(FOTA_STATUS_DOWNLOAD_AUTH_NOT_GRANTED, "can not download firmware");
            return FOTA_STATUS_DOWNLOAD_AUTH_NOT_GRANTED;
        }
        else {
            curl_easy_cleanup(curl_handle);
            fclose(fwfile);
        }
    }
    else {
        tr_error("can not open file, aborting");
        subdevice_abort_update(FOTA_STATUS_STORAGE_WRITE_FAILED,"Can not open file, aborting the update!");
        curl_easy_cleanup(curl_handle);
        curl_global_cleanup();
        return FOTA_STATUS_STORAGE_WRITE_FAILED;
    }
    char* res = realpath(filename,downloaded_path);
    if(res == NULL) {
        tr_error("Err: cannot find the downloaded binary");
        subdevice_abort_update(FOTA_STATUS_STORAGE_WRITE_FAILED,"cannot find the downloaded binary");
        return FOTA_STATUS_STORAGE_WRITE_FAILED;
    }
    return FOTA_STATUS_SUCCESS;
}

void subdevice_abort_update(int err, const char* msg) {
    tr_error("Reason: %d", err);
    tr_error("%s",msg);
    int upd_res = -1 * err;
    update_result_resource(endpoint,upd_res);
    update_state_resource(endpoint, FOTA_SOURCE_STATE_IDLE);
    free_subdev_context_buffers();
}
#endif