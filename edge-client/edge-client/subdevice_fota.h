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

// int fota_download_start(void *download_handle, const char *payload_url, size_t payload_offset);
// int fota_download_init(void **download_handle);
#define ENDPOINT_SIZE 256
#define MANIFEST_URI_SIZE 256
int fota_is_ready(uint8_t *data, size_t size, fota_state_e *fota_state);
int fota_manifest_parse(const uint8_t *input_data, size_t input_size, manifest_firmware_info_t *fw_info);
int fota_component_name_to_id(const char *name, unsigned int *comp_id);
void fota_component_get_desc(unsigned int comp_id, const fota_component_desc_t * *comp_desc);
void fota_component_get_curr_version(unsigned int comp_id, fota_component_version_t *version);
void subdevice_fota_on_manifest(uint8_t* data, size_t data_size, M2MResource* resource);
int update_result_resource(char* device_id, uint8_t err_mccp);
int update_state_resource(char* device_id, uint8_t val);
void get_endpoint(char* endpoint,const char* uri_path);
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
    void subdevice_abort_update(int err, char* msg = NULL);
    size_t get_manifest_fw_size();
#ifdef __cplusplus
}
#endif
#endif
#endif
#endif //__SUBDEVICE_FOTA_H__