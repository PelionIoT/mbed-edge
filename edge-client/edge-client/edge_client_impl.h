/*
 * ----------------------------------------------------------------------------
 * Copyright 2018 ARM Ltd.
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

#ifndef EDGE_CLIENT_IMPL_H_
#define EDGE_CLIENT_IMPL_H_

#ifndef TRACE_GROUP
#define TRACE_GROUP "edgecc"
#endif


#include <stdio.h>
#include "MbedCloudClient.h"
#include "mbed-trace/mbed_trace.h"

#ifdef MBED_EDGE_SUBDEVICE_FOTA
#include <unistd.h>
#include "update-client-common/arm_uc_types_internal.h"
#endif // MBED_EDGE_SUBDEVICE_FOTA

class EdgeClientImpl : MbedCloudClientCallback {
public:

    typedef void(*value_updated_cb) (M2MBase *base, M2MBase::BaseType type);
    typedef void(*on_registered_cb) (void);
    typedef void(*on_registration_updated_cb) (void);
    typedef void(*on_unregistered_cb) (void);
    typedef void(*on_error_cb) (int error_code, const char *error_description);

    EdgeClientImpl() :
    _interrupt_received(false),
    _registered(false),
    _network_interface(EDGE_PRIMARY_NETWORK_INTERFACE_ID)
    {
        _cloud_client.on_registered(this, &EdgeClientImpl::client_registered);
        _cloud_client.on_registration_updated(this, &EdgeClientImpl::client_registration_updated);
        _cloud_client.on_unregistered(this, &EdgeClientImpl::client_unregistered);
        _cloud_client.on_error(this, &EdgeClientImpl::error);
        _cloud_client.set_update_callback(this);
        _on_error_cb = NULL;
        _on_registered_cb = NULL;
        _on_unregistered_cb = NULL;
        _on_registration_updated_cb = NULL;
    }

    virtual ~EdgeClientImpl() {
    }

    void set_interrupt_received()
    {
        _interrupt_received = true;
    }

    bool is_interrupt_received()
    {
        return _interrupt_received;
    }

    void set_on_registered_callback(on_registered_cb cb)
    {
        _on_registered_cb = cb;
    }

    void set_on_registration_updated_callback(on_registration_updated_cb cb)
    {
        _on_registration_updated_cb = cb;
    }

    void set_on_unregistered_callback(on_unregistered_cb cb)
    {
        _on_unregistered_cb = cb;
    }

    void set_on_error_callback(on_error_cb cb)
    {
        _on_error_cb = cb;
    }

    void set_on_certificate_renewal_callback(cert_renewal_cb_f renewal_cb)
    {
        _cloud_client.on_certificate_renewal(renewal_cb);
    }

    void set_on_est_result_callback(est_enrollment_result_cb est_result_cb)
    {
        _on_est_result_cb = est_result_cb;
    }

    void est_free_cert_chain_context(struct cert_chain_context_s *chain_ctx)
    {
        _cloud_client.est_free_cert_chain_context(chain_ctx);
    }

    const est_status_e est_request_enrollment(const char *cert_name,
                                              uint8_t *csr,
                                              const size_t csr_length,
                                              void *context) const
    {
        if (_on_est_result_cb == NULL) {
            return EST_STATUS_INVALID_PARAMETERS;
        }
        return _cloud_client.est_request_enrollment(cert_name, strlen(cert_name), csr, csr_length, _on_est_result_cb, context);
    }


    const char *get_internal_id() {
        const ConnectorClientEndpointInfo *endpoint_info = _cloud_client.endpoint_info();
        if (endpoint_info) {
            return endpoint_info->internal_endpoint_name.c_str();
        } else {
            return "";
        }
    }

    const char *get_account_id() {
        const ConnectorClientEndpointInfo *endpoint_info = _cloud_client.endpoint_info();
        if (endpoint_info) {
            return endpoint_info->account_id.c_str();
        } else {
            return "";
        }
    }

    const char *get_lwm2m_server_uri() {
        const ConnectorClientEndpointInfo *endpoint_info = _cloud_client.endpoint_info();
        if (endpoint_info) {
            return endpoint_info->lwm2m_server_uri.c_str();
        }else {
            return "";
        }

    }
    const char *get_endpoint_name() {
        const ConnectorClientEndpointInfo *endpoint_info = _cloud_client.endpoint_info();
        if (endpoint_info) {
            return endpoint_info->endpoint_name.c_str();
        } else {
            return "";
        }
    }

    void add_objects(M2MBaseList &objects)
    {
        _cloud_client.add_objects(objects);
    }

    void remove_object(M2MBase *object)
    {
        tr_debug("Remove object %p", object);
        _cloud_client.remove_object(object);
    }

    const M2MBaseList *get_object_list()
    {
        return _cloud_client.get_object_list();
    }

    ce_status_e certificate_renew(const char *certificate_name)
    {
        return _cloud_client.certificate_renew(certificate_name);
    }

    void start_registration()
    {
        _cloud_client.setup((void *) _network_interface);
    }

    void start_update_registration()
    {
        tr_debug("Start update registration");
        _cloud_client.register_update();
    }

#ifdef MBED_EDGE_SUBDEVICE_FOTA

    typedef struct {
        char *device_id;                       // Endpoint Id
        uint32_t size_max;                      // Maximum size of the fragment buffer
        uint32_t size;                          // Actual size of the fragment buffer
        uint8_t ptr[2048];                           // Pointer to the fragment buffer
        int offset;                             // Offset in the entire asset that the fragment is at
        char *filename;                         // Filename the asset is getting saved to
        uint8_t *url;                           // URL the asset is getting downloaded from
        int file_size;                          // Total size of the asset
        M2MInterface* interface;                // Interface used for obtaining the asset
        asset_download_complete_cb success_cb;  // Callback to run after the asset has been downloaded
        void *ctx;                              // Original context used for sending the json struct later
        int error_code;                         // Error code for the transaction
        bool last_block;
    } arm_uc_asset_state_t;

    static int checkHTTPstatus(int sock)
    {
        char buff[1024] = "", *ptr = buff + 1;
        int bytes_received, status;
        while (bytes_received = recv(sock, ptr, 1, 0)) {
            if (bytes_received == -1) {
                tr_err("checkHTTPstatus");
                return -1;
            }

            if ((ptr[-1] == '\r') && (*ptr == '\n'))
                break;
            ptr++;
        }
        *ptr = 0;
        ptr = buff + 1;

        sscanf(ptr, "%*s %d ", &status);

        tr_debug("%s\n", ptr);
        tr_debug("status=%d\n", status);
        tr_debug("End Response ..\n");
        return (bytes_received > 0) ? status : 0;
    }

    static int get_total_length_http_header(int sock)
    {
        char buff[1024] = "", *ptr = buff + 4;
        int bytes_received, status;
        tr_info("Begin HEADER ..\n");
        while (bytes_received = recv(sock, ptr, 1, 0)) {
            if (bytes_received == -1) {
                tr_err("Parse Header");
                return -1;
            }

            if ((ptr[-3] == '\r') && (ptr[-2] == '\n') && (ptr[-1] == '\r') && (*ptr == '\n'))
                break;
            ptr++;
        }

        *ptr = 0;
        ptr = buff + 4;

        if (bytes_received) {
            ptr = strstr(ptr, "Content-Length:");
            if (ptr) {
                sscanf(ptr, "%*s %d", &bytes_received);

            } else
                bytes_received = -1;

            tr_debug("Content-Length: %d\n", bytes_received);
        }
        tr_info("End HEADER ..\n");
        return bytes_received;
    }

    static arm_uc_update_result_t fw_file_download(arm_uc_asset_state_t *state)
    {
        char *url_without_http = NULL;
        if (strstr((char *) state->url, "http://")) {
            url_without_http = strdup((char *) state->url + 7);
        } else if (strstr((char *) state->url, "https://")) {
            url_without_http = strdup((char *) state->url + 8);
        }

        char *fw_file = NULL;
        char *server_uri = strtok_r(url_without_http, "/", &fw_file);

        uint sock, bytes_received;
        char send_data[1024], *p;
        char *recv_data;
        if((state) && (state->file_size>0))
        {
            recv_data = (char *) malloc(state->file_size+1);
	        if(recv_data==NULL)
	        {
	            tr_err("File size memory allocation fail");
                return ARM_UC_UPDATE_RESULT_FETCHER_NONSPECIFIC_ERROR;
            }
        }
        struct sockaddr_in server_addr;
        struct hostent *host;

        host = gethostbyname(server_uri);
        if (host == NULL) {
            tr_err("Host name does not resolved");
            free(recv_data);
            return ARM_UC_UPDATE_RESULT_FETCHER_INVALID_REQUEST_TYPE;
        }

        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            tr_err("Socket not opened");
            free(recv_data);
            return ARM_UC_UPDATE_RESULT_FETCHER_INVALID_REQUEST_TYPE;
        }
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(80);
        server_addr.sin_addr = *((struct in_addr *) host->h_addr);
        bzero(&(server_addr.sin_zero), 8);

        if (connect(sock, (struct sockaddr *) &server_addr, sizeof(struct sockaddr)) == -1) {
            tr_err("HTTP Socket Connect Error");
            free(recv_data);
            return ARM_UC_UPDATE_RESULT_FETCHER_NETWORK_CONNECTION_FAILURE;
        }

        snprintf(send_data, sizeof(send_data), "GET /%s HTTP/1.1\r\nHost: %s\r\n\r\n", fw_file, server_uri);

        if (send(sock, send_data, strlen(send_data), 0) == -1) {
            tr_err("HTTP Socket Connect Error");
            free(recv_data);
            return ARM_UC_UPDATE_RESULT_FETCHER_NETWORK_CONNECTION_FAILURE;
        }
        tr_info("Data sent.\n");

        uint totallength;

        if (checkHTTPstatus(sock) && (totallength = get_total_length_http_header(sock))) {

            uint64_t bytes = 0;
            FILE *fd = fopen(state->filename, "w+");

            tr_info("Saving data...\n\n");

            while (bytes_received = recv(sock, recv_data, 1024, 0)) {
                if (bytes_received == -1) {
                    tr_err("recieve failure");
                    fclose(fd);
                    return ARM_UC_UPDATE_RESULT_FETCHER_NETWORK_CONNECTION_FAILURE;
                }

                if (fwrite(recv_data, 1, bytes_received, fd) != bytes_received) {
                    tr_err("Firmware binary Write Fail");
                    fclose(fd);
                    if (url_without_http != NULL)
                        free(url_without_http);
                    if (recv_data)
                        free(recv_data);
                    close(sock);
                    return ARM_UC_UPDATE_RESULT_WRITER_INSUFFICIENT_STORAGE_SPACE;
                }
                bytes += bytes_received;
                uint percent = (bytes * 100) / totallength;
                printf("%d%%\r", percent);
                fflush(stdout);

                if (bytes == totallength)
                    break;
            }
            fclose(fd);
        }

        if(url_without_http!=NULL)
            free(url_without_http);

        if (recv_data)
            free(recv_data);

        close(sock);
        return ARM_UC_UPDATE_RESULT_UPDATE_FIRST;
    }

    static void *subdevice_download_fw(void *ctx)
    {
           // Begin asset download
        tr_cmdline("\nFirmware Downloading");
        arm_uc_asset_state_t *state = (arm_uc_asset_state_t *)ctx;

        tr_cmdline("\n%s",state->filename);
        //HTTP get request download
        arm_uc_update_result_t fw_download_status = fw_file_download(state);
        tr_info("\nFirmware completed %s %d %s", state->url, state->file_size, state->filename);
        if (fw_download_status != ARM_UC_UPDATE_RESULT_UPDATE_FIRST) {
            tr_err("Firmware Download fail");
            char err_str[3] = " "; // for storing the error into string
            itoa_c(fw_download_status, err_str);
            tr_debug("Error Code from Manifest :%d %s", fw_download_status, err_str);
            ARM_UC_SUBDEVICE_ReportUpdateResult(state->device_id, err_str);
            state->filename = NULL;
            state->error_code = fw_download_status;
        }
        state->success_cb(state->url, state->filename, state->error_code, state->ctx);

        if (state->device_id)
            free(state->device_id);
         if (state)
            free(state);
    }

    void client_obtain_asset(char *device_id,
                             uint8_t *uri_buffer,
                             char *filename,
                             size_t size,
                             asset_download_complete_cb cb,
                             void *ctx)
    {
        if (!_registered) {
            tr_error("Client not registered and cannot obtain LWM2M client yet!");
            return;
        }
        // Create a new state and fill with appropriate information
        arm_uc_asset_state_t *state = (arm_uc_asset_state_t *)calloc(1, sizeof(arm_uc_asset_state_t));
        state->size_max = 1024;
        state->size = 1024;
        state->offset = 0;
        state->filename = filename;
        state->url = uri_buffer;
        state->file_size = size;
        state->interface = _cloud_client.get_m2m_interface();
        state->success_cb = cb;
        state->ctx = ctx;
        state->error_code = 0;
        state->device_id = (char *) malloc(strlen(device_id));
        if (state->device_id)
            strcpy(state->device_id, device_id);

        pthread_t subdevice_fw_download_thread;

        /* Create independent threads to download fw each of which will execute function */

        pthread_create( &subdevice_fw_download_thread, NULL, &subdevice_download_fw, (void*) state);
        pthread_detach(subdevice_fw_download_thread);
    }

#endif // MBED_EDGE_SUBDEVICE_FOTA

    void client_registered()
    {
        _registered = true;
        mbed_tracef(TRACE_LEVEL_INFO, TRACE_GROUP, "%s", "Edge-core got registered to the cloud\n");
        const ConnectorClientEndpointInfo *epinfo = _cloud_client.endpoint_info();
        if (epinfo) {
            mbed_tracef(TRACE_LEVEL_INFO, TRACE_GROUP,
                        "Endpoint id : %s, name : %s \n",
                             epinfo->internal_endpoint_name.c_str(),
                             epinfo->endpoint_name.c_str());
        }
        if (_on_registered_cb) {
            _on_registered_cb();
        }
    }

    void client_registration_updated()
    {
        tr_debug("Client registration updated\n");
        if (_on_registration_updated_cb) {
            _on_registration_updated_cb();
        }
    }

    void client_unregistered()
    {
        _registered = false;
        tr_debug("Client unregistered\n");
        if (_on_unregistered_cb) {
            _on_unregistered_cb();
        }
    }

    void error(int error_code)
    {
        const char *error;
        switch(error_code) {
            case MbedCloudClient::ConnectErrorNone:
                error = "MbedCloudClient::ConnectErrorNone";
                break;
            case MbedCloudClient::ConnectAlreadyExists:
                error = "MbedCloudClient::ConnectAlreadyExists";
                stop_client();
                break;
            case MbedCloudClient::ConnectBootstrapFailed:
                error = "MbedCloudClient::ConnectBootstrapFailed";
                stop_client();
                break;
            case MbedCloudClient::ConnectInvalidParameters:
                error = "MbedCloudClient::ConnectInvalidParameters";
                stop_client();
                break;
            case MbedCloudClient::ConnectNotRegistered:
                error = "MbedCloudClient::ConnectNotRegistered";
                stop_client();
                break;
            case MbedCloudClient::ConnectTimeout:
                error = "MbedCloudClient::ConnectTimeout";
                stop_client();
                break;
            case MbedCloudClient::ConnectNetworkError:
                error = "MbedCloudClient::ConnectNetworkError";
                stop_client();
                break;
            case MbedCloudClient::ConnectResponseParseFailed:
                error = "MbedCloudClient::ConnectResponseParseFailed";
                tr_warning("Ignoring CoAP parse error: %s", error);
                return;
            case MbedCloudClient::ConnectUnknownError:
                error = "MbedCloudClient::ConnectUnknownError";
                stop_client();
                break;
            case MbedCloudClient::ConnectMemoryConnectFail:
                error = "MbedCloudClient::ConnectMemoryConnectFail";
                stop_client();
                break;
            case MbedCloudClient::ConnectNotAllowed:
                error = "MbedCloudClient::ConnectNotAllowed";
                stop_client();
                break;
            case MbedCloudClient::ConnectSecureConnectionFailed:
                error = "MbedCloudClient::ConnectSecureConnectionFailed";
                stop_client();
                break;
            case MbedCloudClient::ConnectDnsResolvingFailed:
                error = "MbedCloudClient::ConnectDnsResolvingFailed";
                stop_client();
                break;
#ifdef MBED_CLOUD_CLIENT_SUPPORT_UPDATE
            case MbedCloudClient::UpdateWarningCertificateNotFound:
                error = "MbedCloudClient::UpdateWarningCertificateNotFound";
                break;
            case MbedCloudClient::UpdateWarningIdentityNotFound:
                error = "MbedCloudClient::UpdateWarningIdentityNotFound";
                break;
            case MbedCloudClient::UpdateWarningCertificateInvalid:
                error = "MbedCloudClient::UpdateWarningCertificateInvalid";
                break;
            case MbedCloudClient::UpdateWarningSignatureInvalid:
                error = "MbedCloudClient::UpdateWarningSignatureInvalid";
                break;
            case MbedCloudClient::UpdateWarningVendorMismatch:
                error = "MbedCloudClient::UpdateWarningVendorMismatch";
                break;
            case MbedCloudClient::UpdateWarningClassMismatch:
                error = "MbedCloudClient::UpdateWarningClassMismatch";
                break;
            case MbedCloudClient::UpdateWarningDeviceMismatch:
                error = "MbedCloudClient::UpdateWarningDeviceMismatch";
                break;
            case MbedCloudClient::UpdateWarningURINotFound:
                error = "MbedCloudClient::UpdateWarningURINotFound";
                break;
            case MbedCloudClient::UpdateWarningRollbackProtection:
                error = "MbedCloudClient::UpdateWarningRollbackProtection";
                break;
            case MbedCloudClient::UpdateWarningUnknown:
                error = "MbedCloudClient::UpdateWarningUnknown";
                break;
            case MbedCloudClient::UpdateErrorWriteToStorage:
                error = "MbedCloudClient::UpdateErrorWriteToStorage";
                stop_client();
                break;
#endif
            default:
                stop_client();
                error = "UNKNOWN";
        }
        tr_error("Error occured : %s", error);
        tr_error("Error code : %d", error_code);
        tr_error("Error details : %s",_cloud_client.error_description());
        if (_on_error_cb) {
            _on_error_cb(error_code, _cloud_client.error_description());
        }
    }

    void stop_client()
    {
        _registered = false;
    }

    void value_updated(M2MBase *base, M2MBase::BaseType type)
    {
        (void) base;
        (void) type;
    }

private:
    MbedCloudClient _cloud_client;
    on_registered_cb _on_registered_cb;
    on_registration_updated_cb _on_registration_updated_cb;
    on_unregistered_cb _on_unregistered_cb;
    on_error_cb _on_error_cb;
    est_enrollment_result_cb _on_est_result_cb;
    bool _interrupt_received;
    bool _registered;
    const char *_network_interface;
};

#endif /* EDGE_CLIENT_IMPL_H_ */
