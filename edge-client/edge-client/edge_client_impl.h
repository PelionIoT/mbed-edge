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
