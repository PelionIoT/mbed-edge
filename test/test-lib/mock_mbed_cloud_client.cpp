
#define TRACE_GROUP "edgecc"
#include <stdio.h>
#include <stdint.h>
#include "mbed-cloud-client/MbedCloudClient.h"
#include "mbed-client/m2mbase.h"
#include "mbed-client/m2mendpoint.h"
#include "mbed-client/m2mobject.h"
#include "mbed-client/m2mobjectinstance.h"
#include "mbed-client/m2mresource.h"
#include "mbed-client/m2mstring.h"
#include "edge-client/edge_client.h"
#include "CppUTestExt/MockSupport.h"
#include "mbed-trace/mbed_trace.h"

ConnectorClient::ConnectorClient(ConnectorClientCallback* callback) :
        _callback(callback),
        _current_state(State_Bootstrap_Start),
        _event_generated(false), _state_engine_running(false),
        _interface(NULL), _endpoint_info(M2MSecurity::Certificate),
        _client_objs(NULL), _rebootstrap_timer(NULL), _bootstrap_security_instance(1),
        _lwm2m_security_instance(0), _certificate_chain_handle(NULL)
#ifndef MBED_CLIENT_DISABLE_EST_FEATURE
        ,_est_client(*this)
#endif // !MBED_CLIENT_DISABLE_EST_FEATURE
{

}

ConnectorClient::~ConnectorClient() {

}

void ConnectorClient::sleep() {

}

void ConnectorClient::paused() {

}

void ConnectorClient::alert_mode() {

}

void ConnectorClient::bootstrap_done(M2MSecurity *server_object) {

}

void ConnectorClient::bootstrap_data_ready(M2MSecurity *security_object) {

}

void ConnectorClient::object_registered(M2MSecurity *security_object, const M2MServer &server_object) {

}

void ConnectorClient::object_unregistered(M2MSecurity *server_object) {

}

void ConnectorClient::registration_updated(M2MSecurity *security_object, const M2MServer & server_object) {

}

void ConnectorClient::error(M2MInterface::Error error) {

}

void ConnectorClient::value_updated(M2MBase *base, M2MBase::BaseType type) {

}

void ConnectorClient::timer_expired(M2MTimerObserver::Type type) {

}
void ConnectorClient::network_status_changed(bool connected) {

}
void ConnectorClient::init_security_object(uint16_t instance_id) {

}

ServiceClient::ServiceClient(ServiceClientCallback &callback) :
        _service_callback(callback),
        _service_uri(NULL),
        _stack(NULL),
        _client_objs(NULL),
        _current_state(State_Init),
        _event_generated(false),
        _state_engine_running(false),
        _connector_client(this) {

}

ServiceClient::~ServiceClient() {

}

void ServiceClient::registration_process_result(ConnectorClient::StartupSubStateRegistration status) {

}

void ServiceClient::connector_error(M2MInterface::Error error, const char *reason) {

}

void ServiceClient::value_updated(M2MBase *base, M2MBase::BaseType type) {
    mock().actualCall("ServiceClient::value_updated")
            .withPointerParameter("base", (void *) base)
            .withIntParameter("type", (int) type);
}

MbedCloudClient::~MbedCloudClient() {
    mock().actualCall("MbedCloudClient::~MbedCloudClient");
}

MbedCloudClient::MbedCloudClient() : _client(*this), _value_callback(0), _error_description(0) {
    mock().actualCall("MbedCloudClient::MbedCloudClient");
}

void MbedCloudClient::complete(ServiceClientCallback::ServiceClientCallbackStatus status) {
    mock().actualCall("MbedCloudClient::complete").withIntParameter("status", (int) status);
}

void MbedCloudClient::error(int error, const char *reason) {
    mock().actualCall("MbedCloudClient::error")
            .withIntParameter("error", error)
            .withStringParameter("reason", reason);
}

void MbedCloudClient::value_updated(M2MBase *base, M2MBase::BaseType type) {
    mock().actualCall("MbedCloudClient::value_updated")
            .withPointerParameter("base", (void *) base)
            .withIntParameter("type", (int) type);
}

void MbedCloudClient::set_update_callback(MbedCloudClientCallback*) {
    mock().actualCall("MbedCloudClient::set_update_callback");
}

void MbedCloudClient::add_objects(m2m::Vector<M2MBase *> const &base_list)
{
    M2MBaseList::const_iterator it;
    mock().actualCall("MbedCloudClient::add_objects");
    it = base_list.begin();
    // Add object stub doesn't really exist, but we can use that to verify what is added
    for (; it != base_list.end(); it++) {
        mock().actualCall("MbedCloudClient::add_object_stub");
    }
}

bool MbedCloudClient::setup(void *, bool)
{
    return false;
}

void MbedCloudClient::remove_object(M2MBase *object)
{
    mock().actualCall("MbedCloudClient::remove_object")
            .withPointerParameter("object", (void *) object);
}

void MbedCloudClient::register_update()
{
    mock().actualCall("MbedCloudClient::register_update");
}

extern "C" {
uint8_t __nsdl_c_callback(struct nsdl_s *, sn_coap_hdr_s *, sn_nsdl_addr_s *, sn_nsdl_capab_e)
{
    mock().actualCall("__nsdl_c_callback");
    return 0;
}
}

const char *MbedCloudClient::error_description() const
{
    return _error_description;
}

const ConnectorClientEndpointInfo *MbedCloudClient::endpoint_info() const
{
    return (ConnectorClientEndpointInfo *) mock()
        .actualCall("MbedCloudClient::endpoint_info")
        .returnPointerValue();
}

const M2MBaseList* MbedCloudClient::get_object_list() const
{
    return (M2MBaseList*) mock().actualCall("get_object_list")
        .returnPointerValue();
}

ce_status_e MbedCloudClient::certificate_renew(const char *cert_name)
{
    return (ce_status_e)mock().actualCall("MbedCloudClient::certificate_renew").withStringParameter("cert_name", cert_name).returnUnsignedIntValue();
}

void MbedCloudClient::on_certificate_renewal(cert_renewal_cb_f user_cb)
{
    mock().actualCall("MbedCloudClient::on_certificate_renewal").withPointerParameter("user_cb", (void*)user_cb);
}

est_status_e MbedCloudClient::est_request_enrollment(const char *cert_name,
                                                     const size_t cert_name_length,
                                                     uint8_t *csr,
                                                     const size_t csr_length,
                                                     est_enrollment_result_cb result_cb,
                                                     void *context) const
{
    return (est_status_e)mock().actualCall("MbedCloudClient::est_request_enrollment")
        .withMemoryBufferParameter("cert_name", (const unsigned char *) cert_name, cert_name_length)
        .withMemoryBufferParameter("csr", (const unsigned char *) csr, csr_length)
        .withPointerParameter("result_cb", (void *) result_cb)
        .withPointerParameter("context", context)
        .returnIntValue();
}

void MbedCloudClient::est_free_cert_chain_context(struct cert_chain_context_s *ctx) const
{
    mock().actualCall("MbedCloudClient::est_free_cert_chain_context");
}

EstClient::EstClient(ConnectorClient &connector_client) : _connector_client(connector_client)
{
}

EstClient::~EstClient()
{
}
