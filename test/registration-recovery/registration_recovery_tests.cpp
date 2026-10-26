/* SPDX-License-Identifier: Apache-2.0 */
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include "pal.h"
#include "ns_hal_init.h"
#include "ns_event_loop.h"
#include "eventOS_scheduler.h"
#include "mbed-client/m2minterfacefactory.h"
#include "mbed-client/m2minterfaceobserver.h"
#include "include/m2minterfaceimpl.h"
#include "nsdl-c/sn_nsdl_lib.h"
#include "sn_grs.h"
#include "sn_coap_header.h"
#include "edge-client/edge-client/network_recovery_error.h"
#include "edge_network_recovery.h"
#define CHECK(x) do { if (!(x)) { std::fprintf(stderr,"line %d: %s\n",__LINE__,#x);std::exit(1); } } while(0)
// Explicit-instantiation access is confined to this fixture. Exercise the real
// SDK, inspect its state, and capture CoAP in memory without credentials/network.
int reconnection_state(const M2MInterfaceImpl& client);
template<auto Member> struct StateAccess {
    friend int reconnection_state(const M2MInterfaceImpl& client) {
        return static_cast<int>(client.*Member);
    }
};
template struct StateAccess<&M2MInterfaceImpl::_reconnection_state>;
struct NsdlTag {
    using type=M2MNsdlInterface M2MInterfaceImpl::*;
    friend type get(NsdlTag);
};
struct UpdateTag {
    using type=void (M2MInterfaceImpl::*)(EventData*);
    friend type get(UpdateTag);
};
struct EndpointTag {
    using type=sn_nsdl_ep_parameters_s* M2MNsdlInterface::*;
    friend type get(EndpointTag);
};
template<class Tag, typename Tag::type Member> struct Access {
    friend typename Tag::type get(Tag) { return Member; }
};
template struct Access<NsdlTag, &M2MInterfaceImpl::_nsdl_interface>;
template struct Access<UpdateTag, &M2MInterfaceImpl::state_update_registration>;
template struct Access<EndpointTag, &M2MNsdlInterface::_endpoint>;
class Observer : public M2MInterfaceObserver {
public:
    int error_code = M2MInterface::ErrorNone;
    void init_security_object(uint16_t) override {}
    void bootstrap_done(M2MSecurity*) override {}
    void object_registered(M2MSecurity*,const M2MServer&) override {}
    void object_unregistered(M2MSecurity*) override {}
    void registration_updated(M2MSecurity*,const M2MServer&) override {}
    void error(M2MInterface::Error value) override { error_code=value; }
    void value_updated(M2MBase*,M2MBase::BaseType) override {}
    void network_status_changed(bool) override {}
    void paused() override {}
    void alert_mode() override {}
    void sleep() override {}
};
static std::string last_path, last_query;
static unsigned messages;
static uint8_t capture(nsdl_s *handle, sn_nsdl_capab_e, uint8_t *data,
                       uint16_t length, sn_nsdl_addr_s*)
{
    coap_version_e version;
    sn_coap_hdr_s *packet=sn_coap_parser(handle->grs->coap,length,data,&version);
    CHECK(packet && packet->msg_code==COAP_MSG_CODE_REQUEST_POST);
    last_path.assign(reinterpret_cast<char*>(packet->uri_path_ptr),packet->uri_path_len);
    last_query.clear();
    if(packet->options_list_ptr && packet->options_list_ptr->uri_query_ptr) {
        last_query.assign(reinterpret_cast<char*>(packet->options_list_ptr->uri_query_ptr),
                          packet->options_list_ptr->uri_query_len);
    }
    ++messages;
    sn_coap_parser_release_allocated_coap_msg_mem(handle->grs->coap,packet);
    return 1;
}
static void policy_errors()
{
    const int runtime_errors[]={MbedCloudClient::ConnectMemoryConnectFail,
        MbedCloudClient::ConnectNotRegistered,MbedCloudClient::ConnectNetworkError,
        MbedCloudClient::ConnectDnsResolvingFailed};
    for(int code:runtime_errors) {
        CHECK(edgeclient_cloud_error_is_recoverable(code));
        edge_network_policy p;
        edge_network_policy_init(&p,1000);
        edge_network_policy_cloud(&p,1001,false,edgeclient_cloud_error_is_recoverable(code));
        CHECK(!p.blocked);
        edge_network_policy_change(&p,1002,EDGE_NETWORK_DNS|EDGE_NETWORK_RESUME);
        CHECK(edge_network_policy_step(&p,3002)==(EDGE_NETWORK_DNS|EDGE_NETWORK_RESUME));
        edge_network_policy_cloud(&p,3003,true,false);
        CHECK(edge_network_policy_deadline(&p)==UINT64_MAX);
        CHECK(!edge_network_policy_step(&p,1000000));
    }
    CHECK(!edgeclient_cloud_error_is_recoverable(MbedCloudClient::ConnectInvalidParameters));
    CHECK(!edgeclient_cloud_error_is_recoverable(M2MInterface::InvalidCertificates));
    edge_network_policy p;
    edge_network_policy_init(&p,1000);
    edge_network_policy_cloud(&p,1001,false,false);
    edge_network_policy_change(&p,1002,EDGE_NETWORK_DNS|EDGE_NETWORK_RESUME);
    CHECK(!edge_network_policy_step(&p,1000000));
    CHECK(edge_network_policy_deadline(&p)==UINT64_MAX);
}
int main()
{
    policy_errors();
    CHECK(pal_init()==PAL_SUCCESS);
    ns_hal_init(NULL,65536,NULL,NULL);
    Observer observer;
    eventOS_scheduler_mutex_wait();
    {
        std::unique_ptr<M2MInterface> owned(M2MInterfaceFactory::create_interface(observer,
            String("registration-recovery-test"),String("test"),3600,0,String(""),
            M2MInterface::TCP,M2MInterface::LwIP_IPv4,String(""),String("1.0")));
        CHECK(owned);
        auto& client=static_cast<M2MInterfaceImpl&>(*owned);
        auto& nsdl=client.*get(NsdlTag{});
        nsdl_s *handle=nsdl.get_nsdl_handle();
        CHECK(handle && !sn_nsdl_is_ep_registered(handle));
        handle->sn_nsdl_tx_callback=capture;
        uint8_t loopback[]={127,0,0,1};
        nsdl.set_server_address(loopback,4,5684,SN_NSDL_ADDRESS_TYPE_IPV4);
        // Startup route/DNS/resume storms must never manufacture UPDATE state.
        for(unsigned i=0;i<64;++i) {
            client.pause();
            CHECK(reconnection_state(client)==0);
        }
        (client.*get(UpdateTag{}))(NULL);
        CHECK(messages==1 && last_path=="rd");
        CHECK(observer.error_code==M2MInterface::ErrorNone);
        // Simulate acceptance of the captured full registration by an in-memory
        // server. The registered path must continue to send a normal UPDATE.
        uint8_t location[]="rd/test-registration";
        CHECK(sn_nsdl_set_endpoint_location(handle,location,sizeof(location)-1)==0);
        handle->sn_nsdl_endpoint_registered=SN_NSDL_ENDPOINT_IS_REGISTERED;
        client.pause();
        CHECK(reconnection_state(client)==1);
        (client.*get(UpdateTag{}))(NULL);
        CHECK(messages==2 && last_path=="rd/test-registration");
        CHECK(observer.error_code==M2MInterface::ErrorNone);
        // A lost registration must fall back to full registration on every OS,
        // including callers outside the Windows/macOS recovery wrapper.
        sn_nsdl_nsp_lost(handle);
        (client.*get(UpdateTag{}))(NULL);
        CHECK(messages==3 && last_path=="rd");
        CHECK(observer.error_code==M2MInterface::ErrorNone);
        M2MInterface::Error send_error;
        CHECK(nsdl.send_update_registration(4800,&send_error));
        CHECK(send_error==M2MInterface::ErrorNone);
        CHECK(messages==4 && last_path=="rd");
        CHECK(last_query.find("lt=4800")!=std::string::npos);
        client.pause();
        CHECK(reconnection_state(client)==0);
        // NSDL invalid state/parameters return -1 before allocation. Preserve
        // a send failure instead of inventing the old allocation error 10.
        auto endpoint=nsdl.*get(EndpointTag{});
        nsdl.*get(EndpointTag{})=NULL;
        (client.*get(UpdateTag{}))(NULL);
        nsdl.*get(EndpointTag{})=endpoint;
        CHECK(observer.error_code==M2MInterface::NetworkError);
        CHECK(std::strcmp(client.error_description(),"Failed to send registration message")==0);
    }
    eventOS_scheduler_mutex_release();
    ns_event_loop_thread_stop();
    std::puts("PASS startup pause storms, full/update wire paths, lost registration fallback, accurate errors, recovery after error 10 and idle OS-event policy");
    return 0;
}
