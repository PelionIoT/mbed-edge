/* SPDX-License-Identifier: Apache-2.0 */
#include "CppUTest/TestHarness.h"
#include "edge-client/network_recovery_error.h"
#include "edge-core/edge_network_recovery.h"
TEST_GROUP(NetworkRecovery) {};
TEST(NetworkRecovery, RuntimeFailuresAllowDnsAndResumeRecovery)
{
    const int codes[]={MbedCloudClient::ConnectMemoryConnectFail,
        MbedCloudClient::ConnectNotRegistered,MbedCloudClient::ConnectDnsResolvingFailed};
    for(unsigned i=0;i<sizeof(codes)/sizeof(codes[0]);++i) {
        CHECK(edgeclient_cloud_error_is_recoverable(codes[i]));
        edge_network_policy p;
        edge_network_policy_init(&p,1000);
        edge_network_policy_cloud(&p,1001,false,edgeclient_cloud_error_is_recoverable(codes[i]));
        CHECK(!p.blocked);
        edge_network_policy_change(&p,1002,EDGE_NETWORK_DNS|EDGE_NETWORK_RESUME);
        LONGS_EQUAL(EDGE_NETWORK_DNS|EDGE_NETWORK_RESUME,edge_network_policy_step(&p,3002));
        edge_network_policy_cloud(&p,3003,true,false);
        CHECK(edge_network_policy_deadline(&p)==UINT64_MAX);
    }
}
TEST(NetworkRecovery, CredentialAndConfigurationFailuresRemainGuarded)
{
    CHECK(!edgeclient_cloud_error_is_recoverable(M2MInterface::InvalidCertificates));
    CHECK(!edgeclient_cloud_error_is_recoverable(MbedCloudClient::ConnectInvalidParameters));
    edge_network_policy p;
    edge_network_policy_init(&p,1000);
    edge_network_policy_cloud(&p,1001,false,false);
    edge_network_policy_change(&p,1002,EDGE_NETWORK_DNS|EDGE_NETWORK_RESUME);
    LONGS_EQUAL(0,edge_network_policy_step(&p,3002));
    CHECK(edge_network_policy_deadline(&p)==UINT64_MAX);
}
