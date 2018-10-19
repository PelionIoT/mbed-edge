// ----------------------------------------------------------------------------
// Copyright 2018 ARM Ltd.
//  
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//  
//     http://www.apache.org/licenses/LICENSE-2.0
//  
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

#ifdef CERT_RENEWAL_TEST

#ifndef __TEST_CERTIFICATE_ENROLLMENT_CLIENT_H__
#define __TEST_CERTIFICATE_ENROLLMENT_CLIENT_H__

#include "mbed-client/m2mresource.h"
#include "mbed-client/m2minterface.h"
#include "CertificateEnrollmentClient.h"
#include "eventOS_event.h"

#define TEST_CERTIFICATE_NAME_MAX_SIZE 50
#define TEST_TLV_MAX_SIZE (2 + 2 + TEST_CERTIFICATE_NAME_MAX_SIZE)


// Declarations of test only APIs. Implemented in CertificateEnrollmentClient.cpp
namespace CertificateEnrollmentClient {
void testonly_certificate_renewal_post(void *arg);
}

// Re-implement a friend class of M2MResource::M2MExecuteParameter so that we can instansiate it
class Test_M2MResource {
public:
    Test_M2MResource() : exec_param("0", "0", 0)
    {
    };
    ~Test_M2MResource()
    {
    };

    // set exec_param._value and exec_param._value_length
    void set_exec_param(uint8_t *data, size_t data_size)
    {
        memcpy(tlv_buf, data, data_size);
        exec_param._value = tlv_buf;
        exec_param._value_length = data_size;
    };
    uint8_t tlv_buf[TEST_TLV_MAX_SIZE];
    M2MResource::M2MExecuteParameter exec_param;
private:

};


namespace TestCertificateEnrollmentClient {
    using namespace CertificateEnrollmentClient;

    typedef Test_M2MResource Test_M2MExecuteParameterWrapper;

    // Test events
    enum event_type_e {
        TEST_EVENT_TYPE_INIT,
        TEST_EVENT_TYPE_RENEWAL_RESOURCE, // Certificate renewal resource 
        TEST_EVENT_TYPE_MAX = 0xff // Must fit in a uint8_t (field in the arm_event_s struct)
    };

    static void test_event_handler(arm_event_s* event);
    // Initialize MCC object, register the test event handler to dispatch test events such as network events
    void test_init();
    void test_finalize();

    // Schedule a high priority event where the data pointer points to a valid M2MResource::M2MExecuteParameter object containing cert_name
    void server_initiated_certificate_renewal(uint8_t *tlv_buff, size_t tlv_buff_length);
}


// So that the including file will use this namespace
using namespace TestCertificateEnrollmentClient;

#endif //__TEST_CERTIFICATE_ENROLLMENT_CLIENT_H__
#endif // CERT_RENEWAL_TEST
