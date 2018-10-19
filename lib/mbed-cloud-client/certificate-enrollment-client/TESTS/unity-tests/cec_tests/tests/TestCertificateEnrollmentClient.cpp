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

#include "TestCertificateEnrollmentClient.h"
#include "mbed-client/m2mresource.h"
#include "mbed-cloud-client/MbedCloudClient.h"
#include "include/ServiceClient.h"
#include "eventOS_scheduler.h"
#include "eventOS_event.h"
#include "ce_tlv.h"
#include "unity_fixture.h"


#include "mbed-client/m2mvector.h"

// ID of the handler we register to the MbedCloudClient event loop
static int8_t test_handler_id = -1;

typedef Vector<M2MBase*> M2MBaseList;

MbedCloudClient *g_mcc;

static bool _test_is_initialized = false;

// This emulates the event handler of mbed cloud client
void TestCertificateEnrollmentClient::test_event_handler(arm_event_s* event)
{
    printf("in test event handler\n\n");
    switch (event->event_type) {
        case TEST_EVENT_TYPE_INIT:
            // Nothing to do
            break;
        case TEST_EVENT_TYPE_RENEWAL_RESOURCE:
            // Call resource callback
            CertificateEnrollmentClient::testonly_certificate_renewal_post((void *) &(((Test_M2MExecuteParameterWrapper *)(event->data_ptr))->exec_param) );
            delete (Test_M2MExecuteParameterWrapper *)(event->data_ptr);
    }

}

void TestCertificateEnrollmentClient::server_initiated_certificate_renewal(uint8_t *tlv_buff, size_t tlv_buff_length)
{
    Test_M2MExecuteParameterWrapper *exec_param;

    exec_param = new Test_M2MExecuteParameterWrapper();
    exec_param->set_exec_param(tlv_buff, tlv_buff_length);

    arm_event_s event = {
        .receiver = test_handler_id, // ID we got when creating our handler
        .sender = 0, // Which tasklet sent us the event is irrelevant to us 
        .event_type = TEST_EVENT_TYPE_RENEWAL_RESOURCE, // Indicate event type 
        .event_id = 0, // We currently do not need an ID for a specific event - event type is enough
        .data_ptr = (void *)exec_param, // pointer to the M2MResource::M2MExecuteParameter object that will be used by the resource callback
        .priority = ARM_LIB_HIGH_PRIORITY_EVENT, // Network level priority
        .event_data = 0, // Not used
    };

    eventOS_event_send(&event);
}

void TestCertificateEnrollmentClient::test_init()
{
    if (!_test_is_initialized) {
        // Create MbedCloudClient object - this will start the event loop
        g_mcc = new MbedCloudClient();
        TEST_ASSERT_NOT_EQUAL(g_mcc, NULL);

        // Create an object list and fill it.
        // Also do other initializations
        M2MBaseList obj_list;
        CertificateEnrollmentClient::init(obj_list, NULL);

        // Add the object so that g_mcc has access to them and may release their memory when done
        g_mcc->add_objects(obj_list);

        // Register test event handler
        eventOS_scheduler_mutex_wait();
        if (test_handler_id == -1) { // Register the handler only if it hadn't been registered before
            test_handler_id = eventOS_event_handler_create(test_event_handler, TEST_EVENT_TYPE_INIT);
        }
        eventOS_scheduler_mutex_release();

        _test_is_initialized = true;
    }
}

void TestCertificateEnrollmentClient::test_finalize()
{
    if (_test_is_initialized) {
        delete g_mcc;
        CertificateEnrollmentClient::finalize();
        _test_is_initialized = false;
    }
}

#endif // CERT_RENEWAL_TEST
