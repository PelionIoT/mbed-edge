/*
 * Copyright (c) 2015 ARM Limited. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <stdlib.h>
#include "mbed-client/m2mresourcebase.h"
#include "mbed-client/m2mconstants.h"
#include "mbed-client/m2mobservationhandler.h"
#include "mbed-client/m2mobject.h"
#include "mbed-client/m2mobjectinstance.h"
#include "include/m2mcallbackstorage.h"
#include "include/m2mreporthandler.h"
#include "include/nsdllinker.h"
#include "include/m2mtlvserializer.h"
#include "mbed-client/m2mblockmessage.h"
#include "mbed-trace/mbed_trace.h"
#include "CppUTestExt/MockSupport.h"
#include "cpputest-custom-types/value_pointer.h"
#include "stdlib.h"

#define TRACE_GROUP "mClt"

M2MResourceBase::M2MResourceBase(const String &res_name,
                                 M2MBase::Mode resource_mode,
                                 const String &resource_type,
                                 M2MBase::DataType type,
                                 char *path,
                                 bool external_blockwise_store,
                                 bool multiple_instance)
    : M2MBase(res_name,
              resource_mode,
#ifndef DISABLE_RESOURCE_TYPE
              resource_type,
#endif
              path,
              external_blockwise_store,
              multiple_instance,
              type),
#ifndef DISABLE_BLOCK_MESSAGE
      _block_message_data(NULL)
#endif
{
    mock().actualCall("M2MResourceBasei::M2MResourceBase");
}

M2MResourceBase::M2MResourceBase(
                                         const String &res_name,
                                         M2MBase::Mode resource_mode,
                                         const String &resource_type,
                                         M2MBase::DataType type,
                                         const uint8_t *value,
                                         const uint8_t value_length,
                                         char* path,
                                         bool external_blockwise_store,
                                         bool multiple_instance)
: M2MBase(res_name,
          resource_mode,
#ifndef DISABLE_RESOURCE_TYPE
          resource_type,
#endif
          path,
          external_blockwise_store,
          multiple_instance,
          type)
#ifndef DISABLE_BLOCK_MESSAGE
 ,_block_message_data(NULL)
#endif
{
    mock().actualCall("M2MResourceBase::M2MResourceBase");
}

M2MResourceBase::M2MResourceBase(
                                         const lwm2m_parameters_s* s,
                                         M2MBase::DataType /*type*/)
: M2MBase(s)
#ifndef DISABLE_BLOCK_MESSAGE
  ,_block_message_data(NULL)
#endif
{
    mock().actualCall("M2MResourceBase::M2MResourceBase");
}

M2MResourceBase::~M2MResourceBase()
{
    mock().actualCall("M2MResourceBase::~M2MResourceBase");
}

M2MResourceBase::ResourceType M2MResourceBase::resource_instance_type() const
{
    return (M2MResourceBase::ResourceType)mock().actualCall("M2MResourceBase::resource_instance_type").returnUnsignedIntValue();
}


bool M2MResourceBase::set_execute_function(execute_callback callback)
{
    mock().actualCall("M2MResourceBase::set_execute_function");
    (void) M2MCallbackStorage::remove_callback(
            *this, M2MCallbackAssociation::M2MResourceInstanceExecuteCallback);
    execute_callback* new_callback = new execute_callback(callback);

    return M2MCallbackStorage::add_callback(
            *this, new_callback, M2MCallbackAssociation::M2MResourceInstanceExecuteCallback);
}

bool M2MResourceBase::set_execute_function(execute_callback_2 callback)
{
    mock().actualCall("M2MResourceBase::set_execute_function");
    return false;
}

void M2MResourceBase::clear_value()
{
    mock().actualCall("M2MResourceBase::clear_value");
}

bool M2MResourceBase::set_value(int64_t value)
{
    mock().actualCall("M2MResourceBase::set_value");
    return false;
}

bool M2MResourceBase::set_value(const uint8_t *value, const uint32_t value_length)
{
    mock().actualCall("M2MResourceBase::set_value");
    // normally the mock will own the value
    if (value) {
        free((void *) value);
    }
    return false;
}

bool M2MResourceBase::set_value_raw(uint8_t *value,
                                const uint32_t value_length)

{
    mock().actualCall("M2MResourceBase::set_value_raw");
    // normally the mock will own the value
    if (value) {
        free(value);
    }
    return false;
}

void M2MResourceBase::update_value(uint8_t *value, const uint32_t value_length)
{
    ValuePointer vp(value, value_length);
    mock().actualCall("M2MResourceBase::update_value")
            .withParameterOfType("ValuePointer", "value", &vp);
    // normally the mock will own the value
    if (value) {
        free(value);
    }
}

void M2MResourceBase::report()
{
    mock().actualCall("M2MResourceBase::report");
}

bool M2MResourceBase::has_value_changed(const uint8_t* value, const uint32_t value_len)
{
    mock().actualCall("M2MResourceBase::has_value_changed");
    return false;
}

void M2MResourceBase::report_value_change()
{
    mock().actualCall("M2MResourceBase::report_value_change");
}

void M2MResourceBase::execute(void *arguments)
{
    mock().actualCall("M2MResourceBase::execute");
}

void M2MResourceBase::get_value(uint8_t *&value, uint32_t &value_length)
{
    mock().actualCall("M2MResourceBase::get_value")
        .withPointerParameter("this", (void *) this)
        .withOutputParameter("value", &value)
        .withOutputParameter("value_length", &value_length);
}

int64_t M2MResourceBase::get_value_int() const
{
    mock().actualCall("M2MResourceBase::get_value_int");
    return 0;
}

String M2MResourceBase::get_value_string() const
{
    mock().actualCall("M2MResourceBase::get_value_string");
    return String("");
}

uint8_t* M2MResourceBase::value() const
{
    mock().actualCall("M2MResourceBase::value");
    return NULL;
}

uint32_t M2MResourceBase::value_length() const
{
    return mock().actualCall("M2MResourceBase::value_length")
            .returnUnsignedIntValue();

}

void M2MResourceBase::set_value_set_callback(value_set_callback callback)
{
    mock().actualCall("M2MResourceBase::set_value_set_callback");
}

sn_coap_hdr_s* M2MResourceBase::handle_get_request(nsdl_s *nsdl,
                                               sn_coap_hdr_s *received_coap_header,
                                               M2MObservationHandler *observation_handler)
{
    mock().actualCall("M2MResourceBase::handle_get_request");
    return NULL;
}

sn_coap_hdr_s* M2MResourceBase::handle_put_request(nsdl_s *nsdl,
                                               sn_coap_hdr_s *received_coap_header,
                                               M2MObservationHandler *observation_handler,
                                               bool &execute_value_updated)
{
    mock().actualCall("M2MResourceBase::handle_put_request");
    return NULL;
}


#ifndef DISABLE_BLOCK_MESSAGE

M2MBlockMessage* M2MResourceBase::block_message() const
{
    mock().actualCall("M2MResourceBase::block_message");
    return NULL;
}

bool M2MResourceBase::set_incoming_block_message_callback(incoming_block_message_callback callback)
{
    mock().actualCall("M2MResourceBase::set_incoming_block_message_callback");
    return false;
}

bool M2MResourceBase::set_outgoing_block_message_callback(outgoing_block_message_callback callback)
{
    return mock().actualCall("M2MResourceBase::set_outgoing_block_message_callback")
            .returnBoolValue();
}
#endif

M2MResourceBase::ResourceType M2MResourceBase::convert_data_type(M2MBase::DataType type) const
{
    mock().actualCall("M2MResourceBase::convert_data_type");
    return (M2MResourceBase::ResourceType) 0;

}

#ifdef MBED_EDGE_SUBDEVICE_FOTA
void M2MResourceBase::publish_value_in_registration_msg(bool publish_value)
{
    mock().actualCall("M2MResourceBase::publish_value_in_registration_msg");
}
#endif // MBED_EDGE_SUBDEVICE_FOTA