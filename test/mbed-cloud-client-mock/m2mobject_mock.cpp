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

// Note: this macro is needed on armcc to get the the PRI*32 macros
// from inttypes.h in a C++ code.
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>

#include "mbed-client/m2mobject.h"
#include "mbed-client/m2mendpoint.h"
#include "mbed-client/m2mconstants.h"
#include "include/m2mtlvserializer.h"
#include "include/m2mtlvdeserializer.h"
#include "include/m2mreporthandler.h"
#include "mbed-trace/mbed_trace.h"
#include "mbed-client/m2mstringbuffer.h"
#include "CppUTestExt/MockSupport.h"

#include <stdlib.h>

#define BUFFER_SIZE 10
#define TRACE_GROUP "mClt"

M2MObject::M2MObject(const String &object_name, char *path, bool external_blockwise_store)
: M2MBase(object_name,
          M2MBase::Dynamic,
#ifndef DISABLE_RESOURCE_TYPE
          "",
#endif
          path,
          external_blockwise_store,
          false),
          _observation_handler(NULL)
{
    mock().actualCall("M2MObject::M2MObject")
            .withStringParameter("object_name", object_name.c_str())
            .withStringParameter("path", path)
            .withBoolParameter("external_blockwise_store", external_blockwise_store);
}

M2MObject::M2MObject(const M2MBase::lwm2m_parameters_s* static_res)
: M2MBase(static_res),
_observation_handler(NULL)
{
    mock().actualCall("M2MObject::M2MObject")
            .withPointerParameter("static_res", (void *) static_res);
}

M2MObject::~M2MObject()
{
    mock().actualCall("M2MObject::~M2MObject")
            .withPointerParameter("this", (void *) this);
}

M2MObjectInstance* M2MObject::create_object_instance(uint16_t instance_id)
{
    return (M2MObjectInstance *) mock().actualCall("M2MObject::create_object_instance")
            .withPointerParameter("this", (void *) this)
            .withUnsignedIntParameter("instance_id", instance_id)
            .returnPointerValue();
}


M2MObjectInstance* M2MObject::create_object_instance(const lwm2m_parameters_s* s)
{
    return (M2MObjectInstance *) mock().actualCall("M2MObject::create_object_instance")
            .withPointerParameter("this", (void *) this)
            .returnPointerValue();
}

bool M2MObject::remove_object_instance(uint16_t inst_id)
{
    return mock().actualCall("M2MObject::remove_object_instance")
            .withPointerParameter("this", (void *) this)
            .withUnsignedIntParameter("inst_id", inst_id)
            .returnBoolValue();
}

M2MObjectInstance* M2MObject::object_instance(uint16_t inst_id) const
{
    return (M2MObjectInstance *)mock().actualCall("M2MObject::object_instance")
            .withPointerParameter("this", (void *) this)
            .withUnsignedIntParameter("inst_id", inst_id)
            .returnPointerValue();
}

const M2MObjectInstanceList& M2MObject::instances() const
{
    return *(M2MObjectInstanceList *) mock()
        .actualCall("M2MObject::instances")
        .returnPointerValue();
}

uint16_t M2MObject::instance_count() const
{
    mock().actualCall("M2MObject::instance_count");
    return 0;
}

M2MObservationHandler* M2MObject::observation_handler() const
{
    mock().actualCall("M2MObject::observation_handler");
    return NULL;
}

void M2MObject::set_observation_handler(M2MObservationHandler *handler)
{
    mock().actualCall("M2MObject::set_observation_handler");
}

void M2MObject::add_observation_level(M2MBase::Observation observation_level)
{
    mock().actualCall("M2MObject::add_observation_level");
}

void M2MObject::remove_observation_level(M2MBase::Observation observation_level)
{
    mock().actualCall("M2MObject::remove_observation_level");
}

sn_coap_hdr_s* M2MObject::handle_get_request(nsdl_s *nsdl,
                                             sn_coap_hdr_s *received_coap_header,
                                             M2MObservationHandler *observation_handler)
{
    mock().actualCall("M2MObject::handle_get_request");
    return NULL;
}

sn_coap_hdr_s* M2MObject::handle_put_request(nsdl_s *nsdl,
                                             sn_coap_hdr_s *received_coap_header,
                                             M2MObservationHandler */*observation_handler*/,
                                             bool &/*execute_value_updated*/)
{
    mock().actualCall("M2MObject::handle_put_request");
    return NULL;
}


sn_coap_hdr_s* M2MObject::handle_post_request(nsdl_s *nsdl,
                                              sn_coap_hdr_s *received_coap_header,
                                              M2MObservationHandler *observation_handler,
                                              bool &execute_value_updated,
                                              sn_nsdl_addr_s *)
{
    mock().actualCall("M2MObject::handle_post_request");
    return NULL;
}

void M2MObject::notification_update(uint16_t obj_instance_id)
{
    mock().actualCall("M2MObject::notification_update");
}

void M2MObject::set_endpoint(M2MEndpoint *endpoint)
{
    mock().actualCall("M2MObject::set_endpoint")
            .withPointerParameter("this", (void *) this);
}

M2MEndpoint* M2MObject::get_endpoint() const
{
    return (M2MEndpoint *) mock()
            .actualCall("M2MObject::get_endpoint")
            .withPointerParameter("this", (void *) this)
            .returnPointerValue();
}

M2MBase *M2MObject::get_parent() const
{
   return (M2MBase *) mock().actualCall("M2MObject::get_parent")
            .returnPointerValue();
}
