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
#include "mbed-client/m2mobjectinstance.h"
#include "mbed-client/m2mobject.h"
#include "mbed-client/m2mconstants.h"
#include "mbed-client/m2mresource.h"
#include "mbed-client/m2mresource.h"
#include "mbed-client/m2mobservationhandler.h"
#include "mbed-client/m2mstring.h"
#include "mbed-client/m2mstringbuffer.h"
#include "include/m2mtlvserializer.h"
#include "include/m2mtlvdeserializer.h"
#include "include/m2mreporthandler.h"
#include "mbed-trace/mbed_trace.h"
#include "CppUTestExt/MockSupport.h"
#include "cpputest-custom-types/value_pointer.h"

#include <stdlib.h>

#define BUFFER_SIZE 10
#define TRACE_GROUP "mClt"

M2MObjectInstance::M2MObjectInstance(M2MObject& parent,
                                     const String &resource_type,
                                     char *path,
                                     bool external_blockwise_store)
: M2MBase("",
          M2MBase::Dynamic,
#ifndef DISABLE_RESOURCE_TYPE
          resource_type,
#endif
          path,
          external_blockwise_store,
          false),
  _parent(parent)
{
    mock().actualCall("M2MObjectInstance::M2MObjectInstance")
            .withPointerParameter("parent", (void *) &parent)
            .withStringParameter("resource_type", resource_type.c_str())
            .withStringParameter("path", path)
            .withBoolParameter("external_blockwise_store", external_blockwise_store)
            .returnPointerValue();
}

M2MObjectInstance::M2MObjectInstance(M2MObject& parent, const lwm2m_parameters_s* static_res)
: M2MBase(static_res), _parent(parent)
{
    mock().actualCall("M2MObjectInstance::M2MObjectInstance")
            .withPointerParameter("parent", (void *) &parent)
            .withPointerParameter("static_res", (void *) static_res)
            .returnPointerValue();
}

M2MObjectInstance::~M2MObjectInstance()
{
    mock().actualCall("M2MObjectInstance::~M2MObjectInstance")
        .withPointerParameter("this", this);
}

// TBD, ResourceType to the base class struct?? TODO!
M2MResource* M2MObjectInstance::create_static_resource(const lwm2m_parameters_s* static_res,
                                                       M2MResourceInstance::ResourceType type)
{
    return (M2MResource *) mock().actualCall("M2MObjectInstance::create_static_resource")
            .withPointerParameter("static_res", (void *) static_res)
            .withIntParameter("type", type)
            .returnPointerValue();
}

M2MResource* M2MObjectInstance::create_static_resource(const String &resource_name,
                                                       const String &resource_type,
                                                       M2MResourceInstance::ResourceType type,
                                                       const uint8_t *value,
                                                       const uint8_t value_length,
                                                       bool multiple_instance,
                                                       bool external_blockwise_store)
{
    ValuePointer *vp = new ValuePointer((uint8_t *) value, value_length);
    return (M2MResource *) mock().actualCall("M2MObjectInstance::create_static_resource")
            .withStringParameter("resource_name", resource_name.c_str())
            .withStringParameter("resource_type", resource_type.c_str())
            .withIntParameter("type", (int32_t) type)
            .withParameterOfType("ValuePointer", "value", vp)
            .withBoolParameter("multiple_instance", multiple_instance)
            .withBoolParameter("external_blockwise_store", external_blockwise_store)
            .returnPointerValue();
}

M2MResource* M2MObjectInstance::create_dynamic_resource(const lwm2m_parameters_s* static_res,
                                                        M2MResourceInstance::ResourceType type,
                                                        bool observable)
{
    return (M2MResource *) mock().actualCall("M2MObjectInstance::create_dynamic_resource")
            .withPointerParameter("static_res", (void *) static_res)
            .withIntParameter("type", (int32_t) type)
            .returnPointerValue();
}

M2MResource* M2MObjectInstance::create_dynamic_resource(const String &resource_name,
                                                const String &resource_type,
                                                M2MResourceInstance::ResourceType type,
                                                bool observable,
                                                bool multiple_instance,
                                                bool external_blockwise_store)
{
    return (M2MResource *) mock().actualCall("M2MObjectInstance::create_dynamic_resource")
            .withStringParameter("resource_name", resource_name.c_str())
            .withStringParameter("resource_type", resource_type.c_str())
            .withIntParameter("type", (int32_t) type)
            .withBoolParameter("observable", observable)
            .withBoolParameter("multiple_instance", multiple_instance)
            .withBoolParameter("external_blockwise_store", external_blockwise_store)
            .returnPointerValue();
}

M2MResourceInstance* M2MObjectInstance::create_static_resource_instance(const String &resource_name,
                                                                        const String &resource_type,
                                                                        M2MResourceInstance::ResourceType type,
                                                                        const uint8_t *value,
                                                                        const uint8_t value_length,
                                                                        uint16_t instance_id,
                                                                        bool external_blockwise_store)
{
    ValuePointer *vp = new ValuePointer((uint8_t *) value, value_length);
    return (M2MResourceInstance *) mock().actualCall("M2MObjectInstance::create_static_resource_instance")
            .withStringParameter("resource_name", resource_name.c_str())
            .withStringParameter("resource_type", resource_type.c_str())
            .withIntParameter("type", (int32_t) type)
            .withParameterOfType("ValuePointer", "value" , (void *) vp)
            .withUnsignedIntParameter("instance_id", instance_id)
            .withBoolParameter("external_blockwise_store", external_blockwise_store)
            .returnPointerValue();
}

M2MResourceInstance* M2MObjectInstance::create_dynamic_resource_instance(const String &resource_name,
                                                                         const String &resource_type,
                                                                         M2MResourceInstance::ResourceType type,
                                                                         bool observable,
                                                                         uint16_t instance_id,
                                                                         bool external_blockwise_store)
{
    return (M2MResourceInstance *) mock().actualCall("M2MObjectInstance::create_dynamic_resource_instance")
            .withStringParameter("resource_name", resource_name.c_str())
            .withStringParameter("resource_type", resource_type.c_str())
            .withIntParameter("type", (int32_t) type)
            .withBoolParameter("observable", observable)
            .withBoolParameter("external_blockwise_store", external_blockwise_store)
            .returnPointerValue();
}

bool M2MObjectInstance::remove_resource(const String &resource_name)
{
    return mock().actualCall("M2MObjectInstance::remove_resource")
            .returnBoolValue();
}

bool M2MObjectInstance::remove_resource(const char *resource_name)
{
    return mock().actualCall("M2MObjectInstance::remove_resource")
            .withStringParameter("resource_name", resource_name)
            .returnBoolValue();
}

bool M2MObjectInstance::remove_resource_instance(const String &resource_name,
                                                 uint16_t inst_id)
{
    return mock().actualCall("M2MObjectInstance::remove_resource_instance")
            .withStringParameter("resource_name", resource_name.c_str())
            .returnBoolValue();

}

M2MResource* M2MObjectInstance::resource(const String &resource_name) const
{
    return (M2MResource *) mock().actualCall("M2MObjectInstance::resource")
            .withPointerParameter("this", (void *) this)
            .withStringParameter("resource_name", resource_name.c_str())
            .returnPointerValue();
}

M2MResource* M2MObjectInstance::resource(const char *resource_name) const
{
    return (M2MResource *) mock().actualCall("M2MObjectInstance::resource")
            .withPointerParameter("this", (void *) this)
            .withStringParameter("resource_name", resource_name)
            .returnPointerValue();
}

const M2MResourceList& M2MObjectInstance::resources() const
{
    return *(M2MResourceList *) mock()
        .actualCall("M2MObjectInstance::resources")
        .returnPointerValue();
}

uint16_t M2MObjectInstance::resource_count() const
{
    return mock().actualCall("M2MObjectInstance::resource_count")
            .returnUnsignedIntValue();
}

uint16_t M2MObjectInstance::resource_count(const String& resource) const
{
    return mock().actualCall("M2MObjectInstance::resource_count")
            .withStringParameter("resource", resource.c_str())
            .returnUnsignedIntValue();
}

uint16_t M2MObjectInstance::resource_count(const char *resource) const
{
    return mock().actualCall("M2MObjectInstance::resource_count")
            .withStringParameter("resource", resource)
            .returnUnsignedIntValue();
}

M2MObservationHandler* M2MObjectInstance::observation_handler() const
{
    return (M2MObservationHandler *) mock().actualCall("M2MObjectInstance::observation_handler")
            .returnPointerValue();
}

void M2MObjectInstance::set_observation_handler(M2MObservationHandler *handler)
{
    mock().actualCall("M2MObjectInstance::set_observation_handler")
            .withPointerParameter("handler", handler);
}

void M2MObjectInstance::add_observation_level(M2MBase::Observation observation_level)
{
    mock().actualCall("M2MObjectInstance::add_observation_level")
            .withIntParameter("observation_level", (int32_t) observation_level);
}

void M2MObjectInstance::remove_observation_level(M2MBase::Observation observation_level)
{
    mock().actualCall("M2MObjectInstance::remove_observation_level")
            .withIntParameter("observation_level", (int32_t) observation_level);
}

sn_coap_hdr_s* M2MObjectInstance::handle_get_request(nsdl_s *nsdl,
                                                     sn_coap_hdr_s *received_coap_header,
                                                     M2MObservationHandler *observation_handler)
{
    return (sn_coap_hdr_s *) mock().actualCall("M2MObjectInstance::handle_get_request")
            .returnPointerValue();
}

sn_coap_hdr_s* M2MObjectInstance::handle_put_request(nsdl_s *nsdl,
                                                     sn_coap_hdr_s *received_coap_header,
                                                     M2MObservationHandler *observation_handler,
                                                     bool &/*execute_value_updated*/)
{
    return (sn_coap_hdr_s *) mock().actualCall("M2MObjectInstance::handle_put_request")
            .returnPointerValue();
}

sn_coap_hdr_s* M2MObjectInstance::handle_post_request(nsdl_s *nsdl,
                                                      sn_coap_hdr_s *received_coap_header,
                                                      M2MObservationHandler *observation_handler,
                                                      bool &execute_value_updated,
                                                      sn_nsdl_addr_s *)
{
    return (sn_coap_hdr_s *) mock().actualCall("M2MObjectInstance::handle_post_request")
            .returnPointerValue();
}

void M2MObjectInstance::notification_update(M2MBase::Observation observation_level)
{
    mock().actualCall("M2MObjectInstance::notification_update");
}

M2MBase::DataType M2MObjectInstance::convert_resource_type(M2MResourceInstance::ResourceType type)
{
    return (M2MBase::DataType) mock().actualCall("M2MObjectInstance::convert_resource_type")
            .withIntParameter("type", (int32_t) type)
            .returnIntValue();
}

M2MBase *M2MObjectInstance::get_parent() const
{
   return (M2MBase *) mock().actualCall("M2MObjectInstance::get_parent")
            .returnPointerValue();
}
