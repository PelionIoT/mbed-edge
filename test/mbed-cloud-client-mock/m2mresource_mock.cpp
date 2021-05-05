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
#include "mbed-client/m2mconstants.h"
#include "mbed-client/m2mresource.h"
#include "mbed-client/m2mobservationhandler.h"
#include "include/m2mreporthandler.h"
#include "include/m2mtlvserializer.h"
#include "include/m2mtlvdeserializer.h"
#include "mbed-trace/mbed_trace.h"
#include "CppUTestExt/MockSupport.h"
#include "cpputest-custom-types/value_pointer.h"

#include <stdlib.h>

#define TRACE_GROUP "mClt"

M2MResource::M2MResource(M2MObjectInstance &parent,
                         const String &resource_name,
                         M2MBase::Mode resource_mode,
                         const String &resource_type,
                         M2MBase::DataType type,
                         const uint8_t *value,
                         const uint8_t value_length,
                         char *path,
                         bool multiple_instance,
                         bool external_blockwise_store)
    : M2MResourceBase(resource_name,
                      resource_mode,
                      resource_type,
                      type,
                      value,
                      value_length,
                      path,
                      external_blockwise_store,
                      multiple_instance),
      _parent(parent)
#ifndef DISABLE_DELAYED_RESPONSE
  ,_delayed_token(NULL),
  _delayed_token_len(0),
  _delayed_response(false)
#endif
{
    ValuePointer value_pointer((uint8_t*) value, value_length);
    mock().actualCall("M2MResource::M2MResource")
            .withPointerParameter("parent", (void *) &parent)
            .withStringParameter("resource_name", resource_name.c_str())
            .withIntParameter("resource_mode", (int)resource_mode)
            .withStringParameter("resource_type", resource_type.c_str())
            .withIntParameter("type", (int)type)
            .withParameterOfType("ValuePointer", "value", (void *) &value_pointer)
            .withStringParameter("path", path)
            .withBoolParameter("multiple_instance", multiple_instance)
            .withBoolParameter("external_blockwise_store", external_blockwise_store);
}

M2MResource::M2MResource(M2MObjectInstance &parent, const lwm2m_parameters_s *s, M2MBase::DataType type)
    : M2MResourceBase(s, type), _parent(parent)
#ifndef DISABLE_DELAYED_RESPONSE
  ,_delayed_token(NULL),
  _delayed_token_len(0),
  _delayed_response(false)
#endif
{
}

M2MResource::M2MResource(M2MObjectInstance &parent,
                         const String &resource_name,
                         M2MBase::Mode resource_mode,
                         const String &resource_type,
                         M2MBase::DataType type,
                         bool observable,
                         char *path,
                         bool multiple_instance,
                         bool external_blockwise_store)
    : M2MResourceBase(resource_name,
                      resource_mode,
                      resource_type,
                      type,
                      path,
                      external_blockwise_store,
                      multiple_instance),
      _parent(parent)
#ifndef DISABLE_DELAYED_RESPONSE
  ,_delayed_token(NULL),
  _delayed_token_len(0),
  _delayed_response(false)
#endif
{
}

M2MResource::~M2MResource()
{
    mock().actualCall("~M2MResource")
        .withPointerParameter("this", this);
}

bool M2MResource::supports_multiple_instances() const
{
    return mock().actualCall("supports_multiple_instances")
            .returnBoolValue();
}

#ifndef DISABLE_DELAYED_RESPONSE
void M2MResource::set_delayed_response(bool delayed_response)
{
    mock().actualCall("M2MResource::set_delayed_response")
            .withPointerParameter("this", (void *) this)
            .withBoolParameter("delayed_response", (bool) delayed_response);
}

bool M2MResource::send_delayed_post_response(sn_coap_msg_code_e code)
{
    return mock()
            .actualCall("M2MResource::send_delayed_post_response")
            .withPointerParameter("this", (void *) this)
            .returnBoolValue();
}

void M2MResource::get_delayed_token(uint8_t *&token, uint8_t &token_length)
{
    (void) token;
    (void) token_length;
    mock().actualCall("get_delayed_token");
}
#endif

bool M2MResource::remove_resource_instance(uint16_t inst_id)
{
    (void) inst_id;
    return mock().actualCall("remove_resource_instance")
            .returnBoolValue();
}

M2MResourceInstance* M2MResource::resource_instance(uint16_t inst_id) const
{
    (void) inst_id;
    mock().actualCall("resource_instance");
    return NULL;
}

const M2MResourceInstanceList& M2MResource::resource_instances() const
{
    return *(M2MResourceInstanceList *)mock().actualCall("resource_instances")
            .returnPointerValue();
}

uint16_t M2MResource::resource_instance_count() const
{
    return mock().actualCall("M2MResource::resource_instance_count")
        .returnUnsignedIntValue();
}

#ifndef DISABLE_DELAYED_RESPONSE
bool M2MResource::delayed_response() const
{
    return mock().actualCall("M2MResource::delayed_response")
        .returnBoolValue();
}
#endif

M2MObservationHandler* M2MResource::observation_handler() const
{
    return (M2MObservationHandler *)mock().actualCall("M2MResource::observation_handler")
        .withPointerParameter("this", (void *) this)
        .returnPointerValue();
}

void M2MResource::set_observation_handler(M2MObservationHandler *handler)
{
    (void) handler;
    mock().actualCall("M2MResource::set_observation_handler")
        .withPointerParameter("this", this);
}

bool M2MResource::handle_observation_attribute(const char *query)
{
    (void) query;
    return mock().actualCall("M2MResource::handle_observation_attribute")
        .withPointerParameter("this", this)
        .returnBoolValue();
}

void M2MResource::add_observation_level(M2MBase::Observation observation_level)
{
    (void) observation_level;
    mock().actualCall("M2MResource::add_observation_level")
        .withPointerParameter("this", this);
}

void M2MResource::remove_observation_level(M2MBase::Observation observation_level)
{
    (void) observation_level;
    mock().actualCall("M2MResource::remove_observation_level")
        .withPointerParameter("this", this);
}

void M2MResource::add_resource_instance(M2MResourceInstance *res)
{
    mock().actualCall("M2MResource::add_resource_instance")
        .withPointerParameter("this", this);
}

sn_coap_hdr_s* M2MResource::handle_get_request(nsdl_s *nsdl,
                                               sn_coap_hdr_s *received_coap_header,
                                               M2MObservationHandler *observation_handler)
{
    return NULL;
}

sn_coap_hdr_s* M2MResource::handle_put_request(nsdl_s *nsdl,
                                               sn_coap_hdr_s *received_coap_header,
                                               M2MObservationHandler *observation_handler,
                                               bool &execute_value_updated)
{
    return NULL;
}

sn_coap_hdr_s *M2MResource::handle_post_request(nsdl_s *nsdl,
                                                sn_coap_hdr_s *received_coap_header,
                                                M2MObservationHandler * /* observation_handler */,
                                                bool & /* execute_value_updated */,
                                                sn_nsdl_addr_s *address)
{
    return NULL;
}

M2MObjectInstance& M2MResource::get_parent_object_instance() const
{
    return *(M2MObjectInstance *) mock()
                    .actualCall("M2MResource::get_parent_object_instance")
                    .withPointerParameter("this", (void *) this)
                    .returnPointerValue();
}

uint16_t M2MResource::object_instance_id() const
{
    return mock()
            .actualCall("M2MResource::object_instance_id")
            .withPointerParameter("this", (void *) this)
            .returnUnsignedIntValue();
}

M2MResource& M2MResource::get_parent_resource() const
{
    return *(M2MResource *) mock()
                    .actualCall("M2MResource::get_parent_resource")
                    .withPointerParameter("this", (void *) this)
                    .returnPointerValue();
}

const char* M2MResource::object_name() const
{
    return mock().actualCall("M2MResource::object_name")
            .returnStringValue();
}

#ifdef MEMORY_OPTIMIZED_API
M2MResource::M2MExecuteParameter::M2MExecuteParameter(const char *object_name, const char *resource_name,
                                                        uint16_t object_instance_id) :
_object_name(object_name),
_resource_name(resource_name),
_value(NULL),
_value_length(0),
_object_instance_id(object_instance_id)
{
#else
M2MResource::M2MExecuteParameter::M2MExecuteParameter(const String &object_name, const String &resource_name,
                                                        uint16_t object_instance_id) :
_object_name(object_name),
_resource_name(resource_name),
_value(NULL),
_value_length(0),
_object_instance_id(object_instance_id)
{
#endif
}

// These could be actually changed to be inline ones, as it would likely generate
// smaller code at application side.

const uint8_t *M2MResource::M2MExecuteParameter::get_argument_value() const
{
    return (uint8_t *) mock().actualCall("M2MResource::M2MExecuteParameter::get_argument_value")
            .returnPointerValue();
}

uint16_t M2MResource::M2MExecuteParameter::get_argument_value_length() const
{
    return (uint16_t) mock()
            .actualCall("M2MResource::M2MExecuteParameter::get_argument_value_length")
            .returnUnsignedIntValue();
}

#ifdef MEMORY_OPTIMIZED_API
const char* M2MResource::M2MExecuteParameter::get_argument_object_name() const
{
    mock().actualCall("M2MResource::M2MExecuteParameter::get_argument_object_name");
    return NULL;
}

const char* M2MResource::M2MExecuteParameter::get_argument_resource_name() const
{
    mock().actualCall("M2MResource::M2MExecuteParameter::get_argument_resource_name");
    return NULL;
}
#else
const String& M2MResource::M2MExecuteParameter::get_argument_object_name() const
{
    String *s = new String();
    mock().actualCall("M2MResource::M2MExecuteParameter::get_argument_object_name");
    return *s;
}

const String& M2MResource::M2MExecuteParameter::get_argument_resource_name() const
{
    String *s = new String();
    mock().actualCall("M2MResource::M2MExecuteParameter::get_argument_resource_name");
    return *s;
}
#endif

uint16_t M2MResource::M2MExecuteParameter::get_argument_object_instance_id() const
{
    mock().actualCall("M2MResource::M2MExecuteParameter::get_argument_object_instance_id");
    return 0;
}

M2MBase *M2MResource::get_parent() const
{
   return (M2MBase *) mock().actualCall("M2MResource::get_parent")
            .returnPointerValue();
}

#ifdef MBED_EDGE_SUBDEVICE_FOTA
bool M2MResource::get_manifest_check_status()
{
    return 1;//mock().actualCall("M2MResource::get_manifest_check_status").returnBoolValue();
}
void M2MResource::set_manifest_check_status(bool status)
{
    mock().actualCall("M2MResource::set_manifest_check_status");
}
M2MResource * M2MResource::M2MExecuteParameter::get_resource()
{
    mock().actualCall("M2MExecuteParameter::get_resource");
    return NULL;
}
#endif // MBED_EDGE_SUBDEVICE_FOTA
