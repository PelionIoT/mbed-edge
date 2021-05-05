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
#include "mbed-client/m2mendpoint.h"
#include "mbed-client/m2mobject.h"
#include "mbed-client/m2mconstants.h"
#include "include/m2mtlvserializer.h"
#include "include/m2mtlvdeserializer.h"
#include "include/m2mreporthandler.h"
#include "mbed-trace/mbed_trace.h"
#include "mbed-client/m2mstringbuffer.h"
#include "mbed-client/m2mstring.h"
#include "nsdl-c/sn_nsdl_lib.h"
#include "CppUTestExt/MockSupport.h"

#include <stdlib.h>

#define BUFFER_SIZE 10
#define TRACE_GROUP "mClt"

M2MEndpoint::M2MEndpoint(const String &object_name, char *path)
: M2MBase(object_name,
          M2MBase::Dynamic,
#ifndef DISABLE_RESOURCE_TYPE
          "",
#endif
          path,
          false,
          false), _observation_handler(NULL)
{
    mock().actualCall("M2MEndpoint::M2MEndpoint")
            .withStringParameter("object_name", object_name.c_str())
            .withStringParameter("path", path);
}


M2MEndpoint::~M2MEndpoint()
{
    mock().actualCall("M2MEndpoint::~M2MEndpoint")
            .withPointerParameter("this", (void *) this);
}

M2MObject* M2MEndpoint::create_object(const String &name)
{
    return (M2MObject *) mock()
            .actualCall("M2MEndpoint::create_object")
            .withPointerParameter("this", (void *) this)
            .withStringParameter("name", name.c_str())
            .returnPointerValue();
}

bool M2MEndpoint::remove_object(const String &name)
{
    return (bool) mock().actualCall("M2MEndpoint::remove_object")
            .withStringParameter("name", name.c_str())
            .returnIntValue();
}

M2MObject* M2MEndpoint::object(const String &name) const
{
    return (M2MObject *) mock().actualCall("M2MEndpoint::object")
            .withStringParameter("name", name.c_str())
            .returnPointerValue();
}

const M2MObjectList& M2MEndpoint::objects() const
{
    return *(M2MObjectList*) mock()
        .actualCall("M2MEndpoint::objects")
        .returnPointerValue();
}

uint16_t M2MEndpoint::object_count() const
{
    return (uint16_t) mock().actualCall("M2MEndpoint::object_count")
            .returnIntValue();
}

M2MObservationHandler* M2MEndpoint::observation_handler() const
{
    return (M2MObservationHandler *) mock().actualCall("M2MEndpoint::observation_handler")
            .returnPointerValue();
}

void M2MEndpoint::set_observation_handler(M2MObservationHandler *handler)
{
    mock().actualCall("M2MEndpoint::set_observation_handler");
}

void M2MEndpoint::add_observation_level(M2MBase::Observation observation_level)
{
    mock().actualCall("M2MEndpoint::add_observation_level");
}

void M2MEndpoint::remove_observation_level(M2MBase::Observation observation_level)
{
    mock().actualCall("M2MEndpoint::remove_observation_level");
}

sn_coap_hdr_s* M2MEndpoint::handle_get_request(nsdl_s *nsdl,
                                             sn_coap_hdr_s *received_coap_header,
                                             M2MObservationHandler *observation_handler)
{
    mock().actualCall("M2MEndpoint::handle_get_request");
    return NULL;
}

sn_coap_hdr_s* M2MEndpoint::handle_put_request(nsdl_s *nsdl,
                                             sn_coap_hdr_s *received_coap_header,
                                             M2MObservationHandler */*observation_handler*/,
                                             bool &/*execute_value_updated*/)
{
    mock().actualCall("M2MEndpoint::handle_put_request");
    return NULL;
}


sn_coap_hdr_s* M2MEndpoint::handle_post_request(nsdl_s *nsdl,
                                              sn_coap_hdr_s *received_coap_header,
                                              M2MObservationHandler *observation_handler,
                                              bool &execute_value_updated,
                                              sn_nsdl_addr_s *)
{
    mock().actualCall("M2MEndpoint::handle_post_request");
    return NULL;
}

void M2MEndpoint::set_context(void *ctx)
{
    mock().actualCall("M2MEndpoint::set_context")
            .withPointerParameter("ctx", ctx);
}

void *M2MEndpoint::get_context() const
{
    return mock()
            .actualCall("M2MEndpoint::get_context")
            .withPointerParameter("this", (void *) this)
            .returnPointerValue();
}

void M2MEndpoint::set_changed()
{
   mock().actualCall("M2MEndpoint::set_changed");
}

void M2MEndpoint::clear_changed()
{
   mock().actualCall("M2MEndpoint::clear_changed");
}

bool M2MEndpoint::get_changed() const
{
   return mock().actualCall("M2MEndpoint::get_changed")
            .returnBoolValue();
}

void M2MEndpoint::set_deleted()
{
    mock().actualCall("M2MEndpoint::set_deleted");
}

bool M2MEndpoint::is_deleted()
{
    return mock().actualCall("M2MEndpoint::is_deleted").returnBoolValue();
}
