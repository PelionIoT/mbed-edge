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

#include "mbed-client/m2mbase.h"
#include "mbed-client/m2mobservationhandler.h"
#include "mbed-client/m2mconstants.h"
#include "mbed-client/m2mtimer.h"

#include "mbed-client/m2mendpoint.h"
#include "mbed-client/m2mobject.h"
#include "mbed-client/m2mobjectinstance.h"
#include "mbed-client/m2mresource.h"

#include "include/m2mreporthandler.h"
#include "include/nsdlaccesshelper.h"
#include "include/m2mcallbackstorage.h"
#include "mbed-trace/mbed_trace.h"

#include <assert.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "CppUTestExt/MockSupport.h"
#include "cpputest-custom-types/value_pointer.h"

#define TRACE_GROUP "mClt"

M2MBase::M2MBase(const String& resource_name,
                 M2MBase::Mode mode,
#ifndef DISABLE_RESOURCE_TYPE
                 const String &resource_type,
#endif
                 char *path,
                 bool external_blockwise_store,
                 bool multiple_instance,
                 M2MBase::DataType type)
:
  _sn_resource(NULL),
  _report_handler(NULL)
{
    mock().actualCall("M2MBase::M2MBase")
        .withStringParameter("resource_name", resource_name.c_str())
        .withIntParameter("mode", (int) mode)
#ifndef DISABLE_RESOURCE_TYPE
        .withStringParameter("resource_type", resource_type.c_str())
#endif
        .withStringParameter("path", path)
        .withBoolParameter("external_blockwise_store", external_blockwise_store)
        .withBoolParameter("multiple_instance", multiple_instance)
        .withIntParameter("type", (int) type);
    // need to save e.g. the path so it can be freed in the destructor
    _sn_resource = (lwm2m_parameters_s*)calloc(1,sizeof(lwm2m_parameters_s));
    sn_nsdl_static_resource_parameters_s *params =
        (sn_nsdl_static_resource_parameters_s *) calloc(1, sizeof(sn_nsdl_static_resource_parameters_s));
    _sn_resource->dynamic_resource_params = (sn_nsdl_dynamic_resource_parameters_s *) calloc(1, sizeof(sn_nsdl_dynamic_resource_parameters_s));

    _sn_resource->dynamic_resource_params->static_resource_parameters = params;
    params->path = path;
}

M2MBase::M2MBase(const lwm2m_parameters_s *s):
    _sn_resource((lwm2m_parameters_s*) s),
    _report_handler(NULL)
{
    mock().actualCall("M2MBase::M2MBase")
            .withPointerParameter("s", (void *) s);
}

M2MBase::~M2MBase()
{
    mock().actualCall("M2MBase::~M2MBase").withPointerParameter("this", (void *) this);
    free(_sn_resource->dynamic_resource_params->static_resource_parameters->path);
    free(_sn_resource->dynamic_resource_params->static_resource_parameters);
    free(_sn_resource->dynamic_resource_params);
    free(_sn_resource);
}

char* M2MBase::create_path_base(const M2MBase &parent, const char *name)
{
    return (char *) mock()
            .actualCall("M2MBase::create_path_base")
            .withStringParameter("name", name)
            .returnStringValue();
}

char* M2MBase::create_path(const M2MEndpoint &parent, const char *name)
{
    return create_path_base(parent, name);
}

char* M2MBase::create_path(const M2MObject &parent, uint16_t object_instance)
{
    return (char *) mock().actualCall("M2MBase::create_path")
            .withUnsignedIntParameter("object_instance", object_instance)
            .returnStringValue();
}

char* M2MBase::create_path(const M2MObject &parent, const char *name)
{
    return (char *) mock().actualCall("M2MBase::create_path")
            .withPointerParameter("parent", (void *)&parent)
            .withStringParameter("name", name)
            .returnStringValue();
}

char* M2MBase::create_path(const M2MResource &parent, uint16_t resource_instance)
{
    return (char *) mock().actualCall("M2MBase::create_path")
            .withPointerParameter("parent", (void *)&parent)
            .withUnsignedIntParameter("resource_instance", resource_instance)
            .returnStringValue();
}

char* M2MBase::create_path(const M2MResource &parent, const char *name)
{
    return create_path_base(parent, name);
}

char* M2MBase::create_path(const M2MObjectInstance &parent, const char *name)
{
    return (char *) mock().actualCall("M2MBase::create_path")
            .withPointerParameter("parent", (void *)&parent)
            .withStringParameter("name", name)
            .returnStringValue();
}

void M2MBase::set_operation(M2MBase::Operation opr)
{
    mock().actualCall("M2MBase::set_operation")
            .withPointerParameter("this", (void *) this)
            .withParameter("opr", (int) opr);
}

#ifndef RESOURCE_ATTRIBUTES_LIST
#ifndef MEMORY_OPTIMIZED_API
#ifndef DISABLE_INTERFACE_DESCRIPTION
void M2MBase::set_interface_description(const char *desc)
{
    mock().actualCall("M2MBase::set_interface_description")
            .withStringParameter("desc", desc);
}

void M2MBase::set_interface_description(const String &desc)
{
    set_interface_description(desc.c_str());
}
#endif // DISABLE_INTERFACE_DESCRIPTION

#ifndef DISABLE_RESOURCE_TYPE
void M2MBase::set_resource_type(const String &res_type)
{
    mock().actualCall("M2MBase::set_resource_type")
            .withStringParameter("res_type", (const char *)res_type.c_str());
}

void M2MBase::set_resource_type(const char *res_type)
{
    mock().actualCall("M2MBase::set_resource_type")
            .withStringParameter("res_type", res_type);
}
#endif // DISABLE_RESOURCE_TYPE
#endif //MEMORY_OPTIMIZED_API
#else // RESOURCE_ATTRIBUTES_LIST
void M2MBase::set_interface_description(const char *desc)
{
    mock().actualCall("M2MBase::set_interface_description")
            .withStringParameter("desc", desc);
}

void M2MBase::set_interface_description(const String &desc)
{
    mock().actualCall("M2MBase::set_interface_description")
            .withStringParameter("desc", desc.c_str());
}

void M2MBase::set_resource_type(const String &res_type)
{
    mock().actualCall("M2MBase::set_resource_type")
            .withStringParameter("res_type", res_type.c_str());
}

void M2MBase::set_resource_type(const char *res_type)
{
    mock().actualCall("M2MBase::set_resource_type")
        .withParameter("res_type", res_type);
}
#endif // RESOURCE_ATTRIBUTES_LIST

void M2MBase::set_coap_content_type(const uint16_t con_type)
{
    mock().actualCall("M2MBase::set_coap_content_type")
        .withParameter("con_type", con_type);
}

void M2MBase::set_observable(bool observable)
{
    mock().actualCall("M2MBase::set_observable")
        .withParameter("observable", observable);
}

void M2MBase::add_observation_level(M2MBase::Observation obs_level)
{
    mock().actualCall("M2MBase::add_observation_level")
        .withParameter("obs_level", obs_level);
}

void M2MBase::remove_observation_level(M2MBase::Observation obs_level)
{
    mock().actualCall("M2MBase::remove_observation_level")
        .withParameter("obs_level", obs_level);
}


void M2MBase::set_under_observation(bool observed,
                                    M2MObservationHandler *handler)
{
    mock().actualCall("M2MBase::set_under_observation")
            .withParameter("observed", observed);
}

void M2MBase::set_observation_token(const uint8_t *token, const uint8_t length)
{
    mock().actualCall("M2MBase::set_observation_token")
        .withParameter("length", length);
}

void M2MBase::set_instance_id(const uint16_t inst_id)
{
    mock().actualCall("M2MBase::set_instance_id")
        .withParameter("inst_id", inst_id);
}

void M2MBase::set_max_age(const uint32_t max_age)
{
    mock().actualCall("M2MBase::set_max_age")
        .withParameter("max_age", max_age);
}

M2MBase::BaseType M2MBase::base_type() const
{
    return (M2MBase::BaseType) mock()
            .actualCall("M2MBase::base_type")
            .withPointerParameter("this", (void *) this)
            .returnIntValue();
}

M2MBase::Operation M2MBase::operation() const
{
    return (M2MBase::Operation) mock().actualCall("M2MBase::operation")
            .returnIntValue();
}

const char* M2MBase::name() const
{
    return mock()
            .actualCall("M2MBase::name")
            .withPointerParameter("this", (void *) this)
            .returnStringValue();
}

int32_t M2MBase::name_id() const
{
    return mock().actualCall("M2MBase::name_id").returnIntValue();
}

uint16_t M2MBase::instance_id() const
{
    return (uint16_t)mock().actualCall("M2MBase::instance_id").returnUnsignedIntValue();
}

#ifndef RESOURCE_ATTRIBUTES_LIST
#ifndef DISABLE_INTERFACE_DESCRIPTION
const char* M2MBase::interface_description() const
{
    mock().actualCall("M2MBase::interface_description")
            .returnStringValue();
}
#endif

#ifndef DISABLE_RESOURCE_TYPE
const char* M2MBase::resource_type() const
{
    mock().actualCall("M2MBase::resource_type").returnStringValue();
}
#endif
#else // RESOURCE_ATTRIBUTES_LIST
#ifndef DISABLE_INTERFACE_DESCRIPTION
const char* M2MBase::interface_description() const
{

    return mock().actualCall("M2MBase::interface_description")
            .returnStringValue();
}
#endif

#ifndef DISABLE_RESOURCE_TYPE
const char* M2MBase::resource_type() const
{
    mock().actualCall("resource_type");
    return NULL;
}
#endif
#endif // RESOURCE_ATTRIBUTES_LIST
const char* M2MBase::uri_path() const
{
    return mock().actualCall("M2MBase::uri_path")
            .withPointerParameter("this", (void *) this)
            .returnStringValue();
}

uint16_t M2MBase::coap_content_type() const
{
    return (uint16_t)mock().actualCall("M2MBase::coap_content_type")
            .returnIntValue();
}

bool M2MBase::is_observable() const
{
    return (bool) mock().actualCall("M2MBase::is_observable")
            .returnIntValue();
}

M2MBase::Observation M2MBase::observation_level() const
{
    return (M2MBase::Observation)mock().actualCall("M2MBase::observation_level")
            .returnIntValue();
}

void get_observation_token(const uint8_t *&token, uint32_t &token_length)
{
    mock().actualCall("M2MBase::observation_token");
}

void get_observation_token(uint8_t *&token, uint32_t &token_length)
{
    mock().actualCall("M2MBase::observation_token");
}

M2MBase::Mode M2MBase::mode() const
{
   return (M2MBase::Mode)mock().actualCall("M2MBase::mode")
            .returnIntValue();
}

uint16_t M2MBase::observation_number() const
{
   return (uint16_t) mock().actualCall("M2MBase::observation_number")
            .returnUnsignedIntValue();
}

uint32_t M2MBase::max_age() const
{
   return (uint32_t) mock().actualCall("M2MBase::max_age")
            .returnUnsignedIntValue();
}

bool M2MBase::handle_observation_attribute(const char *query)
{
   return (bool) mock().actualCall("M2MBase::handle_observation_attribute")
            .returnIntValue();
}

bool M2MBase::observation_to_be_sent(const m2m::Vector<uint16_t> &changed_instance_ids,
                                     uint16_t obs_number,
                                     bool send_object)
{
    mock().actualCall("M2MBase::observation_to_be_sent")
            .withUnsignedIntParameter("obs_number", (int)obs_number)
            .withIntParameter("send_object", (int)send_object);
    return true;
}

void M2MBase::set_base_type(M2MBase::BaseType type)
{
    mock().actualCall("M2MBase::set_base_type")
            .withIntParameter("type", (int)type);

}

sn_coap_hdr_s* M2MBase::handle_get_request(nsdl_s */*nsdl*/,
                                           sn_coap_hdr_s */*received_coap_header*/,
                                           M2MObservationHandler */*observation_handler*/)
{
    mock().actualCall("M2MBase::handle_get_request");
    return NULL;
}

sn_coap_hdr_s* M2MBase::handle_put_request(nsdl_s */*nsdl*/,
                                           sn_coap_hdr_s */*received_coap_header*/,
                                           M2MObservationHandler */*observation_handler*/,
                                           bool &)
{
    mock().actualCall("M2MBase::handle_put_request");
    return NULL;
}

sn_coap_hdr_s* M2MBase::handle_post_request(nsdl_s */*nsdl*/,
                                            sn_coap_hdr_s */*received_coap_header*/,
                                            M2MObservationHandler */*observation_handler*/,
                                            bool &,
                                            sn_nsdl_addr_s *)
{
    mock().actualCall("M2MBase::handle_post_request");
    return NULL;
}

void *M2MBase::memory_alloc(uint32_t size)
{
    if(size)
        return malloc(size);
    else
        return 0;
}

void M2MBase::memory_free(void *ptr)
{
    free(ptr);
}

char* M2MBase::alloc_string_copy(const char* source)
{
    assert(source != NULL);

    // Note: the armcc's libc does not have strdup, so we need to implement it here
    const size_t len = strlen(source);

    return (char*)alloc_string_copy((uint8_t*)source, len);
}

uint8_t* M2MBase::alloc_string_copy(const uint8_t* source, uint32_t size)
{
    assert(source != NULL);

    uint8_t* result = (uint8_t*)memory_alloc(size + 1);
    if (result) {
        memcpy(result, source, size);
        result[size] = '\0';
    }
    return result;
}

uint8_t* M2MBase::alloc_copy(const uint8_t* source, uint32_t size)
{
    assert(source != NULL);

    uint8_t* result = (uint8_t*)memory_alloc(size);
    if (result) {
        memcpy(result, source, size);
    }
    return result;
}

bool M2MBase::validate_string_length(const String &string, size_t min_length, size_t max_length)
{
    bool valid = false;

    const size_t len = string.length();
    if ((len >= min_length) && (len <= max_length)) {
        valid = true;
    }

    return valid;
}

bool M2MBase::validate_string_length(const char* string, size_t min_length, size_t max_length)
{
    bool valid = false;

    if (string != NULL) {
        const size_t len = strlen(string);
        if ((len >= min_length) && (len <= max_length)) {
            valid = true;
        }
    }
    return valid;
}

M2MReportHandler* M2MBase::create_report_handler()
{
    mock().actualCall("M2MBase::create_report_handler");
    return NULL;
}

M2MReportHandler* M2MBase::report_handler() const
{
    return NULL;
}

void M2MBase::set_register_uri(bool register_uri)
{
}

bool M2MBase::register_uri()
{
    return (bool) mock().actualCall("M2MBase::set_register_uri")
            .returnIntValue();
}

bool M2MBase::is_integer(const String &value)
{
    return (bool) mock().actualCall("M2MBase::is_integer")
            .withStringParameter("value", value.c_str())
            .returnIntValue();
}

bool M2MBase::is_integer(const char *value)
{
    return (bool) mock().actualCall("M2MBase::is_integer")
                .withStringParameter("value", value)
                .returnIntValue();
}

bool M2MBase::is_under_observation() const
{
    return (bool) mock().actualCall("M2MBase::is_under_observation")
                .returnIntValue();
}

bool M2MBase::set_value_updated_function(value_updated_callback callback)
{
    return (bool) mock().actualCall("M2MBase::set_value_updated_function")
            .returnIntValue();
}

bool M2MBase::set_value_updated_function(value_updated_callback2 callback)
{
    return (bool) mock().actualCall("M2MBase::set_value_updated_function")
            .returnIntValue();
}

bool M2MBase::is_value_updated_function_set() const
{
    return (bool) mock().actualCall("M2MBase::is_value_updated_function_set")
                .returnIntValue();

}

void M2MBase::execute_value_updated(const String& name)
{
    mock().actualCall("M2MBase::execute_value_updated")
            .withStringParameter("name", name.c_str());
}

bool M2MBase::build_path(StringBuffer<MAX_PATH_SIZE> &buffer, const char *s1, uint16_t i1, const char *s2, uint16_t i2)
{
    return (bool) mock().actualCall("M2MBase::build_path")
            .returnIntValue();
}

bool M2MBase::build_path(StringBuffer<MAX_PATH_SIZE_2> &buffer, const char *s1, uint16_t i1, const char *s2)
{
    return (bool) mock().actualCall("M2MBase::build_path")
            .returnIntValue();
}

bool M2MBase::build_path(StringBuffer<MAX_PATH_SIZE_3> &buffer, const char *s1, uint16_t i1, uint16_t i2)
{
    return (bool) mock().actualCall("M2MBase::build_path")
            .returnIntValue();
}

bool M2MBase::build_path(StringBuffer<MAX_PATH_SIZE_4> &buffer, const char *s1, uint16_t i1)
{
    return (bool) mock().actualCall("M2MBase::build_path")
            .returnIntValue();
}

char* M2MBase::stringdup(const char* src)
{
    assert(src != NULL);

    const size_t len = strlen(src) + 1;

    char *dest = (char*)malloc(len);

    if (dest) {
        memcpy(dest, src, len);
    }
    return dest;
}

void M2MBase::free_resources()
{
    mock().actualCall("M2MBase::free_resources");
}

size_t M2MBase::resource_name_length() const
{
    return (size_t) mock().actualCall("M2MBase::resource_name_length")
            .returnUnsignedIntValue();
}

sn_nsdl_dynamic_resource_parameters_s* M2MBase::get_nsdl_resource() const
{
    mock().actualCall("M2MBase::get_nsdl_resource");
    return NULL;
}

M2MBase::lwm2m_parameters_s* M2MBase::get_lwm2m_parameters() const
{
    mock().actualCall("M2MBase::get_lwm2m_parameters");
    return NULL;
}

#ifdef ENABLE_ASYNC_REST_RESPONSE
bool M2MBase::send_async_response_with_code(const uint8_t *payload,
                                            size_t payload_len,
                                            const uint8_t *token,
                                            const uint8_t token_len,
                                            coap_response_code_e code)
{
    ValuePointer *payload_pointer = new ValuePointer((uint8_t *) payload, payload_len);
    ValuePointer *token_pointer = new ValuePointer((uint8_t *) token, token_len);
    bool ret_val = mock().actualCall("M2MBase::send_async_response_with_code")
                           .withParameterOfType("ValuePointer", "payload", (void *) payload_pointer)
                           .withParameterOfType("ValuePointer", "token", (void *) token_pointer)
                           .withIntParameter("code", (int32_t) code)
                           .returnBoolValue();

    delete payload_pointer;
    delete token_pointer;
    return ret_val;
}

bool M2MBase::set_async_coap_request_cb(handle_async_coap_request_cb callback, void *client_args)
{

    M2MCallbackStorage::remove_callback(*this, M2MCallbackAssociation::M2MBaseAsyncCoapRequestCallback);

    bool ret_val = M2MCallbackStorage::add_callback(*this,
                                                    (void *) callback,
                                                    M2MCallbackAssociation::M2MBaseAsyncCoapRequestCallback,
                                                    client_args);
    (void) ret_val;

    return mock()
            .actualCall("M2MBase::set_async_coap_request_cb")
            .withPointerParameter("this", (void *) this)
            .withPointerParameter("callback", (void *) callback)
            // Following is commented out, because the client_args is typically dynamically allocated
            // so it's hard to guess ahead of time which pointer it is.
            //             .withPointerParameter("client_args", client_args)
            .returnBoolValue();
}

#endif

uint16_t M2MBase::get_notification_msgid() const
{
    return (uint16_t) mock().actualCall("M2MBase::get_notification_msgid")
                .returnUnsignedIntValue();
}

void M2MBase::set_notification_msgid(uint16_t msgid)
{
    mock().actualCall("M2MBase::set_notification_msgid")
            .withUnsignedIntParameter("msgid", msgid);
}

void M2MBase::set_changed()
{
   mock().actualCall("M2MBase::set_changed");
}

M2MBase *M2MBase::get_parent() const
{
   return (M2MBase *) mock().actualCall("M2MBase::get_parent")
            .returnPointerValue();
}

void M2MBase::set_deleted()
{
    mock().actualCall("M2MBase::set_deleted");
}

bool M2MBase::is_deleted()
{
    return mock().actualCall("M2MBase::is_deleted").returnBoolValue();
}

#ifdef MBED_EDGE_SUBDEVICE_FOTA
void M2MBase::set_auto_observable(bool auto_observable)
{
    mock().actualCall("M2MBase::set_auto_observable");
}
#endif // MBED_EDGE_SUBDEVICE_FOTA