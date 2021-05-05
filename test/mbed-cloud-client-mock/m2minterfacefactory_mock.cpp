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

#include "mbed-client/m2minterfacefactory.h"
#include "mbed-client/m2mserver.h"
#include "mbed-client/m2mdevice.h"
#include "mbed-client/m2mobject.h"
#include "mbed-client/m2mendpoint.h"
#include "mbed-client/m2mconstants.h"
#include "mbed-client/m2mconfig.h"
#include "include/m2minterfaceimpl.h"
#include "mbed-trace/mbed_trace.h"

#include <inttypes.h>

#include "CppUTestExt/MockSupport.h"

#define TRACE_GROUP "mClt"

M2MInterface* M2MInterfaceFactory::create_interface(M2MInterfaceObserver &observer,
                                                    const String &endpoint_name,
                                                    const String &endpoint_type,
                                                    const int32_t life_time,
                                                    const uint16_t listen_port,
                                                    const String &domain,
                                                    M2MInterface::BindingMode mode,
                                                    M2MInterface::NetworkStack stack,
                                                    const String &context_address)
{
    mock().actualCall("M2MInterfaceFactory::create_interface");
    return NULL;
}

M2MSecurity* M2MInterfaceFactory::create_security(M2MSecurity::ServerType server_type)
{
    mock().actualCall("M2MInterfaceFactory::create_security")
            .withIntParameter("server_type", server_type);
    return NULL;
}

M2MServer* M2MInterfaceFactory::create_server()
{
    mock().actualCall("M2MInterfaceFactory::create_server");
    return NULL;
}

M2MDevice* M2MInterfaceFactory::create_device()
{
    mock().actualCall("M2MInterfaceFactory::create_device");
    return NULL;
}

M2MObject* M2MInterfaceFactory::create_object(const String &name)
{
    return (M2MObject *) mock().actualCall("M2MInterfaceFactory::create_object")
            .withStringParameter("name", name.c_str())
            .returnPointerValue();
}

M2MEndpoint* M2MInterfaceFactory::create_endpoint(const String &name)
{
    return (M2MEndpoint *) mock().actualCall("M2MInterfaceFactory::create_endpoint")
                .withStringParameter("name", name.c_str())
                .returnPointerValue();
}
