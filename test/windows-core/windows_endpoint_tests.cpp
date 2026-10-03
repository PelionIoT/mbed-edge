/* SPDX-License-Identifier: Apache-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include "pal.h"
#include "mbed-client/m2mbase.h"
#include "mbed-client/m2mendpoint.h"
#include "mbed-client/m2mobject.h"
#include "mbed-client/m2mobjectinstance.h"
#include "mbed-client/m2mresource.h"
#include "mbed-client/m2minterfacefactory.h"

#define CHECK(value) do { if (!(value)) { \
    fprintf(stderr, "Endpoint test line %d: %s failed\n", __LINE__, #value); exit(1); \
} } while (0)

int main()
{
    CHECK(pal_init() == PAL_SUCCESS);
    M2MBase::lwm2m_parameters_s parameters = {};
    for (int type = M2MBase::Object; type <= M2MBase::ObjectDirectory; ++type) {
        parameters.base_type = static_cast<M2MBase::BaseType>(type);
        CHECK(parameters.base_type == type);
    }
    for (int type = M2MBase::STRING; type <= M2MBase::OBJLINK; ++type) {
        parameters.data_type = static_cast<M2MBase::DataType>(type);
        CHECK(parameters.data_type == type);
    }
    M2MEndpoint *endpoint = M2MInterfaceFactory::create_endpoint(String("windows-counter"));
    CHECK(endpoint != NULL);
    // The real Edge endpoint lookup depends on this comparison.
    CHECK(endpoint->base_type() == M2MBase::ObjectDirectory);
    M2MObject *object = endpoint->create_object(String("3300"));
    CHECK(object != NULL);
    M2MObjectInstance *instance = object->create_object_instance(static_cast<uint16_t>(0));
    CHECK(instance != NULL);
    M2MResource *counter = instance->create_dynamic_resource("5700", "Counter", M2MResourceInstance::FLOAT, true);
    CHECK(counter != NULL);
    CHECK(counter->set_value_float(1001.0));
    CHECK(counter->set_value_float(1002.0));
    CHECK(counter->get_value_float() == 1002.0);
    CHECK(endpoint->object(String("3300")) == object);
    CHECK(object->object_instance(0) == instance);
    CHECK(instance->resource("5700") == counter);
    delete endpoint;
    pal_destroy();
    puts("PASS Windows endpoint lookup, resource updates and all base/data type bitfields");
    return 0;
}
