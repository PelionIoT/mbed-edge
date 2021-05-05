#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"

#include "ns_list.h"
#include "common/constants.h"
#include "mbed-client/m2minterface.h"
#include "edge-client/edge_client_mgmt.h"
#include "testfactory.h"

TEST_GROUP(edge_client_mgmt) {
    void setup()
    {
    }

    void teardown()
    {
    }
};

TEST(edge_client_mgmt, null_m2m_device_list)
{
    M2MBaseList *m2m_devices = NULL;
    mock().expectOneCall("get_object_list").andReturnValue(m2m_devices);
    edge_device_list_t *devices = edgeclient_devices();
    CHECK(ns_list_is_empty(devices));
    edgeclient_destroy_device_list(devices);
    mock().checkExpectations();
}


TEST(edge_client_mgmt, empty_m2m_device_list)
{
    M2MBaseList m2m_devices = M2MBaseList();
    mock().expectOneCall("get_object_list").andReturnValue(&m2m_devices);
    edge_device_list_t *devices = edgeclient_devices();
    CHECK(ns_list_is_empty(devices));
    edgeclient_destroy_device_list(devices);
    mock().checkExpectations();
}

TEST(edge_client_mgmt, m2m_device_list_no_objects)
{
    M2MBaseList m2m_devices = M2MBaseList();
    M2MObjectList m2m_objects = M2MObjectList();

    mock().disable();
    String ep1_name = String("ep1");
    M2MEndpoint *ep1 = TestFactory::create_endpoint(ep1_name, strdup("/3"));
    m2m_devices.push_back(ep1);
    mock().enable();

    mock().expectOneCall("get_object_list").andReturnValue(&m2m_devices);
    mock().expectOneCall("M2MBase::base_type")
        .withPointerParameter("this", ep1)
        .andReturnValue((int) M2MBase::ObjectDirectory);
    mock()
        .expectOneCall("M2MEndpoint::is_deleted")
        .andReturnValue(false);
    mock().expectOneCall("M2MBase::name")
        .withPointerParameter("this", ep1)
        .andReturnValue(ep1_name.c_str());
    mock().expectOneCall("M2MEndpoint::objects")
        .andReturnValue(&m2m_objects);

    edge_device_list_t *devices = edgeclient_devices();
    CHECK_EQUAL(1, ns_list_count(devices));
    edge_device_entry_t *device = ns_list_get_first(devices);
    STRCMP_EQUAL("ep1", device->name);
    edgeclient_destroy_device_list(devices);

    mock().expectOneCall("M2MEndpoint::~M2MEndpoint")
        .withPointerParameter("this", ep1);
    mock().expectOneCall("M2MBase::~M2MBase")
        .withPointerParameter("this", ep1);
    delete ep1;

    mock().checkExpectations();
}

TEST(edge_client_mgmt, m2m_device_list_no_instances)
{
    M2MBaseList m2m_devices = M2MBaseList();
    M2MObjectList m2m_objects = M2MObjectList();
    M2MObjectInstanceList m2m_instances = M2MObjectInstanceList();

    mock().disable();
    String ep1_name = String("ep1");
    M2MEndpoint *ep1 = TestFactory::create_endpoint(ep1_name, strdup("/ep1"));
    m2m_devices.push_back(ep1);

    String obj1_name = String("obj1");
    M2MObject *obj1 = ep1->create_object(obj1_name);
    m2m_objects.push_back(obj1);
    mock().enable();

    mock().expectOneCall("get_object_list").andReturnValue(&m2m_devices);
    mock().expectOneCall("M2MBase::base_type")
        .withPointerParameter("this", ep1)
        .andReturnValue((int) M2MBase::ObjectDirectory);
    mock()
        .expectOneCall("M2MEndpoint::is_deleted")
        .andReturnValue(false);
    mock().expectOneCall("M2MBase::name")
        .withPointerParameter("this", ep1)
        .andReturnValue(ep1_name.c_str());
    mock().expectOneCall("M2MEndpoint::objects")
        .andReturnValue(&m2m_objects);
    mock().expectOneCall("M2MObject::instances")
        .andReturnValue(&m2m_instances);

    edge_device_list_t *devices = edgeclient_devices();
    CHECK_EQUAL(1, ns_list_count(devices));
    edge_device_entry_t *device = ns_list_get_first(devices);
    STRCMP_EQUAL("ep1", device->name);

    edgeclient_destroy_device_list(devices);

    mock().expectOneCall("M2MEndpoint::~M2MEndpoint")
        .withPointerParameter("this", ep1);
    mock().expectOneCall("M2MBase::~M2MBase")
        .withPointerParameter("this", ep1);
    delete ep1;

    mock().checkExpectations();
}

TEST(edge_client_mgmt, m2m_device_list_no_resources)
{
    M2MBaseList m2m_devices = M2MBaseList();
    M2MObjectList m2m_objects = M2MObjectList();
    M2MObjectInstanceList m2m_instances = M2MObjectInstanceList();
    M2MResourceList m2m_resources = M2MResourceList();

    mock().disable();
    String ep1_name = String("ep1");
    M2MEndpoint *ep1 = TestFactory::create_endpoint(ep1_name, strdup("/ep1"));
    m2m_devices.push_back(ep1);

    String obj1_name = String("obj1");
    M2MObject *obj1 = ep1->create_object(obj1_name);
    m2m_objects.push_back(obj1);
    M2MObjectInstance *ins1 = obj1->create_object_instance((uint16_t) 0);
    m2m_instances.push_back(ins1);
    mock().enable();

    mock().expectOneCall("get_object_list").andReturnValue(&m2m_devices);
    mock().expectOneCall("M2MBase::base_type")
        .withPointerParameter("this", ep1)
        .andReturnValue((int) M2MBase::ObjectDirectory);
    mock()
        .expectOneCall("M2MEndpoint::is_deleted")
        .andReturnValue(false);
    mock().expectOneCall("M2MBase::name")
        .withPointerParameter("this", ep1)
        .andReturnValue(ep1_name.c_str());
    mock().expectOneCall("M2MEndpoint::objects")
        .andReturnValue(&m2m_objects);
    mock().expectOneCall("M2MObject::instances")
        .andReturnValue(&m2m_instances);
    mock().expectOneCall("M2MObjectInstance::resources")
        .andReturnValue(&m2m_resources);

    /* Test */
    edge_device_list_t *devices = edgeclient_devices();
    CHECK_EQUAL(1, ns_list_count(devices));
    edge_device_entry_t *device = ns_list_get_first(devices);
    STRCMP_EQUAL("ep1", device->name);

    edgeclient_destroy_device_list(devices);

    mock().expectOneCall("M2MEndpoint::~M2MEndpoint")
        .withPointerParameter("this", ep1);
    mock().expectOneCall("M2MBase::~M2MBase")
        .withPointerParameter("this", ep1);
    delete ep1;

    mock().checkExpectations();
}

TEST(edge_client_mgmt, m2m_device_list_has_resources)
{
    M2MBaseList m2m_devices = M2MBaseList();
    M2MObjectList m2m_objects = M2MObjectList();
    M2MObjectInstanceList m2m_instances = M2MObjectInstanceList();
    M2MResourceList m2m_resources = M2MResourceList();

    mock().disable();
    String ep1_name = String("ep1");
    M2MEndpoint *ep1 = TestFactory::create_endpoint(ep1_name, strdup("/ep1"));
    m2m_devices.push_back(ep1);

    String obj1_name = String("obj1");
    M2MObject *obj1 = ep1->create_object(obj1_name);
    m2m_objects.push_back(obj1);
    M2MObjectInstance *ins1 = obj1->create_object_instance((uint16_t) 0);
    m2m_instances.push_back(ins1);
    String res1_name = String("res1");
    M2MResource *res1 = ins1->create_dynamic_resource(res1_name, "",
                                                      M2MResourceBase::STRING,
                                                      true, false, false);
    m2m_resources.push_back(res1);

    // This endpoint is deleted and must not be in the returned results
    String ep2_name = String("ep2");
    M2MEndpoint *ep2 = TestFactory::create_endpoint(ep2_name, strdup("/ep2"));
    m2m_devices.push_back(ep2);

    mock().enable();

    mock().expectOneCall("get_object_list").andReturnValue(&m2m_devices);
    mock().expectOneCall("M2MBase::base_type")
        .withPointerParameter("this", ep1)
        .andReturnValue((int) M2MBase::ObjectDirectory);
    mock()
        .expectOneCall("M2MEndpoint::is_deleted")
        .andReturnValue(false);

    // M2MBase::name gets called once for each item, except instance
    mock().expectOneCall("M2MBase::name")
        .withPointerParameter("this", ep1)
        .andReturnValue(ep1_name.c_str());

    // CppuMock does not match the calls with pointer parameter and
    // therefore does return correct value unless ordered manually.
    // This is why the res1 name call is mocked first and the obj1
    // name call is last.
    mock().expectOneCall("M2MBase::name")
        .withPointerParameter("this", res1)
        .andReturnValue(res1_name.c_str());
    mock().expectOneCall("M2MBase::instance_id")
        .andReturnValue((uint16_t) 0);
    mock().expectOneCall("M2MBase::name")
        .withPointerParameter("this", obj1)
        .andReturnValue(obj1_name.c_str());

    mock().expectOneCall("M2MEndpoint::objects")
        .andReturnValue(&m2m_objects);
    mock().expectOneCall("M2MObject::instances")
        .andReturnValue(&m2m_instances);
    mock().expectOneCall("M2MObjectInstance::resources")
        .andReturnValue(&m2m_resources);

    mock().expectOneCall("M2MResourceBase::resource_instance_type")
        .andReturnValue(M2MResourceBase::STRING);
    mock().expectOneCall("M2MBase::operation")
        .andReturnValue(M2MBase::GET_ALLOWED);

    mock().expectOneCall("M2MBase::base_type")
        .withPointerParameter("this", ep2)
        .andReturnValue((int) M2MBase::ObjectDirectory);
    mock().expectOneCall("M2MEndpoint::is_deleted")
        .andReturnValue(true);

    /* Test */
    edge_device_list_t *devices = edgeclient_devices();

    /* Checks */
    CHECK_EQUAL(1, ns_list_count(devices));
    edge_device_entry_t *device = ns_list_get_first(devices);
    STRCMP_EQUAL("ep1", device->name);
    edge_device_resource_entry_t *resource = ns_list_get_first(device->resources);

    STRCMP_EQUAL("/obj1/0/res1", resource->uri);
    CHECK_EQUAL((int32_t) M2MBase::STRING, (int32_t)(resource->type));
    CHECK_EQUAL(OPERATION_READ, resource->operation);

    edgeclient_destroy_device_list(devices);

    mock().expectOneCall("M2MEndpoint::~M2MEndpoint")
        .withPointerParameter("this", ep1);
    mock().expectOneCall("M2MBase::~M2MBase")
        .withPointerParameter("this", ep1);
    delete ep1;

    mock()
        .expectOneCall("M2MEndpoint::~M2MEndpoint")
        .withPointerParameter("this", ep2);
    mock()
        .expectOneCall("M2MBase::~M2MBase")
        .withPointerParameter("this", ep2);
    delete ep2;

    mock().checkExpectations();
}

TEST(edge_client_mgmt, m2m_device_list_has_empty_structures)
{
    // Create a data set that has empty object before one that has content
    // Similar date for object instances, empty one before content.

    M2MBaseList m2m_devices = M2MBaseList();
    M2MObjectList m2m_empty_objects = M2MObjectList();
    M2MObjectList m2m_objects = M2MObjectList();

    M2MObjectInstanceList m2m_instances = M2MObjectInstanceList();
    M2MObjectInstanceList m2m_empty_instances = M2MObjectInstanceList();

    M2MResourceList m2m_resources = M2MResourceList();
    M2MResourceList m2m_empty_resources = M2MResourceList();

    mock().disable();
    String ep_empty_name = String("empty");
    M2MEndpoint *ep_empty = TestFactory::create_endpoint(ep_empty_name, strdup("/empty"));
    m2m_devices.push_back(ep_empty);

    String ep1_name = String("ep1");
    M2MEndpoint *ep1 = TestFactory::create_endpoint(ep1_name, strdup("/ep1"));
    m2m_devices.push_back(ep1);

    String obj_empty_name = String("empty_obj");
    M2MObject *obj_empty = ep1->create_object(obj_empty_name);
    m2m_objects.push_back(obj_empty);

    String obj1_name = String("obj1");
    M2MObject *obj1 = ep1->create_object(obj1_name);
    m2m_objects.push_back(obj1);

    M2MObjectInstance *empty_ins = obj1->create_object_instance((uint16_t) 0);
    m2m_instances.push_back(empty_ins);

    M2MObjectInstance *ins1 = obj1->create_object_instance((uint16_t) 1);
    m2m_instances.push_back(ins1);
    String res1_name = String("res1");
    M2MResource *res1 = ins1->create_dynamic_resource(res1_name, "",
                                                      M2MResourceBase::STRING,
                                                      true, false, false);
    m2m_resources.push_back(res1);
    mock().enable();

    mock().expectOneCall("get_object_list").andReturnValue(&m2m_devices);
    mock().expectOneCall("M2MBase::base_type")
        .withPointerParameter("this", ep_empty)
        .andReturnValue((int) M2MBase::ObjectDirectory);
    mock().expectOneCall("M2MBase::base_type")
        .withPointerParameter("this", ep1)
        .andReturnValue((int) M2MBase::ObjectDirectory);
    mock().expectNCalls(2, "M2MEndpoint::is_deleted")
        .andReturnValue(false);

    // M2MBase::name gets called once for each item, except instance
    mock().expectOneCall("M2MBase::name")
        .withPointerParameter("this", ep_empty)
        .andReturnValue(ep_empty_name.c_str());
    mock().expectOneCall("M2MBase::name")
        .withPointerParameter("this", ep1)
        .andReturnValue(ep1_name.c_str());
    mock().expectOneCall("M2MBase::instance_id")
        .andReturnValue((uint16_t) 1);
    mock().expectOneCall("M2MBase::name")
        .withPointerParameter("this", res1)
        .andReturnValue(res1_name.c_str());
    mock().expectOneCall("M2MBase::name")
        .withPointerParameter("this", obj1)
        .andReturnValue(obj1_name.c_str());

    // continue checked for objects.empty()
    mock().expectOneCall("M2MEndpoint::objects")
        .andReturnValue(&m2m_empty_objects);
    mock().expectOneCall("M2MEndpoint::objects")
        .andReturnValue(&m2m_objects);

    // continue checked for instances.empty()
    mock().expectOneCall("M2MObject::instances")
        .andReturnValue(&m2m_empty_instances);
    mock().expectOneCall("M2MObject::instances")
        .andReturnValue(&m2m_instances);

    // continue checked for resources.empty()
    mock().expectOneCall("M2MObjectInstance::resources")
        .andReturnValue(&m2m_empty_resources);
    mock().expectOneCall("M2MObjectInstance::resources")
        .andReturnValue(&m2m_resources);
    mock().expectOneCall("M2MResourceBase::resource_instance_type")
        .andReturnValue(M2MResourceBase::STRING);
    mock().expectOneCall("M2MBase::operation")
        .andReturnValue(M2MBase::GET_ALLOWED);

    /* Test */
    edge_device_list_t *devices = edgeclient_devices();

    CHECK_EQUAL(2, ns_list_count(devices));

    edge_device_entry_t *device = ns_list_get_first(devices);
    STRCMP_EQUAL("empty", device->name);
    CHECK_EQUAL(0, ns_list_count(device->resources));

    device = ns_list_get_next(devices, device);
    STRCMP_EQUAL("ep1", device->name);
    CHECK_EQUAL(1, ns_list_count(device->resources));
    edge_device_resource_entry_t *resource = ns_list_get_first(device->resources);
    STRCMP_EQUAL("/obj1/1/res1", resource->uri);
    CHECK_EQUAL((int32_t) M2MBase::STRING, (int) resource->type);
    CHECK_EQUAL(OPERATION_READ, resource->operation);

    mock().expectOneCall("M2MEndpoint::~M2MEndpoint")
        .withPointerParameter("this", ep_empty);
    mock().expectOneCall("M2MBase::~M2MBase")
        .withPointerParameter("this", ep_empty);
    delete ep_empty;

    mock().expectOneCall("M2MEndpoint::~M2MEndpoint")
        .withPointerParameter("this", ep1);
    mock().expectOneCall("M2MBase::~M2MBase")
        .withPointerParameter("this", ep1);
    delete ep1;

    edgeclient_destroy_device_list(devices);
    mock().checkExpectations();
}
