#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"

#include <string.h>
extern "C" {
#include "pt-client-2/pt_api.h"
#include "pt-client-2/pt_device_object.h"
}

TEST_GROUP(pt_device_object)
{
    void setup() {}

    void teardown() {
    }
};

#if 0
void test_callback(const pt_resource_t *resource,
                   uint8_t operation,
                   const uint8_t *value,
                   const uint32_t size)
{
    // no-op
}

TEST(pt_device_object, test_initialize_device_object)
{
    pt_status_t status = ptdo_initialize_device_object(NULL, NULL);
    CHECK(PT_STATUS_INVALID_PARAMETERS == status);

    pt_device_t *device = pt_device_create("device", 3600, NONE, &status);
    CHECK(PT_STATUS_SUCCESS == status);
    status = ptdo_initialize_device_object(device, NULL);
    CHECK(PT_STATUS_INVALID_PARAMETERS == status);

    ptdo_device_object_data_t ptdo;
    ptdo.reboot_callback = NULL;
    ptdo.factory_reset_callback = test_callback;
    ptdo.reset_error_code_callback = test_callback;
    ptdo.manufacturer = strdup("test");
    ptdo.model_number = strdup("1");
    ptdo.serial_number = strdup("2");
    ptdo.firmware_version = strdup("3");
    ptdo.hardware_version = strdup("4");
    ptdo.software_version = strdup("5");
    ptdo.device_type = strdup("type");

    status = ptdo_initialize_device_object(device, &ptdo);
    CHECK(PT_STATUS_INVALID_PARAMETERS == status);

    ptdo.reboot_callback = test_callback;
    status = ptdo_initialize_device_object(device, &ptdo);
    CHECK(PT_STATUS_SUCCESS == status);

    mock().checkExpectations();
    pt_device_free(device);
}
#endif
