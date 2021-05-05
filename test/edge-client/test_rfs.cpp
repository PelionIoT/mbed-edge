#include "CppUTest/TestHarness.h"
#include "CppUTestExt/MockSupport.h"

#include "edge-client/edge_client.h"
#include "edge-client/edge_core_cb.h"
extern "C" {
#include "edge-core/edge_device_object.h"
#include "kcm_status.h"
#include "edge-client/reset_factory_settings.h"
}

TEST_GROUP(edge_rfs){
    void setup()
    {
    }

    void teardown()
    {
    }
};

