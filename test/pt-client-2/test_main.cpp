#include "CppUTest/CommandLineTestRunner.h"
#include <CppUTest/TestRegistry.h>
#include <CppUTestExt/MockSupportPlugin.h>
#include <CppUTestExt/MockSupport.h>
#include "cpputest-custom-types/my_json_frame.h"
#include "cpputest-custom-types/value_pointer.h"
#include "mbed-trace/mbed_trace.h"
#include "test-lib/msg_api_mocks.h"
extern "C" {
#include "edge-rpc/rpc.h"
}

int main(int args, char** argv)
{
    MockSupportPlugin mock_plugin;
    MyJsonFrameCopier json_frame_copier;
    ValuePointerComparator value_pointer_comparator;
    ValuePointerCopier value_pointer_copier;

    mock_plugin.installCopier("MyJsonFrame", json_frame_copier);
    mock_plugin.installComparator("ValuePointer", value_pointer_comparator);
    mock_plugin.installCopier("ValuePointer", value_pointer_copier);

    TestRegistry::getCurrentRegistry()->installPlugin(&mock_plugin);

    // Clean the memory inside the mock (otherwise you will see memory leaks in the first testcase)
    mock().clear();
    mbed_trace_init();
    mock().expectOneCall("edge_mutex_init")
            .withIntParameter("type", PTHREAD_MUTEX_ERRORCHECK)
            .withPointerParameter("mutex", &rpc_mutex)
            .andReturnValue(0);
    rpc_init();
    mock_msg_api_messages_init();

    int result = RUN_ALL_TESTS(args, argv);

    mbed_trace_free();

    return result;
}
