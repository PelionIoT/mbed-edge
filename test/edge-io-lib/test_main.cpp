#include "CppUTest/CommandLineTestRunner.h"
#include <CppUTest/TestRegistry.h>
#include <CppUTestExt/MockSupportPlugin.h>
#include <CppUTestExt/MockSupport.h>
#include "mbed-trace/mbed_trace.h"

int main(int args, char** argv)
{
    MockSupportPlugin mock_plugin;

    TestRegistry::getCurrentRegistry()->installPlugin(&mock_plugin);

    mbed_trace_init();
    // Clean the memory inside the mock (otherwise you will see memory leaks in the first testcase)
    mock().clear();

    int result = RUN_ALL_TESTS(args, argv);

    mbed_trace_free();

    return result;
}
