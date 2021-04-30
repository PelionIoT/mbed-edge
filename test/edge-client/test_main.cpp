#include "CppUTest/CommandLineTestRunner.h"
#include <CppUTest/TestRegistry.h>
#include <CppUTestExt/MockSupportPlugin.h>
#include <CppUTestExt/MockSupport.h>
#include "mbed-trace/mbed_trace.h"
#include "cpputest-custom-types/value_pointer.h"
#include "test-lib/edgeclient_request_context.h"

int main(int args, char** argv)
{
    MockSupportPlugin mock_plugin;
    ValuePointerComparator value_pointer_comparator;
    EdgeClientRequestContextComparator edgeclient_request_context_comparator;
    mock_plugin.installComparator("ValuePointer", value_pointer_comparator);
    mock_plugin.installComparator("EdgeClientRequestContext", edgeclient_request_context_comparator);

    TestRegistry::getCurrentRegistry()->installPlugin(&mock_plugin);

    mbed_trace_init();
    // Clean the memory inside the mock (otherwise you will see memory leaks in the first testcase)
    mock().clear();

    int result = RUN_ALL_TESTS(args, argv);

    mbed_trace_free();

    return result;
}
