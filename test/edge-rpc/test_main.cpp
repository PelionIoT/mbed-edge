#include "CppUTest/CommandLineTestRunner.h"
#include <CppUTest/TestRegistry.h>
#include <CppUTestExt/MockSupportPlugin.h>
#include <CppUTestExt/MockSupport.h>
#include "mbed-trace/mbed_trace.h"
#include "test-lib/json_pointer.h"
#include "test-lib/json_message_t_pointer.h"

int main(int args, char** argv)
{
    MockSupportPlugin mock_plugin;
    JsonPointerCopier json_pointer_copier;
    JsonPointerComparator json_pointer_comparator;
    JsonMessageTPointerComparator jmtp_comparator;
    JsonMessageTPointerCopier jmtp_copier;

    mock_plugin.installComparator("JsonPointer", json_pointer_comparator);
    mock_plugin.installComparator("JsonMessageTPointer", jmtp_comparator);
    mock_plugin.installCopier("JsonPointer", json_pointer_copier);
    mock_plugin.installCopier("JsonMessageTPointer", jmtp_copier);
    TestRegistry::getCurrentRegistry()->installPlugin(&mock_plugin);

    mbed_trace_init();
    // Clean the memory inside the mock (otherwise you will see memory leaks in the first testcase)
    mock().clear();
    // mock().tracing(true);

    int result = RUN_ALL_TESTS(args, argv);

    mbed_trace_free();

    return result;
}
