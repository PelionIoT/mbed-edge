#include "CppUTest/CommandLineTestRunner.h"
#include <CppUTest/TestRegistry.h>
#include <CppUTestExt/MockSupportPlugin.h>
#include <CppUTestExt/MockSupport.h>
#include "test-lib/MyEvBuffer.h"
#include "cpputest-custom-types/value_pointer.h"
#include "mbed-trace/mbed_trace.h"

int main(int args, char** argv)
{
    MockSupportPlugin mock_plugin;
    MyEvBufferCopier ev_buffer_copier;
    ValuePointerComparator value_pointer_comparator;
    ValuePointerCopier value_pointer_copier;

    mock_plugin.installCopier("MyEvBuffer", ev_buffer_copier);
    mock_plugin.installComparator("ValuePointer", value_pointer_comparator);
    mock_plugin.installCopier("ValuePointer", value_pointer_copier);

    TestRegistry::getCurrentRegistry()->installPlugin(&mock_plugin);

    mbed_trace_init();
    // Clean the memory inside the mock (otherwise you will see memory leaks in the first testcase)
    mock().clear();

    int result = RUN_ALL_TESTS(args, argv);

    mbed_trace_free();

    return result;
}
