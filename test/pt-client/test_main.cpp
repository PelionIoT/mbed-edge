#include "CppUTest/CommandLineTestRunner.h"
#include <CppUTest/TestRegistry.h>
#include <CppUTestExt/MockSupportPlugin.h>
#include <CppUTestExt/MockSupport.h>
#include "cpputest-custom-types/my_json_frame.h"
#include "cpputest-custom-types/value_pointer.h"

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

    return RUN_ALL_TESTS(args, argv);
}
