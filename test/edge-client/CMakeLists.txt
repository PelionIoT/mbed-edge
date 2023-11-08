file (GLOB SOURCES ./*.cpp ../../common/apr_base64.c ../test-lib/msg_api_test_helper.cpp)

enable_language(C)
enable_language(CXX)
if(FOTA_ENABLE)
    add_definitions(-DMBED_EDGE_SUBDEVICE_FOTA)
endif()
add_executable (edge-client-test ${SOURCES})

add_definitions(-DMBED_CONF_MBED_TRACE_ENABLE=1)
include_directories (../cpputest-custom-types)
target_include_directories (edge-client-test PUBLIC ${CPPUTEST_HOME}/include)
target_include_directories (edge-client-test PUBLIC ${ROOT_HOME}/test/test-lib)
target_include_directories (edge-client-test PUBLIC ${ROOT_HOME}/lib/mbed-cloud-client/unittests/stub)
target_link_libraries (edge-client-test edge-server-mock-lib pal-mock-lib test-lib edge-client CppUTest CppUTestExt mbedTrace nanostacklibservice pthread curl)

add_definitions(-DTEST_DATA_DIR="${TEST_DATA_DIR}")
