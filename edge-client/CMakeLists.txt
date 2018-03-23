project(edge-client)
set_property(GLOBAL PROPERTY TARGET_SUPPORTS_SHARED_LIBS TRUE)

if (TARGET_GROUP STREQUAL test)
add_definitions(-DBUILD_TYPE_TEST)
endif ()

file (GLOB SOURCES ./*.cpp ./*.c ../common/integer_length.c)

add_definitions(-DMBED_CONF_MBED_TRACE_ENABLE=1)

add_library (edge-client STATIC ${SOURCES})
set_target_properties(edge-client PROPERTIES LINKER_LANGUAGE CXX)
target_include_directories (edge-client PUBLIC ${ROOT_HOME}/edge-core)

if (TARGET_GROUP STREQUAL test)
  target_link_libraries (edge-client libevent-mock-lib edge-server-mock-lib test-lib pal-mock-lib mbed-cloud-client-mock)
endif ()
set_property(SOURCE ${SOURCES} PROPERTY OBJECT_DEPENDS "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed_edge_config.h")
