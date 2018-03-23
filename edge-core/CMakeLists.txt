file (GLOB SOURCES ./*.c ../common/*.c)

if (TARGET_GROUP STREQUAL test)
  add_library (edge-core ${SOURCES})
  add_definitions(-DBUILD_TYPE_TEST)
else ()
  add_executable (edge-core ${SOURCES})
endif ()

add_definitions(-DMBED_CONF_MBED_TRACE_ENABLE=1)

target_include_directories (edge-core PUBLIC ${CMAKE_CURRENT_LIST_DIR})
if (TARGET_GROUP STREQUAL test)
  target_link_libraries (edge-core jansson jsonrpc libevent-mock-lib fstrm rpc mbed-trace nanostack-libservice edge-client-mock-lib pal-mock-lib test-lib)
else ()
  target_link_libraries (edge-core jansson event event_pthreads fstrm rpc mbed-trace nanostack-libservice mbed-cloud-client edge-client)
endif ()

set_property(SOURCE ${SOURCES} PROPERTY OBJECT_DEPENDS "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed_edge_config.h")
