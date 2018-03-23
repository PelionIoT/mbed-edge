file (GLOB SOURCES ./*.c ../common/*.c)
if (TARGET_GROUP STREQUAL test)
add_definitions(-DBUILD_TYPE_TEST)
endif ()

include_directories (${CMAKE_CURRENT_LIST_DIR}/include)

add_library (pt-client ${SOURCES})

add_definitions(-DMBED_CONF_MBED_TRACE_ENABLE=1)

target_include_directories (pt-client PUBLIC ${CMAKE_CURRENT_LIST_DIR})
SET (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -shared")
target_link_libraries (pt-client event event_pthreads fstrm jansson rpc pal mbed-trace nanostack-libservice)
set_property(SOURCE ${SOURCES} PROPERTY OBJECT_DEPENDS "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed_edge_config.h")
