file (GLOB SOURCES ./*.c)

include_directories (${CMAKE_CURRENT_LIST_DIR}/include)

add_executable (pt-example ${SOURCES})

add_definitions(-DMBED_CONF_MBED_TRACE_ENABLE=1)

target_include_directories (pt-example PUBLIC ${CMAKE_CURRENT_LIST_DIR})
target_link_libraries (pt-example pt-client)
set_property(SOURCE ${SOURCES} PROPERTY OBJECT_DEPENDS "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed_edge_config.h")
