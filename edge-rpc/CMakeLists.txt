file (GLOB SOURCES ./*.c)

add_definitions(-DMBED_CONF_MBED_TRACE_ENABLE=1)

add_library (rpc ${SOURCES})
target_include_directories (rpc PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)

target_link_libraries(rpc jsonrpc mbed-trace nanostack-libservice)
set_property(SOURCE ${SOURCES} PROPERTY OBJECT_DEPENDS "${CMAKE_SOURCE_DIR}/../../build/mcc-linux-x86/mbed_edge_config.h")
