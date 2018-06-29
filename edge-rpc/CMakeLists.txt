file (GLOB SOURCES ./*.c ../common/edge_time.c)

add_definitions(-DMBED_CONF_MBED_TRACE_ENABLE=1)

add_library (rpc ${SOURCES})
target_include_directories (rpc PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)

target_link_libraries(rpc jsonrpc)
