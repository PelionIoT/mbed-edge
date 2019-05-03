file (GLOB SOURCES ./*.c ../common/edge_time.c)
list(APPEND SOURCES ../common/edge-mutex/edge_mutex.c)
add_definitions(-DMBED_CONF_MBED_TRACE_ENABLE=1)
if (TARGET_GROUP STREQUAL test)
  add_definitions(-DBUILD_TYPE_TEST)
endif ()

add_library (rpc ${SOURCES})
target_include_directories (rpc PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
target_include_directories (rpc PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../lib/jsonrpc)

target_link_libraries(rpc jsonrpc)
