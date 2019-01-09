file (GLOB SOURCES
  ./*.c
  ../common/apr_base64.c
  ../common/default_message_id_generator.c
  ../common/edge_common.c
  ../common/integer_length.c
  ../common/pt_api_error_codes.c
  ../common/websocket_comm.c
  )
if (TARGET_GROUP STREQUAL test)
  add_definitions(-DBUILD_TYPE_TEST)
else()
  list(APPEND SOURCES ../common/edge-mutex/edge_mutex.c)
endif ()

include_directories (${CMAKE_CURRENT_LIST_DIR}/include)

add_library (pt-client ${SOURCES})

add_definitions(-DMBED_CONF_MBED_TRACE_ENABLE=1)

target_include_directories (pt-client PUBLIC ${CMAKE_CURRENT_LIST_DIR})
target_include_directories (pt-client PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../lib/jsonrpc)
target_include_directories (pt-client PUBLIC ${CMAKE_CURRENT_LIST_DIR}/../edge-rpc)
SET (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -shared")

if (TARGET_GROUP STREQUAL test)
  target_link_libraries (pt-client jansson rpc mbedTraceEdge)
else ()
  target_link_libraries (pt-client event jansson websockets rpc nanostack mbedTraceEdge)
endif()
