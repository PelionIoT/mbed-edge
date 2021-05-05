file (GLOB SOURCES ./*.cpp ./*.c)
file (GLOB EDGE_WEBSOCKET_COMMON_MOCK_SOURCES ./mock_edge_websocket_comm.cpp)
file (GLOB EDGE_MSG_API_COMMON_MOCK_SOURCES ./mock_edge_msg_api.cpp)
file (GLOB EDGE_MUTEX_MOCK_SOURCES ./mock_edge_mutex.cpp)
file (GLOB EDGE_MUTEX_HELPER_SOURCES ./edge_mutex_helper.cpp)

add_definitions(-DMBED_CONF_MBED_TRACE_ENABLE=1)

include_directories (../cpputest-custom-types)

add_library (test-lib ${SOURCES})
target_include_directories (test-lib PUBLIC ${CPPUTEST_HOME}/include)

add_library (edge-websocket-common-mock ${EDGE_WEBSOCKET_COMMON_MOCK_SOURCES})
target_include_directories (edge-websocket-common-mock PUBLIC ${CPPUTEST_HOME}/include)

add_library (edge-msg-api-common-mock ${EDGE_MSG_API_COMMON_MOCK_SOURCES})
target_include_directories (edge-msg-api-common-mock PUBLIC ${CPPUTEST_HOME}/include)

add_library (edge-mutex-mock ${EDGE_MUTEX_MOCK_SOURCES})
target_include_directories (edge-mutex-mock PUBLIC ${CPPUTEST_HOME}/include)

add_library (edge-mutex-helper ${EDGE_MUTEX_HELPER_SOURCES})
target_include_directories (edge-mutex-helper PUBLIC ${CPPUTEST_HOME}/include)

