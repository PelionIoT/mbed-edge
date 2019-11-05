project(edge-client)
set_property(GLOBAL PROPERTY TARGET_SUPPORTS_SHARED_LIBS TRUE)

if (TARGET_GROUP STREQUAL test)
add_definitions(-DBUILD_TYPE_TEST)
endif ()

file (GLOB SOURCES ./*.cpp ./*.c ../common/integer_length.c ../common/msg_api.c)

add_definitions(-DMBED_CONF_MBED_TRACE_ENABLE=1)

add_library (edge-client STATIC ${SOURCES})
set_target_properties(edge-client PROPERTIES LINKER_LANGUAGE CXX)
target_include_directories (edge-client PUBLIC ${ROOT_HOME}/edge-core)

if (TARGET_GROUP STREQUAL test)
  list (APPEND EDGE_CLIENT_LIBS libevent-mock-lib edge-server-mock-lib test-lib pal-mock-lib mbed-cloud-client-mock)
else ()
  list (APPEND EDGE_CLIENT_LIBS pthread stdc++ mbedCloudClient mbedtls rt)
  if (${DEVELOPER_MODE})
    list (APPEND EDGE_CLIENT_LIBS mbed-developer-certificate)
  endif ()
  if (${FIRMWARE_UPDATE} AND ${DEVELOPER_MODE})
    list (APPEND EDGE_CLIENT_LIBS mbed-update-default-resources)
  endif ()
endif ()
target_link_libraries(edge-client ${EDGE_CLIENT_LIBS})
