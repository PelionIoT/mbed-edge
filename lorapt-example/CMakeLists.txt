if (NOT TARGET_GROUP STREQUAL test)
  file (GLOB SOURCES ./*.c ../common/edge_trace.c)

  include_directories (${CMAKE_CURRENT_LIST_DIR}/include)

  add_executable (lorapt-example ${SOURCES})

  add_definitions(-DMBED_CONF_MBED_TRACE_ENABLE=1)

  target_include_directories (lorapt-example PUBLIC ${CMAKE_CURRENT_LIST_DIR})

  target_link_libraries (lorapt-example pthread pt-client mosquitto)
endif()
