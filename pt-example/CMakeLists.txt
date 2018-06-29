if (NOT TARGET_GROUP STREQUAL test)
  file (GLOB SOURCES ./*.c ../common/edge_trace.c)

  include_directories (${CMAKE_CURRENT_LIST_DIR}/include)

  add_executable (pt-example ${SOURCES})

  add_definitions(-DMBED_CONF_MBED_TRACE_ENABLE=1)

  target_include_directories (pt-example PUBLIC ${CMAKE_CURRENT_LIST_DIR})

  target_link_libraries (pt-example pthread pt-client)
endif()
