set_property(GLOBAL PROPERTY TARGET_SUPPORTS_SHARED_LIBS TRUE)

if (TARGET_GROUP STREQUAL test)
  set (TESTS OFF CACHE BOOL "Disable CppUTest test compilation.")
  add_subdirectory (cpputest)
endif ()

set (DISABLE_PAL_TESTS ON CACHE BOOL "Disable PAL tests.")

add_definitions ("-DJANSSON_EXAMPLES=OFF")
add_definitions ("-DJANSSON_BUILD_DOCS=OFF")
add_definitions ("-DJANSSON_WITHOUT_TESTS=ON")
add_definitions ("-DJANSSON_INSTALL=OFF")

set (ENABLE_TESTING OFF CACHE BOOL "Disable mbedTLS tests")
set (ENABLE_PROGRAMS OFF CACHE BOOL "Disable mbedTLS programs.")
add_subdirectory (mbedtls)
add_subdirectory (libevent)
add_subdirectory (jansson)
add_subdirectory(libwebsockets)

add_subdirectory (mbed-cloud-client)
add_library (jsonrpc STATIC jsonrpc/jsonrpc.c)
target_link_libraries(jsonrpc jansson)
