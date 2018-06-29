set_property(GLOBAL PROPERTY TARGET_SUPPORTS_SHARED_LIBS TRUE)

if (TARGET_GROUP STREQUAL test)
  set (TESTS OFF CACHE BOOL "Disable CppUTest test compilation.")
  add_subdirectory (cpputest)
endif ()

add_definitions ("-DJANSSON_EXAMPLES=OFF")
add_definitions ("-DJANSSON_BUILD_DOCS=OFF")
add_definitions ("-DJANSSON_WITHOUT_TESTS=ON")
add_definitions ("-DJANSSON_INSTALL=OFF")

set (ENABLE_TESTING OFF CACHE BOOL "Disable mbedTLS tests")
set (ENABLE_PROGRAMS OFF CACHE BOOL "Disable mbedTLS programs.")
add_subdirectory (mbedtls)

# Workaround for: https://github.com/libevent/libevent/issues/482
# Applies for CMake build for libevent 2.1.8-stable
# Fixing commit: https://github.com/libevent/libevent/commit/66a4eb0c3ae3b1f22b084b2d3aeb5c872f37efbd
set(EVENT__HAVE_WAITPID_WITH_WNOWAIT_EXITCODE 1)

set (EVENT__DISABLE_DEBUG_MODE ON CACHE BOOL "Disable libevent debug mode.")
set (EVENT__DISABLE_TESTS ON CACHE BOOL "Disable libevent tests.")
set (EVENT__DISABLE_REGRESS ON CACHE BOOL "Disable libevent regression tests.")
set (EVENT__DISABLE_SAMPLES ON CACHE BOOL "Disable libevent samples.")
set (EVENT__DISABLE_OPENSSL ON CACHE BOOL "Disable OpenSSL support from libevent.")
set (EVENT__DISABLE_BENCHMARK ON CACHE BOOL "Disable libevent bencmark executables.")
add_subdirectory (libevent)

set (JANSSON_EXAMPLES OFF CACHE BOOL "Disable example from jansson.")
set (JANSSON_BUILD_DOCS OFF CACHE BOOL "Disable documentation generation for jansson.")
set (JANSSON_WITHOUT_TESTS ON CACHE BOOL "Disable tests from jansson.")
set (JANSSON_INSTALL OFF CACHE BOOL "Disable install target from jansson.")
add_subdirectory (jansson)

set (LWS_UNIX_SOCK ON CACHE BOOL "Mbed Edge communicates with domain sockets")
set (LWS_WITH_SSL OFF CACHE BOOL "No SSL needed with domain sockets.")
set (LWS_WITH_LIBEVENT ON CACHE BOOL "Libevent is selected as event loop.")
set (LWS_WITH_SHARED OFF CACHE BOOL "No need for shared libraries, link it in.")
set (LWS_WITH_SSL OFF CACHE BOOL "Disable ssl to help debugging")
set (LWS_WITHOUT_TESTAPPS ON CACHE BOOL "Disable tests from libwebsockets.")
set (LWS_WITHOUT_TEST_SERVER ON CACHE BOOL "Disable tests from libwebsockets.")
set (LWS_WITHOUT_TEST_SERVER_EXT_POLL ON CACHE BOOL "Disable tests from libwebsockets.")
set (LWS_WITHOUT_TEST_PING ON CACHE BOOL "Disable tests from libwebsockets.")
set (LWS_WITHOUT_TEST_ECHO ON CACHE BOOL "Disable tests from libwebsockets.")
set (LWS_WITHOUT_TEST_CLIENT ON CACHE BOOL "Disable tests from libwebsockets.")
set (LWS_WITHOUT_TEST_FRAGGLE ON CACHE BOOL "Disable tests from libwebsockets.")
add_subdirectory(libwebsockets)

add_subdirectory (mbed-cloud-client)
add_library (jsonrpc STATIC jsonrpc/jsonrpc.c)
target_link_libraries(jsonrpc jansson)
