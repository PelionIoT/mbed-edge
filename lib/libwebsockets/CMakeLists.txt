set (LWS_UNIX_SOCK ON CACHE BOOL "Device Management Edge communicates with domain sockets")
set (LWS_WITH_SSL ON CACHE BOOL "Enable SSL support.")
set (LWS_WITH_MBEDTLS ON CACHE BOOL "Use mbedTLS for SSL support.")
set (LWS_WITH_LIBEVENT ON CACHE BOOL "Libevent is selected as event loop.")
set (LWS_WITH_SHARED OFF CACHE BOOL "No need for shared libraries, link it in.")
set (LWS_WITHOUT_TESTAPPS ON CACHE BOOL "Disable tests from libwebsockets.")
set (LWS_WITHOUT_TEST_SERVER ON CACHE BOOL "Disable tests from libwebsockets.")
set (LWS_WITHOUT_TEST_SERVER_EXT_POLL ON CACHE BOOL "Disable tests from libwebsockets.")
set (LWS_WITHOUT_TEST_PING ON CACHE BOOL "Disable tests from libwebsockets.")
set (LWS_WITHOUT_TEST_ECHO ON CACHE BOOL "Disable tests from libwebsockets.")
set (LWS_WITHOUT_TEST_CLIENT ON CACHE BOOL "Disable tests from libwebsockets.")
set (LWS_WITHOUT_TEST_FRAGGLE ON CACHE BOOL "Disable tests from libwebsockets.")

# Set mbedTLS paths for libwebsockets
set(LWS_MBEDTLS_INCLUDE_DIRS "${CMAKE_SOURCE_DIR}/lib/mbedtls/include" CACHE PATH "mbedTLS include directory")
set(MBEDTLS_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/../mbedtls/library/libmbedtls.a" CACHE FILEPATH "mbedTLS library")
set(MBEDX509_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/../mbedtls/library/libmbedx509.a" CACHE FILEPATH "mbedTLS X.509 library")
set(MBEDCRYPTO_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/../mbedtls/library/libmbedcrypto.a" CACHE FILEPATH "mbedTLS crypto library")

# Add mbedTLS include directories to the current scope
include_directories("${CMAKE_SOURCE_DIR}/lib/mbedtls/include")

add_subdirectory(libwebsockets)
