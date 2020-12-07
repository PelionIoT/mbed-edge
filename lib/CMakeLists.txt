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
add_subdirectory(mbedtls)

if(PARSEC_TPM_SE_SUPPORT)
  get_filename_component(CMAKE_PLATFORM ${CMAKE_SOURCE_DIR}/lib/platform.cmake REALPATH)
  message ("path to platform.cmake is ${CMAKE_PLATFORM}")
  include (${CMAKE_PLATFORM})
endif()

add_subdirectory (libevent)
add_subdirectory (jansson)
add_subdirectory (libwebsockets)
add_subdirectory (mbed-cloud-client)
add_library (jsonrpc STATIC jsonrpc/jsonrpc.c)
target_link_libraries(jsonrpc jansson)

if(PARSEC_TPM_SE_SUPPORT)
  message("TARGET ${PLATFORM_TARGET}")
  execute_process( COMMAND pip install -r pal-platform/requirements.txt
                    RESULT_VARIABLE CMD_ERROR
                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
  execute_process( COMMAND python pal-platform/pal-platform.py
                  deploy --target=${PLATFORM_TARGET}
                  RESULT_VARIABLE CMD_ERROR
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} )
  add_subdirectory("pal-platform/Middleware/parsec_se_driver")
  add_subdirectory("pal-platform/Middleware/trusted_storage")
endif()
