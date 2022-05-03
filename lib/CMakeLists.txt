set_property(GLOBAL PROPERTY TARGET_SUPPORTS_SHARED_LIBS TRUE)

if (TARGET_GROUP STREQUAL test)
  set (TESTS OFF CACHE BOOL "Disable CppUTest test compilation.")
  set (MEMORY_LEAK_DETECTION OFF CACHE BOOL "Disable CppUTest memoryleak detection.")
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

include_directories("${CMAKE_CURRENT_SOURCE_DIR}/../platform/linux")

add_subdirectory (libevent)
add_subdirectory (jansson)
add_subdirectory (libwebsockets)
add_subdirectory (mbed-cloud-client)
add_library (jsonrpc STATIC jsonrpc/jsonrpc.c)
target_link_libraries(jsonrpc jansson)

if (PARSEC_TPM_SE_SUPPORT OR (FOTA_ENABLE AND NOT MBED_CLOUD_CLIENT_CURL_DYNAMIC_LINK))
  get_filename_component(CMAKE_PLATFORM ${CMAKE_SOURCE_DIR}/lib/platform.cmake REALPATH)
  message ("path to platform.cmake is ${CMAKE_PLATFORM}")
  include (${CMAKE_PLATFORM})

  message("TARGET ${PLATFORM_TARGET}")
  find_program(PIP pip3)
  if (NOT PIP)
    message(FATAL_ERROR "pip3 not found!")
  endif ()

  execute_process( COMMAND pip3 install -r pal-platform/requirements.txt
                    RESULT_VARIABLE CMD_ERROR
                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

  find_program(PYTHON python3)
  if (NOT PYTHON)
    message(FATAL_ERROR "python3 not found!")
  endif ()

  execute_process( COMMAND python3 pal-platform/pal-platform.py
                  deploy --target=${PLATFORM_TARGET}
                  RESULT_VARIABLE CMD_ERROR
                  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} )

  if (PARSEC_TPM_SE_SUPPORT)

    find_program(CARGO cargo)
    if (NOT CARGO)
      message(FATAL_ERROR "cargo not found!")
    endif ()

    add_subdirectory("pal-platform/Middleware/parsec_se_driver")
    add_subdirectory("pal-platform/Middleware/trusted_storage")
  endif ()
  # This cannot be included until after pal-platform.py is run, as curl does not exist before that
  add_subdirectory("${ROOT_HOME}/lib/pal-platform/Middleware/curl/")
  endif ()
