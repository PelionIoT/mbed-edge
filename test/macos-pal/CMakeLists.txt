cmake_minimum_required(VERSION 3.22)
project(macos_pal_tests C)
if(NOT APPLE OR NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)$")
    message(FATAL_ERROR "These tests require native Apple Silicon macOS.")
endif()
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
get_directory_property(macos_pal_definitions COMPILE_DEFINITIONS)
list(FILTER macos_pal_definitions EXCLUDE REGEX "^(PAL_FS_MOUNT_POINT_PRIMARY|PAL_FS_MOUNT_POINT_SECONDARY|MBED_CONF_MBED_TRACE_ENABLE)=")
set_property(DIRECTORY PROPERTY COMPILE_DEFINITIONS "${macos_pal_definitions}")
find_package(Threads REQUIRED)
get_filename_component(EDGE_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
set(CLIENT "${EDGE_ROOT}/lib/mbed-cloud-client")
set(PAL "${CLIENT}/mbed-client-pal")
set(PORT "${PAL}/Source/Port/Reference-Impl/OS_Specific/Darwin")
add_library(macos-pal-adapters STATIC
    "${PORT}/RTOS/pal_plat_rtos.c"
    "${PORT}/Board_Specific/TARGET_aarch64/pal_plat_aarch64.c"
    "${PORT}/../Linux/Storage/FileSystem/pal_plat_fileSystem.c"
    "${PORT}/../Linux/Networking/pal_plat_network.c"
    "${PAL}/Source/PAL-Impl/Modules/RTOS/pal_rtos.c"
    "${PAL}/Source/PAL-Impl/Modules/Networking/pal_network.c"
    "${PAL}/Source/PAL-Impl/Modules/Storage/FileSystem/pal_fileSystem.c"
)
target_include_directories(macos-pal-adapters PUBLIC
    "${PAL}/Source" "${PAL}/Source/PAL-Impl/Services-API"
    "${PAL}/Source/Port/Platform-API" "${CLIENT}/mbed-trace")
target_compile_definitions(macos-pal-adapters PUBLIC
    MBED_CONF_MBED_TRACE_ENABLE=0
    PAL_USER_DEFINED_CONFIGURATION="${EDGE_ROOT}/config/sotp_fs_macos.h"
    PAL_PLATFORM_DEFINED_CONFIGURATION="${EDGE_ROOT}/config/pal_macos.h"
    PAL_FS_MOUNT_POINT_PRIMARY="./pal-test-storage"
    PAL_FS_MOUNT_POINT_SECONDARY="./pal-test-storage"
)
target_compile_options(macos-pal-adapters PRIVATE -Wall -Wextra)
set_source_files_properties("${PORT}/RTOS/pal_plat_rtos.c"
    "${PORT}/Board_Specific/TARGET_aarch64/pal_plat_aarch64.c"
    PROPERTIES COMPILE_OPTIONS -Werror)
target_link_libraries(macos-pal-adapters PUBLIC Threads::Threads)
find_library(PAL_SYSTEM_CONFIGURATION SystemConfiguration REQUIRED)
find_library(PAL_CORE_FOUNDATION CoreFoundation REQUIRED)
target_link_libraries(macos-pal-adapters PUBLIC ${PAL_SYSTEM_CONFIGURATION} ${PAL_CORE_FOUNDATION})
add_executable(macos-pal-tests macos_pal_tests.c)
target_compile_options(macos-pal-tests PRIVATE -Wall -Wextra -Werror)
target_link_libraries(macos-pal-tests PRIVATE macos-pal-adapters)
enable_testing()
add_test(NAME macos-pal-runtime COMMAND macos-pal-tests)
set_tests_properties(macos-pal-runtime PROPERTIES TIMEOUT 45)
add_executable(macos-network-tests macos_network_tests.c)
target_compile_options(macos-network-tests PRIVATE -Wall -Wextra -Werror)
target_link_libraries(macos-network-tests PRIVATE macos-pal-adapters)
add_test(NAME macos-pal-network COMMAND macos-network-tests)
set_tests_properties(macos-pal-network PROPERTIES TIMEOUT 45)
add_executable(macos-options-tests macos_options_tests.c)
target_include_directories(macos-options-tests PRIVATE "${EDGE_ROOT}/edge-core")
target_compile_options(macos-options-tests PRIVATE -Wall -Wextra -Werror)
add_test(NAME macos-core-options COMMAND macos-options-tests)
if(TARGET edge-core)
    add_executable(macos-provisioning-tests macos_provisioning_tests.c
        "${EDGE_ROOT}/edge-core/windows/json2cbor_windows.c" "${EDGE_ROOT}/common/read_file.c")
    target_compile_definitions(macos-provisioning-tests PRIVATE MBED_CONF_MBED_TRACE_ENABLE=0)
    target_compile_options(macos-provisioning-tests PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(macos-provisioning-tests PRIVATE jansson tinycbor)
    add_test(NAME macos-core-provisioning COMMAND macos-provisioning-tests)
    set_tests_properties(macos-core-provisioning PROPERTIES TIMEOUT 15)
    add_test(NAME macos-core-unprovisioned COMMAND ${CMAKE_COMMAND}
        "-DEDGE_EXE=$<TARGET_FILE:edge-core>" "-DTEST_ROOT=${CMAKE_CURRENT_BINARY_DIR}/startup-tests"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/unprovisioned-startup.cmake")
    set_tests_properties(macos-core-unprovisioned PROPERTIES TIMEOUT 20)
    add_executable(macos-status-tests macos_status_tests.c
        "${EDGE_ROOT}/edge-core/http_server.c" "${EDGE_ROOT}/edge-core/status_public.c"
        "${EDGE_ROOT}/edge-core/listener_status.c" "${EDGE_ROOT}/edge-core/listener_address.c")
    target_include_directories(macos-status-tests PRIVATE "${EDGE_ROOT}/edge-core")
    target_compile_definitions(macos-status-tests PRIVATE MBED_CONF_MBED_TRACE_ENABLE=0)
    target_compile_options(macos-status-tests PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(macos-status-tests PRIVATE event event_pthreads jansson Threads::Threads)
    add_test(NAME macos-core-status COMMAND macos-status-tests)
    set_tests_properties(macos-core-status PROPERTIES TIMEOUT 30)
endif()
option(MACOS_PAL_TEST_TLS "Test the shared OpenSSL backend over Darwin PAL sockets" ${MBED_CLOUD_CLIENT_USE_OPENSSL})
if(MACOS_PAL_TEST_TLS)
    find_package(OpenSSL 3.0 REQUIRED)
    add_executable(macos-tls-tests macos_tls_tests.c
        "${PAL}/Source/Port/Reference-Impl/Lib_Specific/OpenSSL/TLS/pal_plat_TLS.c")
    target_include_directories(macos-tls-tests PRIVATE
        "${CLIENT}/factory-configurator-client/crypto-service/crypto-service"
        "${CLIENT}/nanostack-libservice/mbed-client-libservice"
        "${CLIENT}/sal-stack-nanostack-eventloop"
        "${CLIENT}/sal-stack-nanostack-eventloop/nanostack-event-loop")
    target_compile_definitions(macos-tls-tests PRIVATE MBED_CONF_MBED_CLOUD_CLIENT_USE_OPENSSL=1 PAL_USE_SECURE_TIME=0)
    set_source_files_properties(macos_tls_tests.c PROPERTIES COMPILE_OPTIONS "-Wall;-Wextra;-Werror")
    target_link_libraries(macos-tls-tests PRIVATE macos-pal-adapters OpenSSL::SSL OpenSSL::Crypto)
    add_test(NAME macos-pal-tls COMMAND macos-tls-tests)
    set_tests_properties(macos-pal-tls PROPERTIES TIMEOUT 30)
    add_executable(macos-crypto-tests "${EDGE_ROOT}/test/windows-pal/windows_pal_crypto_tests.c"
        "${CLIENT}/factory-configurator-client/crypto-service/source/cs_pal_plat_crypto_openssl.c")
    target_include_directories(macos-crypto-tests PRIVATE
        "${CLIENT}/mbed-client"
        "${CLIENT}/factory-configurator-client/crypto-service/crypto-service"
        "${CLIENT}/factory-configurator-client/utils/utils")
    target_compile_definitions(macos-crypto-tests PRIVATE MBED_CONF_MBED_CLOUD_CLIENT_USE_OPENSSL=1 PAL_USE_SECURE_TIME=0)
    target_link_libraries(macos-crypto-tests PRIVATE macos-pal-adapters OpenSSL::Crypto)
    add_test(NAME macos-pal-crypto COMMAND macos-crypto-tests)
    set_tests_properties(macos-pal-crypto PROPERTIES TIMEOUT 15)
endif()
