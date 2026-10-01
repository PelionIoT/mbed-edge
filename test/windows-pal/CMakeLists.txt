cmake_minimum_required(VERSION 3.22)
project(windows_pal_tests C)
if(NOT WIN32 OR NOT MSVC OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "These tests require native MSVC x64.")
endif()
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
get_filename_component(EDGE_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
set(CLIENT "${EDGE_ROOT}/lib/mbed-cloud-client")
set(PAL "${CLIENT}/mbed-client-pal")
set(PORT "${PAL}/Source/Port/Reference-Impl/OS_Specific/Windows")
add_library(windows-pal-adapters STATIC
    "${PORT}/RTOS/pal_plat_rtos.c"
    "${PORT}/Board_Specific/TARGET_x86_x64/pal_plat_x86_x64.c"
    "${PORT}/Storage/FileSystem/pal_plat_fileSystem.c"
    "${PORT}/Networking/pal_plat_network.c"
    "${PAL}/Source/PAL-Impl/Modules/RTOS/pal_rtos.c"
    "${PAL}/Source/PAL-Impl/Modules/Networking/pal_network.c"
    "${PAL}/Source/PAL-Impl/Modules/Storage/FileSystem/pal_fileSystem.c"
)
target_include_directories(windows-pal-adapters PUBLIC
    "${PAL}/Source" "${PAL}/Source/PAL-Impl/Services-API"
    "${PAL}/Source/Port/Platform-API" "${CLIENT}/mbed-trace")
target_compile_definitions(windows-pal-adapters PUBLIC
    WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00 _CRT_SECURE_NO_WARNINGS
    MBED_CONF_MBED_TRACE_ENABLE=0
    PAL_USER_DEFINED_CONFIGURATION="${EDGE_ROOT}/config/sotp_fs_windows.h"
    PAL_PLATFORM_DEFINED_CONFIGURATION="${EDGE_ROOT}/config/pal_windows.h"
    PAL_FS_MOUNT_POINT_PRIMARY="./pal-test-storage"
    PAL_FS_MOUNT_POINT_SECONDARY="./pal-test-storage"
)
target_compile_options(windows-pal-adapters PRIVATE /W4)
set_source_files_properties(windows_pal_tests.c
    "${PORT}/RTOS/pal_plat_rtos.c"
    "${PORT}/Board_Specific/TARGET_x86_x64/pal_plat_x86_x64.c"
    "${PORT}/Storage/FileSystem/pal_plat_fileSystem.c"
    "${PORT}/Networking/pal_plat_network.c"
    PROPERTIES COMPILE_OPTIONS /WX)
target_link_libraries(windows-pal-adapters PUBLIC ws2_32 bcrypt iphlpapi)
add_executable(windows-pal-tests windows_pal_tests.c)
target_compile_options(windows-pal-tests PRIVATE /W4 /WX)
target_link_libraries(windows-pal-tests PRIVATE windows-pal-adapters)
enable_testing()
add_test(NAME windows-pal-runtime COMMAND windows-pal-tests)
set_tests_properties(windows-pal-runtime PROPERTIES TIMEOUT 45)

add_executable(windows-edge-common-tests windows_edge_common_tests.c
    "${EDGE_ROOT}/common/edge_time.c"
    "${EDGE_ROOT}/common/read_file.c"
    "${EDGE_ROOT}/common/edge-mutex/edge_mutex.c"
    "${EDGE_ROOT}/common/edge-io-lib/edge_io_windows.c")
target_include_directories(windows-edge-common-tests PRIVATE "${EDGE_ROOT}/include" "${EDGE_ROOT}/common")
target_compile_options(windows-edge-common-tests PRIVATE /W4 /WX)
target_link_libraries(windows-edge-common-tests PRIVATE windows-pal-adapters)
add_dependencies(windows-pal-tests windows-edge-common-tests)
add_test(NAME windows-edge-common COMMAND windows-edge-common-tests)
set_tests_properties(windows-edge-common PROPERTIES TIMEOUT 15)

add_executable(windows-pal-rot-tests windows_pal_rot_tests.c
    "${PAL}/Source/Port/Reference-Impl/Generic/ROT/FileBased/pal_plat_rot_file.c")
target_include_directories(windows-pal-rot-tests PRIVATE
    "${CLIENT}/factory-configurator-client/storage/storage"
    "${CLIENT}/factory-configurator-client/storage/source/include"
    "${CLIENT}/factory-configurator-client/key-config-manager/key-config-manager"
    "${CLIENT}/factory-configurator-client/crypto-service/crypto-service"
    "${CLIENT}/factory-configurator-client/crypto-service/source/include"
    "${CLIENT}/factory-configurator-client/mbed-client-esfs/source/include")
target_compile_definitions(windows-pal-rot-tests PRIVATE PAL_USE_ROT_FROM_FILE=1)
target_compile_options(windows-pal-rot-tests PRIVATE /W4)
set_source_files_properties(windows_pal_rot_tests.c PROPERTIES COMPILE_OPTIONS /WX)
target_link_libraries(windows-pal-rot-tests PRIVATE windows-pal-adapters)
add_dependencies(windows-pal-tests windows-pal-rot-tests)
add_test(NAME windows-pal-file-rot COMMAND windows-pal-rot-tests)
set_tests_properties(windows-pal-file-rot PROPERTIES TIMEOUT 45)

option(WINDOWS_PAL_TEST_TLS "Test shared OpenSSL TLS over Windows PAL sockets and crypto" ON)
if(WINDOWS_PAL_TEST_TLS)
    find_package(OpenSSL 3.0 REQUIRED)
    add_executable(windows-pal-tls-tests windows_pal_tls_tests.c
        "${PAL}/Source/Port/Reference-Impl/Lib_Specific/OpenSSL/TLS/pal_plat_TLS.c")
    target_include_directories(windows-pal-tls-tests PRIVATE
        "${CLIENT}/factory-configurator-client/crypto-service/crypto-service")
    target_include_directories(windows-pal-tls-tests SYSTEM PRIVATE
        "${CLIENT}/nanostack-libservice/mbed-client-libservice"
        "${CLIENT}/sal-stack-nanostack-eventloop"
        "${CLIENT}/sal-stack-nanostack-eventloop/nanostack-event-loop")
    target_compile_definitions(windows-pal-tls-tests PRIVATE
        MBED_CONF_MBED_CLOUD_CLIENT_USE_OPENSSL=1 PAL_USE_SECURE_TIME=0)
    target_compile_options(windows-pal-tls-tests PRIVATE /W4)
    set_source_files_properties(windows_pal_tls_tests.c PROPERTIES COMPILE_OPTIONS /WX)
    target_link_libraries(windows-pal-tls-tests PRIVATE windows-pal-adapters OpenSSL::SSL OpenSSL::Crypto)
    add_dependencies(windows-pal-tests windows-pal-tls-tests)
    add_test(NAME windows-pal-openssl COMMAND windows-pal-tls-tests)
    set_tests_properties(windows-pal-openssl PROPERTIES TIMEOUT 45)
    add_executable(windows-pal-crypto-tests windows_pal_crypto_tests.c
        "${CLIENT}/factory-configurator-client/crypto-service/source/cs_pal_plat_crypto_openssl.c")
    target_include_directories(windows-pal-crypto-tests PRIVATE
        "${CLIENT}/mbed-client"
        "${CLIENT}/factory-configurator-client/crypto-service/crypto-service"
        "${CLIENT}/factory-configurator-client/utils/utils")
    target_compile_definitions(windows-pal-crypto-tests PRIVATE
        MBED_CONF_MBED_CLOUD_CLIENT_USE_OPENSSL=1 PAL_USE_SECURE_TIME=0)
    target_compile_options(windows-pal-crypto-tests PRIVATE /W4)
    set_source_files_properties(windows_pal_crypto_tests.c PROPERTIES COMPILE_OPTIONS /WX)
    target_link_libraries(windows-pal-crypto-tests PRIVATE windows-pal-adapters OpenSSL::Crypto)
    add_dependencies(windows-pal-tests windows-pal-crypto-tests)
    add_test(NAME windows-pal-openssl-crypto COMMAND windows-pal-crypto-tests)
    set_tests_properties(windows-pal-openssl-crypto PROPERTIES TIMEOUT 45)
    if(OPENSSL_ROOT_DIR AND EXISTS "${OPENSSL_ROOT_DIR}/bin")
        # Shared native OpenSSL DLLs are found only in the test process.
        set_tests_properties(windows-pal-openssl windows-pal-openssl-crypto PROPERTIES
            ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${OPENSSL_ROOT_DIR}/bin")
    endif()
endif()
