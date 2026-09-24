cmake_minimum_required(VERSION 3.20)
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
add_executable(windows-pal-tests
    windows_pal_tests.c
    "${PORT}/RTOS/pal_plat_rtos.c"
    "${PORT}/Board_Specific/TARGET_x86_x64/pal_plat_x86_x64.c"
    "${PORT}/Storage/FileSystem/pal_plat_fileSystem.c"
    "${PORT}/Networking/pal_plat_network.c"
    "${PAL}/Source/PAL-Impl/Modules/RTOS/pal_rtos.c"
    "${PAL}/Source/PAL-Impl/Modules/Networking/pal_network.c"
    "${PAL}/Source/PAL-Impl/Modules/Storage/FileSystem/pal_fileSystem.c"
)
target_include_directories(windows-pal-tests PRIVATE
    "${PAL}/Source" "${PAL}/Source/PAL-Impl/Services-API"
    "${PAL}/Source/Port/Platform-API" "${CLIENT}/mbed-trace")
target_compile_definitions(windows-pal-tests PRIVATE
    WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00 _CRT_SECURE_NO_WARNINGS
    PAL_USER_DEFINED_CONFIGURATION="${EDGE_ROOT}/config/sotp_fs_windows.h"
    PAL_PLATFORM_DEFINED_CONFIGURATION="${EDGE_ROOT}/config/pal_windows.h"
    PAL_FS_MOUNT_POINT_PRIMARY="./pal-test-storage"
    PAL_FS_MOUNT_POINT_SECONDARY="./pal-test-storage"
)
target_compile_options(windows-pal-tests PRIVATE /W4)
set_source_files_properties(windows_pal_tests.c
    "${PORT}/RTOS/pal_plat_rtos.c"
    "${PORT}/Board_Specific/TARGET_x86_x64/pal_plat_x86_x64.c"
    "${PORT}/Storage/FileSystem/pal_plat_fileSystem.c"
    "${PORT}/Networking/pal_plat_network.c"
    PROPERTIES COMPILE_OPTIONS /WX)
target_link_libraries(windows-pal-tests PRIVATE ws2_32 bcrypt iphlpapi)
enable_testing()
add_test(NAME windows-pal-runtime COMMAND windows-pal-tests)
set_tests_properties(windows-pal-runtime PROPERTIES TIMEOUT 45)
