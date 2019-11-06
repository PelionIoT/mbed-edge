INCLUDE(CMakeForceCompiler)
# CROSS COMPILER SETTING

cmake_minimum_required (VERSION 2.8)
SET(CMAKE_SYSTEM_NAME Generic)

# This defines the name of the test's executable
project(authorization-api-unittests)

add_definitions(-DMBED_CLIENT_USER_CONFIG_FILE=\"mbed_cloud_client_user_config_test.h\")
add_definitions(-DMBED_CLOUD_CLIENT_USER_CONFIG_FILE=\"mbed_cloud_client_user_config_test.h\")
add_definitions(-DPROTOMAN_USER_CONFIG_FILE=\"mbed_cloud_client_user_config_test.h\")
add_definitions(-DPAL_USER_DEFINED_CONFIGURATION=\"sotp_fs.h\")

option(MBED_CLOUD_CLIENT_SUPPORT_UPDATE "Enable Update Client" ON)

add_definitions(-DMBED_CONF_MBED_TRACE_ENABLE)
add_definitions(-DMBED_CONF_MBED_CLIENT_ENABLE_CPP_API)
add_definitions(-DPAL_CMAC_SUPPORT=false)
add_definitions(-DPAL_X509_SUPPORT=0)
add_definitions(-DMAX_FIRMWARE_LOCATIONS=1)
add_definitions(-DMBED_CLOUD_CLIENT_UPDATE_STORAGE=ARM_UCP_LINUX_YOCTO_RPI)
add_definitions(-DARM_UC_USE_KCM=0)
add_definitions(-DARM_UC_FEATURE_CRYPTO_MBEDTLS=1)
add_definitions(-DARM_UC_FEATURE_CRYPTO_PAL=0)
add_definitions(-DARM_UC_USE_RAW_CONFIG=1)
add_definitions(-DARM_UC_ENABLE_PSK=1)

add_definitions(-DMBED_CONF_APP_DEVELOPER_MODE=1)
add_definitions(-DARM_UC_PROFILE_MBED_CLIENT_LITE=0)
add_definitions(-DARM_UC_PROFILE_MBED_CLOUD_CLIENT=1)
add_definitions(-DMBED_CONF_MBED_CLOUD_CLIENT_UPDATE_DOWNLOAD_PROTOCOL=MBED_CLOUD_CLIENT_UPDATE_DOWNLOAD_PROTOCOL_HTTP)

OPTION( ENABLE_CODECOVERAGE "Enable code coverage testing support" )

if ( ENABLE_CODECOVERAGE )

    if ( NOT CMAKE_BUILD_TYPE STREQUAL "Debug" )
        message( WARNING "Code coverage results with an optimised (non-Debug) build may be misleading" )
    endif ( NOT CMAKE_BUILD_TYPE STREQUAL "Debug" )

    if ( NOT DEFINED CODECOV_OUTPUTFILE )
        set( CODECOV_OUTPUTFILE cmake_coverage.output )
    endif ( NOT DEFINED CODECOV_OUTPUTFILE )

    if ( NOT DEFINED CODECOV_HTMLOUTPUTDIR )
        set( CODECOV_HTMLOUTPUTDIR coverage_results )
    endif ( NOT DEFINED CODECOV_HTMLOUTPUTDIR )

    SET(GCC_COVERAGE_COMPILE_FLAGS "-fprofile-arcs -ftest-coverage -g -Wall -Wextra -Wshadow -Wswitch-default -Wswitch-enum -Wconversion")
    SET(GCC_COVERAGE_LINK_FLAGS    "-lgcov --coverage ")
    add_definitions(${GCC_COVERAGE_COMPILE_FLAGS})

    SET( CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${GCC_COVERAGE_COMPILE_FLAGS}" )
    SET( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}" )


    find_program( CODECOV_GCOV gcov )
    find_program( CODECOV_LCOV lcov )
    find_program( CODECOV_GENHTML genhtml )
    add_definitions( -fprofile-arcs -ftest-coverage )
    link_libraries( gcov )
    set( CMAKE_EXE_LINKER_FLAGS ${CMAKE_EXE_LINKER_FLAGS} --coverage )
    add_custom_target( coverage_init ALL ${CODECOV_LCOV} --base-directory .  --directory ${CMAKE_BINARY_DIR} --output-file ${CODECOV_OUTPUTFILE} --capture --initial )
    add_custom_target( coverage ${CODECOV_LCOV} --base-directory .  --directory ${CMAKE_BINARY_DIR} --output-file ${CODECOV_OUTPUTFILE} --capture COMMAND genhtml -o ${CODECOV_HTMLOUTPUTDIR} ${CODECOV_OUTPUTFILE} )

    execute_process(COMMAND lcov --zerocounters  --directory .
         WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
endif (ENABLE_CODECOVERAGE )

SET(UTEST_CPPFLAGS "-DTARGET_LIKE_POSIX -DMBED_CLOUD_CLIENT_SUPPORT_UPDATE  -DMBED_CLOUD_DEV_UPDATE_ID-DARM_UC_ALL_TRACE_ENABLE=1 -DTARGET_IS_PC_LINUX")

SET( CMAKE_C_FLAGS  "${CMAKE_CXX_FLAGS} -std=gnu99 ${UTEST_CPPFLAGS}" )
SET( CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${UTEST_CPPFLAGS}" )

# Run clone dependencies to get external modules
execute_process(COMMAND ./clone_dependencies.sh
     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
     )

include_directories(${CMAKE_CURRENT_SOURCE_DIR}
    "${CMAKE_CURRENT_SOURCE_DIR}/../test_modules/mbedtls"
    "${CMAKE_CURRENT_SOURCE_DIR}/../test_modules/mbedtls/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/source"
    "${CMAKE_CURRENT_SOURCE_DIR}/../common"
    "${CMAKE_CURRENT_SOURCE_DIR}/../test_modules/mbed-client-pal/Source"
    "${CMAKE_CURRENT_SOURCE_DIR}/../test_modules/mbed-client-pal/Source/PAL-Impl/Services-API"
    "${CMAKE_CURRENT_SOURCE_DIR}/../test_modules/mbed-client-pal/Source/Port/Platform-API"
    "${CMAKE_CURRENT_SOURCE_DIR}/../test_modules/mbed-client-pal/Configs/pal_config/Linux/TARGET_x86_x64"
    "${CMAKE_CURRENT_SOURCE_DIR}/../test_modules/mbed-client-pal/Configs/pal_config/Linux/"
    "${CMAKE_CURRENT_SOURCE_DIR}/../test_modules/mbed-client-pal/Configs/pal_config/"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../TESTS/stubs"
    "${CMAKE_CURRENT_SOURCE_DIR}/stubs"
    "${CMAKE_CURRENT_SOURCE_DIR}/stubs/update-client-firmware-manager"
    "${CMAKE_CURRENT_SOURCE_DIR}/stubs/update-client-source-manager"
    "${CMAKE_CURRENT_SOURCE_DIR}/stubs/update-client-manifest-manager"
    "${CMAKE_CURRENT_SOURCE_DIR}/TESTS/unit/authorization_api"
    "${CMAKE_CURRENT_SOURCE_DIR}/update-client-linux-test-framework"
    "${CMAKE_CURRENT_SOURCE_DIR}/update-client-linux-test-framework/utest"
    "${CMAKE_CURRENT_SOURCE_DIR}/update-client-linux-test-framework/mbed-events"
    "${CMAKE_CURRENT_SOURCE_DIR}/update-client-control-center"
    "${CMAKE_CURRENT_SOURCE_DIR}/../atomic-queue"
    "${CMAKE_CURRENT_SOURCE_DIR}/../atomic-queue/atomic-queue"
    "${CMAKE_CURRENT_SOURCE_DIR}/../monitor"
    "${CMAKE_CURRENT_SOURCE_DIR}/../monitor/update-client-monitor"
    "${CMAKE_CURRENT_SOURCE_DIR}/../device-identity"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../source"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../mbed-client"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../mbed-client/mbed-client-c"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../mbed-client/mbed-client-c/nsdl-c"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../mbed-client/mbed-client"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../mbed-client/source"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../mbed-client/source/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../mbed-client/mbed-protocol-manager"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../mbed-client/mbed-protocol-manager/source"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../mbed-client/mbed-protocol-manager/mbed-protocol-manager"
   )

FILE(GLOB UNITTESTS_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/stubs/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/stubs/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/stubs/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/stubs/update-client-firmware-manager/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/stubs/update-client-source-manager/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/stubs/update-client-manifest-manager/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/stubs/update-client-firmware-manager/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/stubs/update-client-source-manager/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/stubs/update-client-manifest-manager/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/stubs/arm_uc_scheduler_stub.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/source/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/TESTS/unit/authorization_api/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../common/source/arm_uc_utilities.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/update-client-control-center/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../source/update_client_hub_error_handler.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../source/update_client_hub_error_handler.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../source/update_client_hub_event_handlers.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../source/update_client_hub_event_handlers.c"
    )


# Call CREATE_TEST_LIBRARY with the above list of sources
CREATE_TEST_LIBRARY(${PROJECT_NAME} "${UNITTESTS_SRC}" "")

# Alwasy remember to call ADDSUBDIRS() at the end of your CMakeLists.txt
ADDSUBDIRS()
