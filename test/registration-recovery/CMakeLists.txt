enable_language(CXX)
add_executable(registration-recovery-tests registration_recovery_tests.cpp
    ../../edge-core/edge_network_policy.c)
target_compile_features(registration-recovery-tests PRIVATE cxx_std_17)
target_include_directories(registration-recovery-tests PRIVATE
    "${ROOT_HOME}" "${ROOT_HOME}/edge-core"
    "${ROOT_HOME}/lib/mbed-cloud-client/mbed-client/source"
    "${ROOT_HOME}/lib/mbed-cloud-client/mbed-client/mbed-client-c"
    "${ROOT_HOME}/lib/mbed-cloud-client/mbed-client/mbed-client-c/source/include")
target_link_libraries(registration-recovery-tests PRIVATE mbedCloudClient)
if(MSVC)
  target_compile_options(registration-recovery-tests PRIVATE /W4 /WX)
else()
  target_compile_options(registration-recovery-tests PRIVATE -Wall -Wextra -Werror)
endif()
add_test(NAME sdk-registration-recovery COMMAND registration-recovery-tests)
set_tests_properties(sdk-registration-recovery PROPERTIES TIMEOUT 20
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
if(TARGET windows-core-tests)
  add_dependencies(windows-core-tests registration-recovery-tests)
endif()
