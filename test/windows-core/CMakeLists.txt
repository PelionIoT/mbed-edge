add_executable(windows-websocket-tests windows_websocket_tests.c)
target_compile_options(windows-websocket-tests PRIVATE /W4 /WX)
target_link_libraries(windows-websocket-tests websockets event ws2_32)
# The application's post-build step places runtime DLLs in the shared bin dir.
add_dependencies(windows-websocket-tests edge-core)
add_test(NAME windows-core-help COMMAND edge-core --help)
set_tests_properties(windows-core-help PROPERTIES
    PASS_REGULAR_EXPRESSION "edge-pt-address" TIMEOUT 10)
add_test(NAME windows-core-version COMMAND edge-core --version)
set_tests_properties(windows-core-version PROPERTIES TIMEOUT 10)
add_test(NAME windows-core-options
    COMMAND ${CMAKE_COMMAND} "-DEDGE_EXE=$<TARGET_FILE:edge-core>"
        "-DTEST_ROOT=${CMAKE_CURRENT_BINARY_DIR}" "-DBYOC=${BYOC_MODE}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/windows-options.cmake")
set_tests_properties(windows-core-options PROPERTIES TIMEOUT 30)
add_test(NAME windows-core-websocket COMMAND windows-websocket-tests)
set_tests_properties(windows-core-websocket PROPERTIES TIMEOUT 15)
add_executable(windows-client-timer-tests windows_client_timer_tests.cpp)
target_link_libraries(windows-client-timer-tests mbedCloudClient)
target_compile_options(windows-client-timer-tests PRIVATE /W4 /WX)
add_dependencies(windows-client-timer-tests edge-core)
add_executable(windows-service-probe windows_service_probe.c ../../edge-core/windows/edge_service.c)
target_include_directories(windows-service-probe PRIVATE ../../edge-core/windows)
target_link_libraries(windows-service-probe advapi32 shell32)
target_compile_options(windows-service-probe PRIVATE /W4 /WX)
add_executable(windows-update-failure windows_update_failure.c ../../edge-core/windows/edge_service.c)
target_include_directories(windows-update-failure PRIVATE ../../edge-core/windows)
target_link_libraries(windows-update-failure advapi32 shell32)
target_compile_options(windows-update-failure PRIVATE /W4 /WX)
add_test(NAME windows-client-timer COMMAND windows-client-timer-tests)
set_tests_properties(windows-client-timer PROPERTIES TIMEOUT 15)
if (BYOC_MODE AND NOT DEVELOPER_MODE)
  add_executable(windows-provisioning-tests windows_provisioning_tests.c
      ../../edge-core/windows/json2cbor_windows.c ../../common/read_file.c)
  target_link_libraries(windows-provisioning-tests jansson tinycbor mbedTrace pal)
  target_compile_options(windows-provisioning-tests PRIVATE /W4 /WX)
  add_dependencies(windows-provisioning-tests edge-core)
  add_test(NAME windows-core-provisioning COMMAND windows-provisioning-tests)
  set_tests_properties(windows-core-provisioning PROPERTIES TIMEOUT 15)
  add_test(NAME windows-core-unprovisioned
    COMMAND ${CMAKE_COMMAND} "-DEDGE_EXE=$<TARGET_FILE:edge-core>"
            "-DTEST_ROOT=${CMAKE_CURRENT_BINARY_DIR}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/unprovisioned-startup.cmake")
  set_tests_properties(windows-core-unprovisioned PROPERTIES TIMEOUT 20)
endif ()
add_custom_target(windows-core-tests DEPENDS edge-core windows-websocket-tests
    windows-client-timer-tests windows-service-probe windows-update-failure)
if (TARGET windows-provisioning-tests)
  add_dependencies(windows-core-tests windows-provisioning-tests)
endif()
