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
add_test(NAME windows-core-websocket COMMAND windows-websocket-tests)
set_tests_properties(windows-core-websocket PROPERTIES TIMEOUT 15)
add_executable(windows-client-timer-tests windows_client_timer_tests.cpp)
target_link_libraries(windows-client-timer-tests mbedCloudClient)
target_compile_options(windows-client-timer-tests PRIVATE /W4 /WX)
add_dependencies(windows-client-timer-tests edge-core)
add_test(NAME windows-client-timer COMMAND windows-client-timer-tests)
set_tests_properties(windows-client-timer PROPERTIES TIMEOUT 15)
if (BYOC_MODE AND NOT DEVELOPER_MODE)
  add_test(NAME windows-core-unprovisioned
    COMMAND ${CMAKE_COMMAND} "-DEDGE_EXE=$<TARGET_FILE:edge-core>"
            "-DTEST_ROOT=${CMAKE_CURRENT_BINARY_DIR}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/unprovisioned-startup.cmake")
  set_tests_properties(windows-core-unprovisioned PROPERTIES TIMEOUT 20)
endif ()
