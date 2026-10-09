execute_process(COMMAND /usr/bin/mktemp -d /private/tmp/edge-startup-XXXXXXXX
    RESULT_VARIABLE created OUTPUT_VARIABLE run_dir OUTPUT_STRIP_TRAILING_WHITESPACE)
if (NOT created EQUAL 0)
    message(FATAL_ERROR "Cannot create isolated startup directory.")
endif ()
execute_process(COMMAND "${EDGE_EXE}" --status-socket "${run_dir}/status.sock"
    --edge-pt-domain-socket "${run_dir}/pt.sock" --http-port 0
    WORKING_DIRECTORY "${run_dir}" TIMEOUT 15
    RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE errors)
file(MAKE_DIRECTORY "${TEST_ROOT}")
file(WRITE "${TEST_ROOT}/stdout.log" "${output}")
file(WRITE "${TEST_ROOT}/stderr.log" "${errors}")
set(failed FALSE)
if (NOT "${result}" STREQUAL "1" OR
    NOT output MATCHES "Device not configured for Device Management - exit" OR
    EXISTS "${run_dir}/status.sock")
    set(failed TRUE)
endif ()
execute_process(COMMAND "${EDGE_EXE}" --status-tcp --bind 0.0.0.0
    WORKING_DIRECTORY "${run_dir}" TIMEOUT 5
    RESULT_VARIABLE invalid_result ERROR_VARIABLE invalid_error)
file(REMOVE_RECURSE "${run_dir}")
if (failed OR NOT invalid_result EQUAL 1 OR NOT invalid_error MATCHES "TCP status requires")
    message(FATAL_ERROR "Startup/status cleanup checks failed; logs: ${TEST_ROOT}\n${output}\n${errors}")
endif ()
