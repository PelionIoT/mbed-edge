string(RANDOM LENGTH 16 ALPHABET 0123456789abcdef run_id)
set(root "${TEST_ROOT}/windows-options-${run_id}")
file(MAKE_DIRECTORY "${root}/state with spaces-é")
foreach(arguments IN ITEMS "--service" "--data-dir|relative" "--service-name|bad/name"
        "--data-dir" "--data-dir|C:/one|--data-dir|C:/two")
    string(REPLACE "|" ";" arguments "${arguments}")
    execute_process(COMMAND "${EDGE_EXE}" ${arguments}
        WORKING_DIRECTORY "${root}" TIMEOUT 5 RESULT_VARIABLE result
        OUTPUT_VARIABLE output ERROR_VARIABLE errors)
    if(NOT "${result}" STREQUAL "1")
        message(FATAL_ERROR "Invalid Windows arguments were accepted: ${arguments}: ${result}")
    endif()
endforeach()
execute_process(COMMAND "${EDGE_EXE}" --service --data-dir "${root}/state with spaces-é"
    WORKING_DIRECTORY "${root}" TIMEOUT 5 RESULT_VARIABLE result
    OUTPUT_VARIABLE output ERROR_VARIABLE errors)
if(NOT "${result}" STREQUAL "1" OR NOT errors MATCHES "SCM dispatcher failed: 1063" OR
        EXISTS "${root}/state with spaces-é/edge-core.lock")
    message(FATAL_ERROR "Service mode was accepted outside SCM: ${result}: ${errors}")
endif()
if(BYOC)
    execute_process(COMMAND "${EDGE_EXE}" --data-dir "${root}/state with spaces-é" --http-port 0
        WORKING_DIRECTORY "${root}" TIMEOUT 15 RESULT_VARIABLE result
        OUTPUT_VARIABLE output ERROR_VARIABLE errors)
    file(WRITE "${root}/stdout.log" "${output}")
    file(WRITE "${root}/stderr.log" "${errors}")
    if(NOT "${result}" STREQUAL "1" OR
            NOT output MATCHES "Device not configured for Device Management - exit" OR
            NOT EXISTS "${root}/state with spaces-é/mcc_config" OR EXISTS "${root}/mcc_config")
        message(FATAL_ERROR "Console PAL state-directory isolation failed (${result}): ${output} ${errors}")
    endif()
endif()
