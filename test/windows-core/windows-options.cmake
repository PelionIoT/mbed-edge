string(RANDOM LENGTH 16 ALPHABET 0123456789abcdef run_id)
set(root "${TEST_ROOT}/windows-options-${run_id}")
file(MAKE_DIRECTORY "${root}/state with spaces-é" "${root}/config-state")
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
foreach(config IN ITEMS "missing.json" "invalid.json")
    file(WRITE "${root}/invalid.json" "{\"schemaVersion\":1,\"pt\":{\"afUnix\":{\"enabled\":true}}}")
    execute_process(COMMAND "${EDGE_EXE}" --config "${root}/${config}" --data-dir "${root}/config-state"
        WORKING_DIRECTORY "${root}" TIMEOUT 5 RESULT_VARIABLE result
        OUTPUT_VARIABLE output ERROR_VARIABLE errors)
    if(NOT "${result}" STREQUAL "1" OR NOT errors MATCHES "Invalid or unreadable Edge runtime configuration" OR
            EXISTS "${root}/config-state/mcc_config")
        message(FATAL_ERROR "Invalid runtime config was not rejected before cloud initialization: ${result}: ${errors}")
    endif()
endforeach()
if(NOT AFUNIX)
    file(WRITE "${root}/enabled.json" "{\"schemaVersion\":1,\"pt\":{\"afUnix\":{\"enabled\":true,\"path\":\"C:/ipc/pt.sock\"}}}")
    execute_process(COMMAND "${EDGE_EXE}" --config "${root}/enabled.json" --data-dir "${root}/config-state"
        WORKING_DIRECTORY "${root}" TIMEOUT 5 RESULT_VARIABLE result
        OUTPUT_VARIABLE output ERROR_VARIABLE errors)
    if(NOT "${result}" STREQUAL "1" OR NOT errors MATCHES "AF_UNIX is unavailable in this Windows target build")
        message(FATAL_ERROR "Compiled-out AF_UNIX was not rejected: ${result}: ${errors}")
    endif()
endif()
if(NOT NAMEDPIPE)
    file(WRITE "${root}/pipe-enabled.json" "{\"schemaVersion\":1,\"pt\":{\"namedPipe\":{\"enabled\":true}}}")
    execute_process(COMMAND "${EDGE_EXE}" --config "${root}/pipe-enabled.json" --data-dir "${root}/config-state"
        WORKING_DIRECTORY "${root}" TIMEOUT 5 RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE errors)
    if(NOT "${result}" STREQUAL "1" OR NOT errors MATCHES "Named pipes are unavailable in this Windows build" OR
            EXISTS "${root}/config-state/mcc_config")
        message(FATAL_ERROR "Compiled-out named pipe was not rejected before cloud initialization: ${result}: ${errors}")
    endif()
endif()
execute_process(COMMAND "${EDGE_EXE}" --service --data-dir "${root}/state with spaces-é"
    WORKING_DIRECTORY "${root}" TIMEOUT 5 RESULT_VARIABLE result
    OUTPUT_VARIABLE output ERROR_VARIABLE errors)
if(NOT "${result}" STREQUAL "1" OR NOT errors MATCHES "SCM dispatcher failed: 1063" OR
        EXISTS "${root}/state with spaces-é/edge-core.lock")
    message(FATAL_ERROR "Service mode was accepted outside SCM: ${result}: ${errors}")
endif()
if(BYOC)
    execute_process(COMMAND "${EDGE_EXE}" --data-dir "${root}/state with spaces-é"
        --cbor-conf missing.cbor --json-conf missing.json
        WORKING_DIRECTORY "${root}" TIMEOUT 5 RESULT_VARIABLE result
        OUTPUT_VARIABLE output ERROR_VARIABLE errors)
    if(NOT "${result}" STREQUAL "1" OR NOT errors MATCHES "Specify only one runtime provisioning file" OR
            EXISTS "${root}/state with spaces-é/mcc_config")
        message(FATAL_ERROR "Ambiguous provisioning was not rejected before storage initialization: ${result}: ${errors}")
    endif()
    file(WRITE "${root}/disabled.json" "{\"schemaVersion\":1,\"pt\":{\"afUnix\":{\"enabled\":false}}}")
    execute_process(COMMAND "${EDGE_EXE}" --data-dir "${root}/state with spaces-é" --http-port 0 --config "${root}/disabled.json"
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
