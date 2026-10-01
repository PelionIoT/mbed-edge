# Exercise real startup and its timestamp logger without using any identity.
string(RANDOM LENGTH 16 ALPHABET 0123456789abcdef run_id)
set(run_dir "${TEST_ROOT}/unprovisioned-${run_id}")
file(MAKE_DIRECTORY "${run_dir}")
execute_process(COMMAND "${EDGE_EXE}" --http-port 0
                WORKING_DIRECTORY "${run_dir}" TIMEOUT 15
                RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE errors)
# Retain the isolated storage and logs for diagnosis. The build tree is ignored.
file(WRITE "${run_dir}/stdout.log" "${output}")
file(WRITE "${run_dir}/stderr.log" "${errors}")
if (NOT "${result}" STREQUAL "1" OR
    NOT output MATCHES "Device not configured for Device Management - exit" OR
    output MATCHES "unexpected filesystem behavior|Failed to do factory reset")
  message(FATAL_ERROR "Unprovisioned startup failed (${result}); logs: ${run_dir}\n${output}\n${errors}")
endif ()
message(STATUS "Unprovisioned startup exited normally with code 1; logs: ${run_dir}")
