function(WRITE_CONFIG_HEADER)
  set (NEW_CONFIG "${CMAKE_CURRENT_SOURCE_DIR}/config/edge_version_info.h.new")
  set (TARGET_CONFIG "${CMAKE_CURRENT_SOURCE_DIR}/config/edge_version_info.h")
  file(READ ${CMAKE_CURRENT_SOURCE_DIR}/config/header_template.txt HEADER_TEMPLATE)
  file(WRITE ${NEW_CONFIG} ${HEADER_TEMPLATE})
  file(APPEND ${NEW_CONFIG} "#ifndef EDGE_CONFIG_INFO_H\n")
  file(APPEND ${NEW_CONFIG} "#define EDGE_CONFIG_INFO_H\n")
  file(APPEND ${NEW_CONFIG} "#define GIT_DIRTY \"${GIT_DIRTY}\"\n")
  file(APPEND ${NEW_CONFIG} "#define RELEASE_VERSION \"${RELEASE_VERSION}\"\n")
  file(APPEND ${NEW_CONFIG} "#define GIT_BRANCH \"${GIT_BRANCH}\"\n")
  file(APPEND ${NEW_CONFIG} "#define GIT_COMMIT \"${GIT_COMMIT}\"\n")
  file(APPEND ${NEW_CONFIG} "#endif\n")
  file(APPEND ${NEW_CONFIG} "#ifdef GIT_DIRTY\n")
  file(APPEND ${NEW_CONFIG} "#define VERSION_STRING RELEASE_VERSION\"-\"GIT_BRANCH\"-\"GIT_COMMIT\"-\"GIT_DIRTY\n")
  file(APPEND ${NEW_CONFIG} "#else\n")
  file(APPEND ${NEW_CONFIG} "#define VERSION_STRING RELEASE_VERSION\"-\"GIT_BRANCH\"-\"GIT_COMMIT\n")
  file(APPEND ${NEW_CONFIG} "#endif\n")

  exec_program(
    "diff"
    ${CMAKE_CURRENT_SOURCE_DIR}
    ARGS "${NEW_CONFIG} ${TARGET_CONFIG}"
    OUTPUT_VARIABLE DIFF_OUTPUT)
  if (NOT ${DIFF_OUTPUT} STREQUAL "")
    file (REMOVE ${TARGET_CONFIG})
    file(RENAME ${NEW_CONFIG} ${TARGET_CONFIG})
  else()
    file (REMOVE ${NEW_CONFIG})
  endif()
endfunction()

function(CHECK_GIT_ROOT)
  exec_program(
    "git"
    ${CMAKE_CURRENT_SOURCE_DIR}
    ARGS "status"
    OUTPUT_VARIABLE RELEASE_VERSION
    RETURN_VALUE RETVAL)

  if(NOT ${RETVAL} EQUAL 0)
    message (WARNING "Not a Git Root '${CMAKE_CURRENT_SOURCE_DIR}'.")
  endif()
endfunction()

function(SET_EDGE_VERSION_VARIABLES)
    exec_program(
      "git"
      ${CMAKE_CURRENT_SOURCE_DIR}
      ARGS "describe --abbrev=0 --tags"
      OUTPUT_VARIABLE RELEASE_VERSION
      RETURN_VALUE RETVAL)

    if(${RETVAL} EQUAL 0)
      exec_program(
        "git"
        ${CMAKE_CURRENT_SOURCE_DIR}
        ARGS "rev-parse --abbrev-ref HEAD"
        OUTPUT_VARIABLE GIT_BRANCH)

      exec_program(
        "git"
        ${CMAKE_CURRENT_SOURCE_DIR}
        ARGS "rev-parse HEAD"
        OUTPUT_VARIABLE GIT_COMMIT)

      exec_program(
        "git"
        ${CMAKE_CURRENT_SOURCE_DIR}
        ARGS "diff --shortstat"
        OUTPUT_VARIABLE GIT_DIRTY)

      set(RELEASE_VERSION "${RELEASE_VERSION}" CACHE INTERNAL "Edge release version")
      set(GIT_BRANCH "${GIT_BRANCH}" CACHE INTERNAL "Edge Git branch")
      set(GIT_COMMIT "${GIT_COMMIT}" CACHE INTERNAL "Edge Git commit")

      if(NOT ${GIT_DIRTY} STREQUAL "")
        set(GIT_DIRTY dirty CACHE INTERNAL "Edge Git if dirty")
      else(NOT ${GIT_DIRTY} STREQUAL "")
        unset(GIT_DIRTY)
      endif(NOT ${GIT_DIRTY} STREQUAL "")
      set(WRITE_VERSION_FILE 1 CACHE INTERNAL "Edge version file write")
    else()
      message("Inited Git root, but does not have history.")
      message("Checking if 'config/edge_version_info.h` exists.")
      if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/config/edge_version_info.h")
        message("The `config/edge_version_info.h` file exists.")
        message("Use the versioning information from the file.")
        set(WRITE_VERSION_FILE 0 CACHE INTERNAL "Edge version file write")
      else()
        message("The version file 'config/edge_version_info.h` not available.")
        message("Setting dummy values to versioning variables.")
        set(RELEASE_VERSION "unknown-release" CACHE INTERNAL "Edge release version")
        set(GIT_BRANCH "branchless" CACHE INTERNAL "Edge Git branch")
        set(GIT_COMMIT "uncommited" CACHE INTERNAL "Edge Git commit")
        set(GIT_DIRTY "uninited" CACHE INTERNAL "Edge Git if dirty")
        set(WRITE_VERSION_FILE 1 CACHE INTERNAL "Edge version file write")
      endif()
    endif()
endfunction()

function(UPDATE_EDGE_VERSION)
  CHECK_GIT_ROOT()
  SET_EDGE_VERSION_VARIABLES()
  if (WRITE_VERSION_FILE)
    WRITE_CONFIG_HEADER()
  endif()
endfunction(UPDATE_EDGE_VERSION)

UPDATE_EDGE_VERSION()
