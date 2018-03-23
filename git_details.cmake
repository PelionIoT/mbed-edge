exec_program(
    "git"
    ${CMAKE_CURRENT_SOURCE_DIR}
    ARGS "status"
    OUTPUT_VARIABLE RELEASE_VERSION
    RETURN_VALUE RETVAL)

if(${RETVAL} EQUAL 0)
    exec_program(
        "git"
        ${CMAKE_CURRENT_SOURCE_DIR}
        ARGS "describe --abbrev=0 --tags"
        OUTPUT_VARIABLE RELEASE_VERSION)

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

    if(NOT ${GIT_DIRTY} STREQUAL "")
        set(GIT_DIRTY dirty)
        add_definitions(-DGIT_DIRTY=\"${GIT_DIRTY}\")
    else(NOT ${GIT_DIRTY} STREQUAL "")
        unset(GIT_DIRTY)
    endif(NOT ${GIT_DIRTY} STREQUAL "")

    add_definitions(-DRELEASE_VERSION=\"${RELEASE_VERSION}\")
    add_definitions(-DGIT_BRANCH=\"${GIT_BRANCH}\")
    add_definitions(-DGIT_COMMIT=\"${GIT_COMMIT}\")
endif(${RETVAL} EQUAL 0)
