#!/bin/bash

set -euxo pipefail

# This script may be used to generate test coverage report.
# It may be run in the cmake build directory using comand:
#
# ../test/generate_coverage.h
#
# After running this script 'coverage.html' directory is created
# and gcovr.xml. The latter may be visualized using the Jenkins Cobertura
# plugin.
#
# Note: GCOV_PREFIX and ORIG_BUILD_PATH may be used to adjust the directory paths for lcov
# if the absolute build path does not match with current location of the sources and executables.
# See https://stackoverflow.com/questions/40642912/cannot-generate-coverage-report-using-lcov

if [ "$#" -ne 1 ]; then
    echo "Illegal number of parameters"
    echo "Please supply the relative path to sources e.g. ../"
    exit 1
fi

if [ -z ${GCOV_PREFIX+x} ] || [ -z ${ORIG_BUILD_PATH+x} ] ; then
    SOURCE_PATH_ADJUST=""
else
    SOURCE_PATH_ADJUST="${ORIG_BUILD_PATH} => ${GCOV_PREFIX}/"
fi

rm -f coverage_all.info coverage.info

# For local viewing.
lcov ${SOURCE_PATH_ADJUST:+ --rc geninfo_adjust_src_path="${SOURCE_PATH_ADJUST}"} --base-directory . --directory . -c -o coverage_all.info
lcov ${SOURCE_PATH_ADJUST:+ --rc geninfo_adjust_src_path="${SOURCE_PATH_ADJUST}"} -q -r coverage_all.info "/usr*" -o coverage.info
lcov ${SOURCE_PATH_ADJUST:+ --rc geninfo_adjust_src_path="${SOURCE_PATH_ADJUST}"} -q -r coverage.info "*/CppUTest/*" -o coverage.info
lcov ${SOURCE_PATH_ADJUST:+ --rc geninfo_adjust_src_path="${SOURCE_PATH_ADJUST}"} -q -r coverage.info "*/CppUTestExt/*" -o coverage.info
lcov ${SOURCE_PATH_ADJUST:+ --rc geninfo_adjust_src_path="${SOURCE_PATH_ADJUST}"} -q -r coverage.info "*/test/*" -o coverage.info
lcov ${SOURCE_PATH_ADJUST:+ --rc geninfo_adjust_src_path="${SOURCE_PATH_ADJUST}"} -q -r coverage.info "*/lib/cpputest/src/Platforms/Gcc/*" -o coverage.info
lcov ${SOURCE_PATH_ADJUST:+ --rc geninfo_adjust_src_path="${SOURCE_PATH_ADJUST}"} -q -r coverage.info "*/lib/jansson/*" -o coverage.info
lcov ${SOURCE_PATH_ADJUST:+ --rc geninfo_adjust_src_path="${SOURCE_PATH_ADJUST}"} -q -r coverage.info "*/lib/jsonrpc/*" -o coverage.info
lcov ${SOURCE_PATH_ADJUST:+ --rc geninfo_adjust_src_path="${SOURCE_PATH_ADJUST}"} -q -r coverage.info "*/lib/libevent/*" -o coverage.info
lcov ${SOURCE_PATH_ADJUST:+ --rc geninfo_adjust_src_path="${SOURCE_PATH_ADJUST}"} -q -r coverage.info "*/lib/libwebsockets/*" -o coverage.info
lcov ${SOURCE_PATH_ADJUST:+ --rc geninfo_adjust_src_path="${SOURCE_PATH_ADJUST}"} -q -r coverage.info "*/lib/mbed-cloud-client/*" -o coverage.info
lcov ${SOURCE_PATH_ADJUST:+ --rc geninfo_adjust_src_path="${SOURCE_PATH_ADJUST}"} -q -r coverage.info "*/lib/mbedtls/*" -o coverage.info
genhtml --version
genhtml ${SOURCE_PATH_ADJUST:+ --rc geninfo_adjust_src_path="${SOURCE_PATH_ADJUST}"} -o coverage.html -t "Edge Core Server" --num-spaces 4 coverage.info

# For Cobertura in Jenkins.
gcovr --object-directory . --root "${1}" \
                           -e '/usr' \
                           -e '.*/CppUTest/.*' \
                           -e '.*/CppUTestExt/.*' \
                           -e '.*/test/.*' \
                           -e '.*/lib/cpputest/src/Platforms/Gcc/.*' \
                           -e '.*/lib/jansson/.*' \
                           -e '.*/lib/jsonrpc/.*' \
                           -e '.*/lib/libevent/.*' \
                           -e '.*/lib/libwebsockets/.*' \
                           -e '.*/lib/mbed-cloud-client/.*' \
                           -e '.*/lib/mbedtls/.*' \
                           -x -o ./gcovr.xml
