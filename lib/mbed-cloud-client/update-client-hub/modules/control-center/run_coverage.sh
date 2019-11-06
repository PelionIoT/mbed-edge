#!/bin/sh

# Give paramter of output filename!
if [ $# -eq 0 ]
  then
     echo "Give 1 parameter of output filename!"
     exit 1
fi

rm -rf ./lcov
rm -rf ./coverage
mkdir -p lcov
mkdir -p lcov/results
mkdir coverage

gcovr --object-directory ./coverage  --exclude-unreachable-branches -e '.*/update-client-linux-test-framework/.*' -e '.*/TESTS/.*' -e '.*/usr/.*' -x -o ./lcov/gcovr.xml
lcov --directory . --capture --output-file $1
genhtml -q $1 --show-details --output-directory lcov/html
genhtml --output-directory coverage   --demangle-cpp --num-spaces 2 --sort   --title "Test Coverage"   --function-coverage --branch-coverage --legend $1
