#!/bin/bash
# Execute script with parameters:
# - filepath where to find test binary, for example: ./__x86_x64_NativeLinux/Debug/lwm2m-source-unittests.elf
# - coverage output file name, for example: lwm2m_source.info
set -e

# Give paramter of output filename!
if [ $# -eq 0 ]
  then
     echo "Give 1st parameter of test binary, for example ./__x86_x64_NativeLinux/Debug/lwm2m-source-unittests.elf"
     echo "Give 2nd parameter the name of coverage output filename, for example: lwm2m_source.info"
     exit 1
fi

# If you want to run with valgrind:
# modify update-client-linux-test-framework/test_driver.py:
# p = subprocess.Popen([name]) 
# to
# p = subprocess.Popen(["/usr/bin/valgrind", "--track-origins=yes","-v","--leak-check=full",name])

python update-client-linux-test-framework/test_driver.py  $1
./run_coverage.sh $2

