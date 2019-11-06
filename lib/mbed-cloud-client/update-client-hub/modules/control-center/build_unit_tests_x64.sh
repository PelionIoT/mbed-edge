#!/bin/sh
git clone git@github.com:ARMmbed/update-client-linux-test-framework.git
cp -R update-client-linux-test-framework/pal-platform .
rm -rf __x86_x64_NativeLinux/
python ./pal-platform/pal-platform.py -v deploy --target=x86_x64_NativeLinux generate
cd __x86_x64_NativeLinux/
cmake -G 'Unix Makefiles' -DCMAKE_BUILD_TYPE=Debug -DCMAKE_TOOLCHAIN_FILE=./../pal-platform/Toolchain/GCC/GCC.cmake -DENABLE_CODECOVERAGE=ON
make VERBOSE=1 -j 4
