#!/usr/bin/env bash

# ----------------------------------------------------------------------------
# Copyright 2018 ARM Ltd.
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ----------------------------------------------------------------------------

if [ "$1" == "--clean" ]; then
    cd build/mcc-linux-x86

    if [ -f "Makefile" ]; then
        make clean
    else
        echo "Edge build environment has not been initialized yet. Please build with \"$0\" first."
    fi
elif [ "$1" == "--build" ] || [ "$1" == "" ]; then
    cd build/mcc-linux-x86
    cmake .
    make
else
    echo "./build_mbed_edge.sh [--build | --clean]"
    echo "Options:"
    echo "  --build: Build the Mbed Edge"
    echo "           Build is also executed if script is run without parameters"
    echo "  --clean: Clean the existing Mbed Edge build"
fi
