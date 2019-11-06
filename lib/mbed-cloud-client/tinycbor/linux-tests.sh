# ----------------------------------------------------------------------------
# Copyright 2016-2017 ARM Ltd.
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
# source (!) this file while at SPV tree top - DO NOT run it
export TINY_CBOR_TOP=`pwd`

	sudo apt-get -y install qt5-default
	export ARCH=`uname -m`
	unset CROSS_COMPILE
	export CC=gcc
	export CXX=g++
	export AR=ar
	export LD=ld
	export OBJCOPY=/usr/bin/objcopy #FIXME: move to /opt
	export PATH=/usr/bin:$PATH

	make
	cd qt_tests
	qmake
	make
	./encoder/encoder
	./parser/parser
	./cpp/cpp
	./tojson/tojson
