#!/bin/sh

TEST_MODULES=../test_modules
TEST_MODULE_MBED_COAP=$TEST_MODULES/mbed-coap
TEST_MODULE_MBED_TRACE=$TEST_MODULES/mbed-trace
TEST_MODULE_NANOSTACK=$TEST_MODULES/nanostack-libservice
TEST_MODULE_RANDLIB=$TEST_MODULES/mbed-client-randlib
TEST_MODULE_MBED_TLS=$TEST_MODULES/mbedtls
TEST_MODULE_NANOSTACK_EVENTLOOP=$TEST_MODULES/sal-stack-nanostack-eventloop
TEST_MODULE_MBED_CLIENT_PAL=$TEST_MODULES/mbed-client-pal

if [ ! -d $TEST_MODULES ]; \
	then mkdir $TEST_MODULES; \
fi;

if [ ! -d $TEST_MODULE_MBED_COAP ]; \
	then git clone --depth 1 git@github.com:ARMmbed/mbed-coap.git $TEST_MODULE_MBED_COAP; \
fi;

if [ ! -d $TEST_MODULE_MBED_TRACE ]; \
	then git clone --depth 1 git@github.com:ARMmbed/mbed-trace.git $TEST_MODULE_MBED_TRACE; \
fi;

if [ ! -d $TEST_MODULE_NANOSTACK ]; \
	then git clone --depth 1 git@github.com:ARMmbed/nanostack-libservice.git $TEST_MODULE_NANOSTACK; \
fi;

if [ ! -d $TEST_MODULE_MBED_TLS ]; \
	then git clone --depth 1 git@github.com:ARMmbed/mbedtls.git $TEST_MODULE_MBED_TLS; \
fi;

if [ ! -d $TEST_MODULE_RANDLIB ]; \
	then git clone --depth 1 git@github.com:ARMmbed/mbed-client-randlib.git $TEST_MODULE_RANDLIB; \
fi;

if [ ! -d $TEST_MODULE_NANOSTACK_EVENTLOOP ]; \
	then git clone --depth 1 git@github.com:ARMmbed/sal-stack-nanostack-eventloop.git $TEST_MODULE_NANOSTACK_EVENTLOOP; \
fi;

if [ ! -d $TEST_MODULE_MBED_CLIENT_PAL ]; \
        then git clone --depth 1 git@github.com:ARMmbed/mbed-client-pal.git $TEST_MODULE_MBED_CLIENT_PAL; \
fi;
