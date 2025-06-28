#!/bin/bash

# http://stackoverflow.com/questions/59895/can-a-bash-script-tell-what-directory-its-stored-in
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do # resolve $SOURCE until the file is no longer a symlink
  SELF="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE" # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
done

MYDIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"

TIMEOUT="50"

cd $MYDIR

echo "Building mbed-edge with SSL_PLATFORM_BACKEND=1 (mbed-tls)"

# if build dir exists, remove it
if [ -d "build-ssl-mbedtls" ]; then
    rm -rf build-ssl-mbedtls
fi
mkdir -p build-ssl-mbedtls
cd build-ssl-mbedtls


cmake -DDEVELOPER_MODE=ON -DFIRMWARE_UPDATE=ON -DTRACE_COAP_PAYLOAD=ON -DTRACE_LEVEL=INFO -DCMAKE_BUILD_TYPE=Debug -DSSL_PLATFORM_BACKEND=1 ..
# if success, run make
if [ $? -eq 0 ]; then
    make -j8
else 
    echo "mbed-tls cmake failed"
    exit 1
fi

# if make is successful, run the test
if [ $? -eq 0 ]; then
    echo "Will run edge-core (mbed-tls) for ${TIMEOUT} seconds. Press CTRL-C to stop the test"
    # run edge-core for 15 seconds in the foreground
    # tee stdout and stderr to a file
    timeout $TIMEOUT ./bin/edge-core 2>&1  | tee edge-core-mbedtls.log
# SUCCESS OUTPUT (or similar):
# 2025-06-18 04:51:26.491 tid: 396819 [INFO][mClt]: MbedCloudClient::register_update
# 2025-06-18 04:51:26.491 tid: 396819 [INFO][mClt]: M2MNsdlInterface::send_update_registration( lifetime 0)
# 2025-06-18 04:51:26.491 tid: 396819 [INFO][COAP]: UPDATE REGISTER MESSAGE
# 2025-06-18 04:51:26.491 tid: 396819 [INFO][COAP]: OUT: [CON|POST|MID:55188|path:rd/0158778f9f1002420a014c1100000000/01978160ac014ec00fe60cff00000000|token:b3:e1:91:1c|pl:0|ct:40|max-age:0|uri-query:et=MBED_GW]
# 2025-06-18 04:51:26.506 tid: 396822 [INFO][coap]: sn_coap_protocol_linked_list_duplication_info_remove - message id 16144 removed
# 2025-06-18 04:51:26.506 tid: 396822 [INFO][COAP]: IN: [CON|GET|MID:56450|path:10252/0/4|token:24:90:e6:1e|pl:0|max-age:0|obs:0]
# 2025-06-18 04:51:26.506 tid: 396822 [INFO][COAP]: OUT: [ACK|NOT_FOUND|MID:56450|token:24:90:e6:1e|pl:0]
# 2025-06-18 04:51:26.544 tid: 396822 [INFO][COAP]: IN: [ACK|CHANGED|MID:55188|token:b3:e1:91:1c|pl:0|max-age:3600]
# 2025-06-18 04:51:26.544 tid: 396822 [INFO][mClt]: M2MNsdlInterface::handle_register_update_response - registration_updated
# 2025-06-18 04:51:26.544 tid: 396822 [INFO][mClt]: M2MInterfaceImpl::registration_updated
# 2025-06-18 04:51:26.544 tid: 396822 [INFO][mClt]: M2MInterfaceImpl::state_registered
# 2025-06-18 04:51:26.544 tid: 396822 [INFO][mClt]: MbedCloudClient::complete status (2)
else
    echo "mbed-tls make failed"
    exit 1
fi

cd $MYDIR

# now do the same for openssl
echo "Building mbed-edge with SSL_PLATFORM_BACKEND=2 (openssl)"
if [ -d "build-ssl-openssl" ]; then
    rm -rf build-ssl-openssl
fi
mkdir -p build-ssl-openssl
cd build-ssl-openssl

cmake -DDEVELOPER_MODE=ON -DFIRMWARE_UPDATE=ON -DTRACE_COAP_PAYLOAD=ON -DTRACE_LEVEL=INFO -DCMAKE_BUILD_TYPE=Debug -DSSL_PLATFORM_BACKEND=2 ..
# if success, run make
if [ $? -eq 0 ]; then
    make -j8
else 
    echo "openssl cmake failed"
    exit 1
fi

if [ $? -eq 0 ]; then
    echo "Will run edge-core (openssl) for ${TIMEOUT} seconds. Press CTRL-C to stop the test"
    # run edge-core for 15 seconds in the foreground
    timeout $TIMEOUT ./bin/edge-core 2>&1 | tee edge-core-openssl.log
else
    echo "openssl make failed"
    exit 1
fi






