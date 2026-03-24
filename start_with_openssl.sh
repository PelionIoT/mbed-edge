#!/bin/bash

# Enable core dumps
ulimit -c unlimited
mkdir -p /core
echo "Core dumps enabled. Core files will be written to /core"

# Configure OpenSSL FIPS environment
export OPENSSL_CONF=/usr/local/ssl/openssl-fips.cnf
export OPENSSL_MODULES=/usr/local/lib/openssl/ossl-modules
export OPENSSL_FIPS=1
export LD_LIBRARY_PATH=/usr/local/lib/openssl:$LD_LIBRARY_PATH
export PATH=/usr/local/bin:$PATH

echo "Using OpenSSL conf: $OPENSSL_CONF"
echo "Using OpenSSL FIPS module directory: $OPENSSL_MODULES"
echo "FIPS mode enabled: $OPENSSL_FIPS"

# Path to the binary
CMD="./build/bin/edge-core $@"

echo "OpenSSL version: $(openssl version -a)"
echo "OpenSSL providers: $(openssl list -providers)"
echo "FIPS module check: $(ls -la /usr/local/lib/openssl/ossl-modules/ 2>/dev/null || echo 'No ossl-modules directory')"
echo "FIPS config check: $(ls -la /usr/local/ssl/ 2>/dev/null || echo 'No ssl directory')"

# Test FIPS provider specifically
echo "Testing FIPS provider:"
openssl list -providers -provider fips 2>/dev/null || echo "FIPS provider not available"

echo "$(ldd ./build/bin/edge-core)"
echo "Starting: $CMD"

# Run + monitor
while true; do
    $CMD
    EXIT_CODE=$?
    echo "Process exited with code $EXIT_CODE"

    # If a core file was generated, print the stack trace
    CORE_FILE=$(ls /core/core.edge-core.* 2>/dev/null | tail -n 1)
    if [[ -f core ]]; then
        TIMESTAMP=$(date +%s)
        mv core "core.edge-core.${TIMESTAMP}"
        echo "==== Crash detected. Stack trace ===="
        gdb -batch -ex "thread apply all bt" -ex "quit" /usr/src/app/mbed-edge/build/bin/edge-core "core.edge-core.${TIMESTAMP}"
    fi

    echo "Restarting in 5s..."
    sleep 5
done
