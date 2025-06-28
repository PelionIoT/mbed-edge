#!/bin/bash

# SSL Platform SNI Support Test Script
# 
# This script builds and tests the newly added SNI (Server Name Indication)
# functionality in the ssl-platform abstraction layer.

set -e  # Exit on any error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== SSL Platform SNI Support Test ==="
echo "Building and testing SNI functionality in ssl-platform..."
echo

# Check if we have a build directory
if [ ! -d "build-ssl-mbedtls" ]; then
    echo "Error: build-ssl-mbedtls directory not found!"
    echo "Please run the main build script first to create the build directory."
    exit 1
fi

echo "Using existing build directory: build-ssl-mbedtls"
cd build-ssl-mbedtls

echo
echo "=== Building SNI Test ==="

# Build the SNI test specifically
make test_sni

if [ $? -ne 0 ]; then
    echo "Error: Failed to build test_sni"
    exit 1
fi

echo "SNI test built successfully!"
echo

# Check if the test binary exists
if [ ! -f "lib/ssl-platform/test_sni" ]; then
    echo "Error: test_sni binary not found at lib/ssl-platform/test_sni"
    exit 1
fi

echo "=== Running SNI Test ==="
echo

# Run the SNI test
./lib/ssl-platform/test_sni

test_result=$?

echo
echo "=== Test Results ==="

if [ $test_result -eq 0 ]; then
    echo "✅ SNI test PASSED!"
    echo
    echo "🎉 SNI support has been successfully added to ssl-platform!"
    echo
    echo "Next steps:"
    echo "1. The ssl-platform abstraction now supports SNI via ssl_platform_ssl_set_hostname()"
    echo "2. The compatibility macro 'mbedtls_ssl_set_hostname' is available for existing code"
    echo "3. You can now update mbed-edge code to use SNI and resolve the bootstrap server connection issue"
    echo
    echo "To use SNI in your code:"
    echo "  ssl_platform_ssl_set_hostname(&ssl_ctx, \"bootstrap.us-east-1.mbedcloud.com\");"
    echo "  // or using compatibility macro:"
    echo "  mbedtls_ssl_set_hostname(&ssl_ctx, \"bootstrap.us-east-1.mbedcloud.com\");"
    
else
    echo "❌ SNI test FAILED!"
    echo
    echo "The SNI implementation needs to be reviewed."
    echo "Check the test output above for specific failures."
    exit 1
fi

echo
echo "=== Summary ==="
echo "SNI (Server Name Indication) support has been successfully integrated into ssl-platform."
echo "This should resolve the TLS protocol difference causing bootstrap server connection failures." 