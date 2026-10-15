#!/bin/bash
set -euo pipefail

if [[ "$(uname -s)" != Darwin || "$(uname -m)" != arm64 ]]; then
    echo "This build requires native Apple Silicon macOS." >&2
    exit 1
fi
root_dir="$(cd "$(dirname "$0")" && pwd)"
build_dir="${1:-$root_dir/build/macos}"
if [[ $# -gt 0 ]]; then shift; fi
sdk_dir="${SDKROOT:-$(xcrun --sdk macosx --show-sdk-path)}"
cmake -S "$root_dir" -B "$build_dir" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_OSX_ARCHITECTURES=arm64 \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=14.0 \
    -DCMAKE_OSX_SYSROOT="$sdk_dir" \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DBYOC_MODE=ON -DFIRMWARE_UPDATE=OFF \
    -DMBED_CLOUD_CLIENT_USE_OPENSSL=ON \
    -DEDGE_MACOS_TESTS=ON -DBUILD_DOCUMENTATION=OFF "$@"
cmake --build "$build_dir" --parallel
ctest --test-dir "$build_dir" --no-tests=error --output-on-failure
