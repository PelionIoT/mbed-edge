#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

if [[ $# -ne 1 || "$(uname -s)" != Darwin || "$(uname -m)" != arm64 ]]; then
    echo "Usage: $0 NEW_OUTPUT_DIRECTORY (native Apple Silicon macOS)" >&2
    exit 1
fi
version="${OPENSSL_VERSION:-3.5.9}"
checksum="${OPENSSL_SHA256:-603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a}"
if [[ ! "$version" =~ ^3\.[0-9]+\.[0-9]+$ || ! "$checksum" =~ ^[a-fA-F0-9]{64}$ ]]; then
    echo "Supply an OpenSSL 3 release and its independently verified SHA-256." >&2
    exit 1
fi
if [[ -e "$1" ]]; then
    echo "The output directory must be new." >&2
    exit 1
fi
mkdir -p "$1"
output_dir="$(cd "$1" && pwd)"
archive="$output_dir/openssl-$version.tar.gz"
curl --fail --location --retry 3 "https://www.openssl.org/source/openssl-$version.tar.gz" -o "$archive"
actual_checksum="$(shasum -a 256 "$archive")"
actual_checksum="${actual_checksum%% *}"
if [[ "$actual_checksum" != "$checksum" ]]; then
    echo "OpenSSL source checksum does not match the pinned release." >&2
    exit 1
fi
tar -xzf "$archive" -C "$output_dir"
cd "$output_dir/openssl-$version"
sdk_dir="${SDKROOT:-$(xcrun --sdk macosx --show-sdk-path)}"
export MACOSX_DEPLOYMENT_TARGET=14.0
perl Configure darwin64-arm64-cc no-shared no-tests no-module \
    "--prefix=$output_dir/install" "--openssldir=$output_dir/install/ssl" \
    -isysroot "$sdk_dir" -mmacosx-version-min=14.0
make -j "$(sysctl -n hw.logicalcpu)"
make install_sw
echo "OpenSSL SDK: $output_dir/install"
