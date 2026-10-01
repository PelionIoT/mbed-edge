# Building Edge Core with OpenSSL

This document describes how to build Edge Core with OpenSSL instead of MbedTLS for cryptographic operations.

## Overview

By default, Edge Core uses MbedTLS for cryptographic operations. However, you can build Edge Core to use OpenSSL instead of MbedTLS by setting the appropriate CMake flags and installing the required OpenSSL libraries.

## Building with Docker (Recommended)

The easiest way to build Edge Core with OpenSSL is using the provided Dockerfile.

### Using Dockerfile.debian.byoc.openssl

To build Edge Core with OpenSSL support using Docker, use the `Dockerfile.debian.byoc.openssl`:

```sh
docker build -t edge-core:openssl-latest -f ./Dockerfile.debian.byoc.openssl .
```

This Dockerfile builds Edge Core with OpenSSL 3.0.2 and 3.0.9 (with FIPS support) instead of MbedTLS. The build includes:
- OpenSSL 3.0.9 with FIPS module support
- OpenSSL 3.0.2 for libssl and libcrypto libraries
- All necessary OpenSSL configurations and libraries

### Running the OpenSSL-based Docker image

```sh
docker run -v $PWD/mcc_config:/usr/src/app/mbed-edge/mcc_config \
-v $PWD/edge_configuration:/usr/src/app/mbed-edge/edge_configuration \
--name edge-core-with-openssl \
edge-core:openssl-latest \
--json-conf /usr/src/app/mbed-edge/edge_configuration/kcm.json
```

## Building Manually

### Prerequisites

Before building Edge Core with OpenSSL, you need to install OpenSSL libraries on your system.

#### Installing OpenSSL

Install OpenSSL 3.0.9 with FIPS support and OpenSSL 3.0.2 for libraries:

```sh
# Install OpenSSL 3.0.9 with FIPS support
cd /tmp && \
wget https://www.openssl.org/source/openssl-3.0.9.tar.gz && \
tar -xzf openssl-3.0.9.tar.gz && \
cd openssl-3.0.9 && \
./config --prefix=/usr/local/openssl-3.0.9 --openssldir=/usr/local/openssl-3.0.9 enable-fips && \
make -j$(nproc) && \
make install && \
cd /tmp && \
rm -rf openssl-3.0.9 openssl-3.0.9.tar.gz

# Install OpenSSL 3.0.2 for libssl and libcrypto
cd /tmp && \
wget https://www.openssl.org/source/openssl-3.0.2.tar.gz && \
tar -xzf openssl-3.0.2.tar.gz && \
cd openssl-3.0.2 && \
./config --prefix=/usr/local/openssl-3.0.2 --openssldir=/usr/local/openssl-3.0.2 && \
make -j$(nproc) && \
make install && \
cd /tmp && \
rm -rf openssl-3.0.2 openssl-3.0.2.tar.gz
```

### Building Edge Core

To build Edge Core with OpenSSL support, use the following CMake flags:

```bash
mkdir build
cd build
cmake -D[MODE] -DMBED_CLOUD_CLIENT_USE_OPENSSL=ON -DPLATFORM_TARGET=x86_x64_NativeLinux_openssl -DFOTA_ENABLE=ON ..
make
```

### Environment Variables

When running edge-core with OpenSSL directly on the host (not in Docker), you need to set the following environment variables:

```bash
export OPENSSL_CONF=/usr/local/openssl-3.0.2/openssl.cnf
export LD_LIBRARY_PATH=/usr/local/openssl-3.0.2/lib64:$LD_LIBRARY_PATH
```

These environment variables ensure that edge-core uses the correct OpenSSL configuration and can find the OpenSSL libraries at runtime.

**Note:** For reference, you can find an example OpenSSL configuration with FIPS enabled in `config/openssl-3.0.2/openssl-fips.cnf`.

## Verifying the Environment Setup

After building and setting up the environment variables, you can verify that everything is configured correctly by running the following checks:

### 1. Verify OpenSSL Providers

Run the following command to ensure both the default and FIPS providers are available and active:

```bash
openssl list -providers
```

You should see output similar to:

```
Providers:
  default
    name: OpenSSL Default Provider
    version: 3.0.2
    status: active
  fips
    name: OpenSSL FIPS Provider
    version: 3.0.9
    status: active
```

### 2. Verify Library Dependencies

Check that edge-core is correctly linked to the OpenSSL libraries:

```bash
ldd ./bin/edge-core
```

You should see output similar to:

```
        linux-vdso.so.1 (0x00007ff0e6963000)
        libevent-2.1.so.7 => /usr/src/app/mbed-edge/build/lib/libevent/libevent/lib/libevent-2.1.so.7 (0x00007ff0e676b000)
        libevent_pthreads-2.1.so.7 => /usr/src/app/mbed-edge/build/lib/libevent/libevent/lib/libevent_pthreads-2.1.so.7 (0x00007ff0e6766000)
        libstdc++.so.6 => /lib/x86_64-linux-gnu/libstdc++.so.6 (0x00007ff0e6549000)
        libssl.so.3 => /usr/local/lib/openssl/libssl.so.3 (0x00007ff0e64a1000)
        libcrypto.so.3 => /usr/local/lib/openssl/libcrypto.so.3 (0x00007ff0e603e000)
        libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x00007ff0e601c000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ff0e5e3b000)
        libevent_core-2.1.so.7 => /usr/src/app/mbed-edge/build/lib/libevent/libevent/lib/libevent_core-2.1.so.7 (0x00007ff0e5e06000)
        libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007ff0e5d26000)
        /lib64/ld-linux-x86-64.so.2 (0x00007ff0e6965000)
```

**Important:** Ensure that `libssl.so.3` and `libcrypto.so.3` are pointing to the correct OpenSSL libraries (e.g., `/usr/local/lib/openssl/` or `/usr/local/openssl-3.0.2/lib64/`).

If the libraries are not pointing to the correct location, verify that your `LD_LIBRARY_PATH` environment variable is set correctly.
