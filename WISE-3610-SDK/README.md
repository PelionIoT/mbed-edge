### WISE-3610 SDK image build

To create the image for WISE-3610, follow these instructions:

1. Download and install the WISE-3610 SDK
1. Create following folder inside the SDK: `qsdk/package/network/utils/mbed-edge`
1. Copy the Mbed Edge source code from the release repository to the following folder inside the SDK: `qsdk/package/network/utils/mbed-edge/mbed-edge-sources`
1. Add the `Makefile` containing the package information and package generation commands to the following folder inside the SDK: `qsdk/package/network/utils/mbed-edge`
1. Add WISE-3610 toolchain CMake-file to the Mbed Edge sources to the following folder inside the SDK: `qsdk/package/network/utils/mbed-edge/mbed-edge-sources/targets/mcc-linux-x86/CMake`
1. Edit the `mbed_cloud_client_user_config.h`, `mbed_client_user_config.h` and `mbed_edge_config.h` in the `qsdk/package/network/utils/mbed-edge/mbed-edge-sources/WISE-3610-SDK` to configure the build.
1. Navigate to the root of the SDK and set the following environment variables:

    ```export ARMGCC_DIR=`pwd`/qsdk/staging_dir/toolchain-arm_cortex-a7_gcc-4.8-linaro_uClibc-0.9.33.2_eabi/```

    ```export TOOLCHAIN_DIR=`pwd`/qsdk/staging_dir/toolchain-arm_cortex-a7_gcc-4.8-linaro_uClibc-0.9.33.2_eabi/```
1. Create the image by running `make -j 8`

Note that you may have to force edge-core DNS queries to IPv4 only if the edge-core cannot connect to mbed Cloud. This can be configured by adding `#define PAL_NET_DNS_IP_SUPPORT PAL_NET_DNS_IPV4_ONLY` to end of `mbed_edge_config.h`.
