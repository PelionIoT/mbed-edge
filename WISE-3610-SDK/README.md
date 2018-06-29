### WISE-3610 SDK image build

To create the image for WISE-3610, follow these instructions:

1. Download and install the WISE-3610 SDK
1. Create following folder inside the SDK: `qsdk/package/network/utils/mbed-edge`
1. Copy the Mbed Edge source code from the release repository to the following folder inside the SDK: `qsdk/package/network/utils/mbed-edge/mbed-edge-sources`
1. Add the `Makefile` containing the package information and package generation commands to the following folder inside the SDK: `qsdk/package/network/utils/mbed-edge`
1. Copy the supplied OpenWRT configuration from Edge release repository file `WISE-3610-SDK/OpenWrtConfiguration` to configuration file in SDK directory `qsdk/.config`
1. Edit the `mbed_cloud_client_user_config.h` and `mbed_client_user_config.h` in the `qsdk/package/network/utils/mbed-edge/mbed-edge-sources/WISE-3610-SDK` to configure the build.
1. Also check the settings in `cmake/targets/wise3610.cmake`.
1. Navigate to the root of the SDK and set the following environment variables:

    ```export ARMGCC_DIR=`pwd`/qsdk/staging_dir/toolchain-arm_cortex-a7_gcc-4.8-linaro_uClibc-0.9.33.2_eabi/```

    ```export TOOLCHAIN_DIR=`pwd`/qsdk/staging_dir/toolchain-arm_cortex-a7_gcc-4.8-linaro_uClibc-0.9.33.2_eabi/```

    ```export ARM_LIBC_DIR=/home/adv/work/qsdk/staging_dir/target-arm_cortex-a7_uClibc-0.9.33.2_eabi```

1. Create the image by running `make -j 8 V=s`

Note that you may have to force edge-core DNS queries to IPv4 only if the edge-core cannot connect to mbed Cloud. This can be configured by adding `add_definitions ("-DPAL_NET_DNS_IP_SUPPORT=PAL_NET_DNS_IPV4_ONLY")` to end of `cmake/targets/wise3610.cmake`.
