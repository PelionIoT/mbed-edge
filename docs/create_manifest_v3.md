# Firmware update with edge-core

Use Izuma vended [manifest-tool](https://github.com/PelionIoT/manifest-tool/tree/master) to create firmware update manifest. Follow the installation process mentioned in the README.md. For quick demo, here are the list of commands that you can run to quickly preview the firmware update workflow. Note: these are not recommended for production, please follow the guidance mentioned in the manifest-tool README.md.

## Steps demonstrating creating manifests for the MAIN and COMP_1 components

1. Generate update certificate and key
    ```bash
    # Create a workplace and clone mbed-edge and manifest-tool
    # ~/Workspace/IzumaNetworks/mbed-edge
    # ~/Workspace/IzumaNetworks/manifest-tool
    WORKSPACE=~/Workspace/IzumaNetworks

    mkdir -p ${WORKSPACE}/mbed-edge/edge_configuration/

    cd manifest-tool
    source myenv/bin/activate
    cd myenv/bin

    VENDOR_ID=073a785733384957a0a13ffef6ccf2d9
    CLASS_ID=090a41faf2ee48baac4fbd13f2c3eb6f

    # Assuming manifest-tool is installed on your box
    # Generate dev update key and certificate
    manifest-dev-tool init --vendor-id ${VENDOR_ID} --class-id ${CLASS_ID} --cache-dir ${WORKSPACE}/mbed-edge/edge_configuration/

    cd ${WORKSPACE}/mbed-edge/edge_configuration/

    # Rename
    mv dev.cert.der update_dev.cert.der
    mv dev.key.pem update_dev.key.pem

    # if using pem format in kcm.json then convert to pem using openssl
    openssl x509 -inform der -in update_dev.cert.der -out update_dev.cert.pem

    cd -
    ```

2. Create a random firmware image file of 10MB

    ```bash
    FIRMWARE_FILE="./random_file.bin"
    dd if=/dev/urandom of=${FIRMWARE_FILE} bs=1M count=10
    ```

3. Upload the firmware image to server accessible from device or Izuma Device Management portal following the steps mentioned [here](https://developer.izumanetworks.com/docs/device-management/current/updating-firmware/running-update-campaigns.html).

4. Create manifest config
    Note: Use VENDOR_ID and CLASS_ID of your device. Replace FIRMWARE_URL with firmware image url accessible by the device.

```bash
FIRMWARE_IMAGE_URL=http://firmware-catalog-media-ca57.s3.dualstack.us-east-1.amazonaws.com/3nGjS8dpZfk3TnRtyuJPZq
COMPONENT=MAIN
echo "vendor:
  vendor-id: ${VENDOR_ID}
device:
  class-id: ${CLASS_ID}
priority: 1
payload:
  url: ${FIRMWARE_IMAGE_URL}
  file-path: ${FIRMWARE_FILE}
  format: raw-binary
component: ${COMPONENT}
" > update_manifest_config.yaml
```

5. Create manifest

    ```bash
    FIRMWARE_VERSION=0.0.2
    OUT_FILE="update_${COMPONENT}_${VENDOR_ID}_${CLASS_ID}_manifest.${FIRMWARE_VERSION}.bin"
    manifest-tool create \
        --config update_manifest_config.yaml \
        --key ${WORKSPACE}/mbed-edge/edge_configuration/update_dev.key.pem \
        --fw-version ${FIRMWARE_VERSION} \
        --output ${OUT_FILE}
    ```

This will create a manifest in v3 format. Please ensure that the device supports this version of the manifest by compiling edge-core with the `FOTA_ENABLE` flag, see `${WORKSPACE}/mbed-edge/Dockerfile.debian.byoc` for a compilation example.

Perform firwmare update by [uploading the manifest](https://developer.izumanetworks.com/docs/device-management/current/updating-firmware/uploading-the-manifest.html) and [creating a campaign](https://developer.izumanetworks.com/docs/device-management/current/updating-firmware/configuring-initiating-and-monitoring-an-update-campaign.html).

6. To update other component, prepare the manifest using the same update certificate and following steps 2-5. Update the macro `COMPONENT=<COMPONENT_NAME>` in the manifest config with the component name.

## Recommended reads

1. [Security in firmware update](https://developer.izumanetworks.com/docs/device-management/current/updating-firmware/security.html)
1. [Types of campaigns](https://developer.izumanetworks.com/docs/device-management/current/updating-firmware/update-campaigns.html)
1. [Update events](https://developer.izumanetworks.com/docs/device-management/current/device-management/viewing-device-events.html)
1. [Troubleshooting update campaigns](https://developer.izumanetworks.com/docs/device-management/current/updating-firmware/troubleshooting-update-campaigns.html)
1. [How to use Vendor ID and Class ID](https://developer.izumanetworks.com/docs/device-management/current/updating-firmware/device-management-update-concepts.html)
