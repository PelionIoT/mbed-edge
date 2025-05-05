# Firmware (FOTA) with Edge Core

## Prepare edge-core for firmware update of the MAIN and COMP_1 components

In the `./fota` directory there are 2 folders that contains example firmware update scripts to demonstrate how to update the MAIN and COMP_1 components. A component update requires 2 update scripts; 1\ for installation `fota_update_activate.sh` and 2\ for verification `fota_update_verify.sh`. By default the MAIN component verification is done internally by reading the firwmare version from the metadata file. Additionally, the MAIN component is registered with `need_reboot=true` and thus edge-core will auto-restart after the installation script returns with exit code 0. The COMP_1 component is registered with `need_reboot=false` and requires both the update script.

The `fota_update_activate.sh` is invoked once the firmware image is downloaded. A success is reported when the script exit with code 0. Any other value, the installation will be failed and requires a new firmware update campaign to retry the installation. The `fota_update_verify.sh` is invoked after the installation is done. To support asynchronous update workflow, you could stall any of the scripts to report success only after the update process is complete.

At the time of registration, edge-core reports Izuma cloud how many components it supports. By default you can have 5 components (including MAIN). You can update this number by overriding the compile time macro [FOTA_NUM_COMPONENTS](https://github.com/PelionIoT/mbed-cloud-client/blob/c04abe4de443a82e4634737e8d5b9ae036718ba2/fota/fota_component_defs.h#L26). Also note that the component name cannot be more than 9 characters as set by macro [FOTA_COMPONENT_MAX_NAME_SIZE](https://github.com/PelionIoT/mbed-cloud-client/blob/c04abe4de443a82e4634737e8d5b9ae036718ba2/fota/fota_component_defs.h#L31).

To enable FOTA features compile edge-core with following flags `-DFIRMWARE_UPDATE=ON -DFOTA_ENABLE=ON -DFOTA_COMBINED_IMAGE_SUPPORT=ON`. For a compilation example, refer to `Dockerfile.debian.byoc`.

