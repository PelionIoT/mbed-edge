#!/bin/bash
set +x
DEVICE_ID=$1
./createLinuxHostUpdate.sh BUILD/K64F/GCC_ARM/old-mbed-cloud-client-example-internal_application.bin BUILD/K64F/GCC_ARM/mbed-cloud-client-example-internal_update.bin $DEVICE_ID
echo "linux update done"
