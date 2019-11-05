#!/bin/bash
set +x
set -e

if [[ $# -eq 0 ]] ; then
    echo 'Please give device id as parametter'
    exit 0
fi

case "$1" in
    1) echo 'Running update tests to Device ID $1' ;;
    *) echo 'Wrong number of parametters only needs device ID' ;;
esac

DEVICE_ID=$1

NEWFILE="mbed-cloud-client/update-client-hub/delta-tool-internal/bsdiff/test_data/driver_add_new.bin"
OLDFILE="mbed-cloud-client/update-client-hub/delta-tool-internal/bsdiff/test_data/driver_add_old.bin"
echo test1 driver add
./createLinuxHostUpdate.sh $OLDFILE $NEWFILE $DEVICE_ID

NEWFILE="mbed-cloud-client/update-client-hub/delta-tool-internal/bsdiff/test_data/app_update_new.bin"
OLDFILE="mbed-cloud-client/update-client-hub/delta-tool-internal/bsdiff/test_data/app_update_old.bin"
echo test2 update app
./createLinuxHostUpdate.sh $OLDFILE $NEWFILE $DEVICE_ID

OLDFILE="mbed-cloud-client/update-client-hub/delta-tool-internal/bsdiff/test_data/mbed-cloud-client-example-2-0-0.bin"
NEWFILE="mbed-cloud-client/update-client-hub/delta-tool-internal/bsdiff/test_data/mbed-cloud-client-example-2-1-0.bin"
echo test3 mbed-cloud-client-example update
./createLinuxHostUpdate.sh $OLDFILE $NEWFILE $DEVICE_ID


NEWFILE="mbed-cloud-client/update-client-hub/delta-tool-internal/bsdiff/test_data/string_tweak_new.bin"
OLDFILE="mbed-cloud-client/update-client-hub/delta-tool-internal/bsdiff/test_data/string_tweak_old.bin"
echo test4 string tweak
./createLinuxHostUpdate.sh $OLDFILE $NEWFILE $DEVICE_ID

NEWFILE="mbed-cloud-client/update-client-hub/delta-tool-internal/bsdiff/test_data/new1.bin"
OLDFILE="mbed-cloud-client/update-client-hub/delta-tool-internal/bsdiff/test_data/old1.bin"
echo test5 new1 
./createLinuxHostUpdate.sh $OLDFILE $NEWFILE $DEVICE_ID

NEWFILE="mbed-cloud-client/update-client-hub/delta-tool-internal/bsdiff/test_data/new2.bin"
OLDFILE="mbed-cloud-client/update-client-hub/delta-tool-internal/bsdiff/test_data/old1.bin"
echo test6 new2
./createLinuxHostUpdate.sh $OLDFILE $NEWFILE $DEVICE_ID

OLDFILE="mbed-cloud-client/update-client-hub/delta-tool-internal/bsdiff/test_data/simple1"
NEWFILE="mbed-cloud-client/update-client-hub/delta-tool-internal/bsdiff/test_data/simple1_new"
echo test7 simple
./createLinuxHostUpdate.sh $OLDFILE $NEWFILE $DEVICE_ID

#NEWFILE="mbedCloudClientExample-update.elf"
#OLDFILE="__x86_x64_NativeLinux_mbedtls/Debug/mbedCloudClientExample.elf"
#echo test8 current app
#./createLinuxHostUpdate.sh $OLDFILE $NEWFILE $DEVICE_ID
#
#
