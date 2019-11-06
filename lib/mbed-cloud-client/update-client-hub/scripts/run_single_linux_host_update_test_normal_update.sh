#!/bin/bash
set -x
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
echo test1 driver add
./createLinuxHostUpdate_normal.sh $NEWFILE $DEVICE_ID
