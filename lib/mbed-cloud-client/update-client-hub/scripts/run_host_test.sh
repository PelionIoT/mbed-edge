#!/bin/bash
#set -x
./__x86_x64_NativeLinux_mbedtls/Debug/mbedCloudClientExample.elf < /dev/null  &> cloudclientlog.txt &
( tail -f -n0 cloudclientlog.txt & ) | grep -q "Client registered"
echo "Client Registered found"
DEVICE_ID="$(grep 'Client registered' -A 2  cloudclientlog.txt | cut -d: -f2 | sed -n '2 p')"
run_single_linux_host_update_test.sh $DEVICE_ID

