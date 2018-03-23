#!/bin/sh
#----------------------------------------------------------------------------
# The confidential and proprietary information contained in this file may
# only be used by a person authorised under and to the extent permitted
# by a subsisting licensing agreement from ARM Limited or its affiliates.
#
# (C) COPYRIGHT 2017 ARM Limited or its affiliates.
# ALL RIGHTS RESERVED
#
# This entire notice must be reproduced on all copies of this file
# and copies of this file may only be made by a person if such person is
# permitted to do so under the terms of a subsisting license agreement
# from ARM Limited or its affiliates.
#----------------------------------------------------------------------------

# create output directory if it doesn't exists
if [ ! -d "/mnt/kcm" ]; then
    echo "Create /mnt/kcm"
    mkdir -p /mnt/kcm
fi

# attach and mount device if it doesn't exists
if [ ! -e "/dev/ubi1" ]; then
    MTD_DEVICE=`cat /proc/mtd | grep KCM | awk '{ print $1 }' -F ":"`

    # only continue if KCM partition exists
    if [ ! -z $MTD_DEVICE ]; then
        echo "Mount ${MTD_DEVICE}"
        ubiattach -p /dev/$MTD_DEVICE
        mount -t ubifs /dev/ubi1_0 /mnt/kcm
    fi
fi
