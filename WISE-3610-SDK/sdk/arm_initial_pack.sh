#/bin/bash
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

echo 'ARM Cloud client initial package script'

#Set the SOURCE_DIRECTORY to your SDK root folder
SOURCE_DIRECTORY='/path/to/sdk/root/private/qca-networking-2016-spf-2-0_qca_oem_standard.git/IPQ4019.ILQ.1.1.1.r2/common/build/ipq/'

OUT_DIRECTORY='image'
OUT_FILE='nand-ipq40xx-initial.img'

if [ ! -d $SOURCE_DIRECTORY ]; then
  echo 'Source directory does not exist'
  echo 'Set the SOURCE_DIRECTORY variable in the script to point to your SDK root'
  exit 1
fi

# create output directory if it doesn't exists
if [ ! -d "$OUT_DIRECTORY" ]; then
  mkdir -p $OUT_DIRECTORY
fi

# copy source files to out directory
cp scripts/arm_initial_flash_layout.its $OUT_DIRECTORY
cp scripts/arm_initial_install_script.scr $OUT_DIRECTORY
cp scripts/arm_uboot_script.scr $OUT_DIRECTORY
cp scripts/arm_initial_header.bin $OUT_DIRECTORY
cp scripts/arm_initial_ubi_kcm.ini $OUT_DIRECTORY

# copy root image to out directory
cp $SOURCE_DIRECTORY/openwrt-ipq806x-ipq40xx-ubi-root.img $OUT_DIRECTORY

# generate UBI KCM image
cd $OUT_DIRECTORY
mkfs.ubifs --space-fixup -m 2048 -e 126976 -c 31 -o ubifs-kcm.img
ubinize -m 2048 -p 128KiB -o ubi-kcm.img arm_initial_ubi_kcm.ini

# generate U-Boot script image
mkimage -T script -C none -n 'U-Boot Script' -d arm_uboot_script.scr arm_uboot_script.img

# generate initial header image
mkimage -T script -C none -n 'Initial Header' -d arm_initial_header.bin arm_initial_header.img

# pack images into one multi-image
RUN_CMD="mkimage -f arm_initial_flash_layout.its $OUT_FILE"

echo $RUN_CMD
$RUN_CMD
