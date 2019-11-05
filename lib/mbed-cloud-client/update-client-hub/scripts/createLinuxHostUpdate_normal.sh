#!/bin/bash
set -x

NEWFILE="$(readlink -f $1)"
NEW_FILE_RELATIVE_PATH="$(realpath --relative-to=. $NEWFILE)"

echo newfile $NEWFILE

DEVICE_ID=$2

echo deviceID $DEVICE_ID

# remove just in case it would already exist
set +e
rm pal/firmware/image_0.bin
rm pal/firmware/original_image.bin
set -e

manifest-tool update device -D $DEVICE_ID -p $NEW_FILE_RELATIVE_PATH --no-cleanup

#once campaign complates we should have new file in pal/firmware/image_0.bin
diff $NEWFILE pal/firmware/image_0.bin
rc=$?; 
if [ ${rc} -eq 0 ]
	then
		echo -e "\e[32mFiles match test pass\e[0m"
	else
		echo -e "\e[101mFile not match test fail\e[0m"
	fi 
exit ${rc}
