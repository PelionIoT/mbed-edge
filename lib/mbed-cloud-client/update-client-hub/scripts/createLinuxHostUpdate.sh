#!/bin/bash
set +x

OLDFILE="$(readlink -f $1)"
NEWFILE="$(readlink -f $2)"

echo oldfile $OLDFILE
echo newfile $NEWFILE

touch deltaU.bs
DELTAFILE="$(readlink -f deltaU.bs)"

DELTAFILE_RELATIVE_PATH="$(realpath --relative-to=. $DELTAFILE)"
DEVICE_ID=$3

# remove just in case it would already exist
set +e
rm pal/firmware/image_0.bin
rm pal/firmware/original_image.bin
rm $DELTAFILE
rm delta-tool-generated-manifest.json
set -e
# if no original image in host test then it will fail. this is good way to test failure cases
cp $OLDFILE pal/firmware/original_image.bin

#compile bs diff
pushd .
cd mbed-cloud-client/update-client-hub/delta-tool-internal/bsdiff
make bsdiff
popd

./mbed-cloud-client/update-client-hub/delta-tool-internal/bsdiff/bsdiff $OLDFILE $NEWFILE $DELTAFILE 512

python3 mbed-cloud-client/update-client-hub/delta-tool-internal/tools/delta-tool.py $OLDFILE $NEWFILE -d $DELTAFILE -f -i .manifest_tool.json -o delta-tool-generated-manifest.json
#manifest-tool create -i delta-tool-generated-manifest.json -o deltaManifest.bin --no-cleanup
manifest-tool update device -D $DEVICE_ID -i delta-tool-generated-manifest.json --no-cleanup
#cat delta-tool-generated-manifest.json | manifest-tool update device -D $DEVICE_ID --no-cleanup
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
