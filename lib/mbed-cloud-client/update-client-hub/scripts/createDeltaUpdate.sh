#!/bin/bash
set +x

OLDFILE="$(readlink -f $1)"
NEWFILE="$(readlink -f $2)"

DEVICE_ID=$3

echo oldfile $OLDFILE
echo newfile $NEWFILE

baseNameForDelta=$(basename $2) 
dirNameForDelta=$(dirname  $2)

GENERATED_DELTA_NAME=$dirNameForDelta"TP_DELTA_BS_"$baseNameForDelta".bs"

touch $GENERATED_DELTA_NAME
DELTAFILE="$(readlink -f $GENERATED_DELTA_NAME)"

DELTAFILE_RELATIVE_PATH="$(realpath --relative-to=. $DELTAFILE)"

#just to make it easy to test with this script with host update
cp $OLDFILE pal/firmware/original_image.bin

# remove just in case it would already exist
set +e
rm $DELTAFILE
rm delta-tool-generated-manifest.json
set -e
# if no original image in host test then it will fail. this is good way to test failure cases

#compile bs diff
pushd .
cd mbed-cloud-client/update-client-hub/delta-tool-internal/bsdiff
make bsdiff
popd

./mbed-cloud-client/update-client-hub/delta-tool-internal/bsdiff/bsdiff $OLDFILE $NEWFILE $DELTAFILE 512

python3 mbed-cloud-client/update-client-hub/delta-tool-internal/tools/delta-tool.py $OLDFILE $NEWFILE -d $DELTAFILE_RELATIVE_PATH -f -i .manifest_tool.json -o delta-tool-generated-manifest.json
#manifest-tool create -i delta-tool-generated-manifest.json -o deltaManifest.bin --no-cleanup
#note we backup newfile as oldfile if this command is succesful
manifest-tool update device -D $DEVICE_ID -i delta-tool-generated-manifest.json --no-cleanup && cp $NEWFILE $OLDFILE
#cat delta-tool-generated-manifest.json | manifest-tool update device -D $DEVICE_ID --no-cleanup
#once campaign complates we should have new file in pal/firmware/image_0.bin
