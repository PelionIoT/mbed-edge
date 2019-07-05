#!/bin/bash

rm -f test-folder/*
mkdir -p test-folder

frameSize=
csvFile=./test-folder/results.csv

function calcPercentageOfTwoFiles() {
SIZE1=$(du -b "$1")
SIZE2=$(du -b "$2")

array1=( $SIZE1 )
array2=( $SIZE2 )

echo "NEWBS_SIZE ${array1[0]} ORIGINAL_BS_SIZE ${array2[0]}"
percentage=$(bc <<< "scale=2; ( (${array1[0]}*100)/${array2[0]})")
echo "New BS patch file size related to original BS patch: $percentage %"
}

function calcPercentageOfTwoNumber() {
percentage=$(bc <<< "scale=2; ( ($2*100)/$1)")
echo $percentage
}

#/usr/bin/time -v ./bsdiff ./test_data/old1.bin ./test_data/new1.bin ./test-folder/diff1.bsdiff |& grep resident

function run_bs_patch_test() {
	#set -x
	underScore=_
	testName="$1 (frameSize:$frameSize)"
	oldFile=$2
	newFile=$3
	diffFile=$4$underScore$frameSize
	patchedFile=$5$underScore$frameSize
	#ms_printOutFile = "profilingOf$patchedFile.txt"
	
	#massifOutFile=$diffFile"massif.out"
	#valgrindCommand="valgrind --tool=massif --massif-out-file $massifOutFile"
	
	#ms_print $massifOutFile > $ms_printOutFile
	
	originalBSPatchStr=$underScore$frameSize"origBsPatch"
	echo $testName
	echo "******"
	./bsdiff $oldFile $newFile $diffFile $frameSize
	./bspatch $oldFile $patchedFile $diffFile
	
	originalBsPathcDiffFile=$diffFile$originalBSPatchStr
	originalBsPatchedFile=$patchedFile$originalBSPatchStr
	#original bsbatch results for comparision
	bsdiff $oldFile $newFile $originalBsPathcDiffFile
	bspatch $oldFile $originalBsPatchedFile $originalBsPathcDiffFile
	
	calcPercentageOfTwoFiles $diffFile $diffFile$originalBSPatchStr
	
	diff $newFile $patchedFile
	#do check how much smaller it could have been
	#ls -al $diffFile
	diffFileSize=$(stat -c "%s" $diffFile)
	newFileSize=$(stat -c "%s" $newFile)
	oldFileSize=$(stat -c "%s" $oldFile) 
	originalBsPatchDiffFileSize=$(stat -c "%s" $originalBsPathcDiffFile)
	armBsDiffFileSize=$(stat -c "%s" $diffFile)
	
	#these steps require version of bspatch that can generate uncompressed bspatch format
	# no frame size really for these
	echo "Running no-compression bspatch tests"
	nonCompressionDiffFile=$diffFile$underScore$frameSize$underScore"NonCompress"
	nonCompressionPatchedFile=$patchedFile$underScore$frameSize$underScore"NonCompress"
	./bsdiff_nocompression $oldFile $newFile $nonCompressionDiffFile 
	./bspatch_nocompression $oldFile $nonCompressionPatchedFile $nonCompressionDiffFile
	noCompressionDiffFileSize=$(stat -c "%s" $nonCompressionDiffFile)
	nonCompressedFileNameAfterCompressWithLZ4=$nonCompressionDiffFile".lz4" 
	lz4 $nonCompressionDiffFile $nonCompressedFileNameAfterCompressWithLZ4
	nonCompressedBsPatchSizeAfterLZ4=$(stat -c "%s" $nonCompressedFileNameAfterCompressWithLZ4)
	
	#./lz77 -c $nonCompressionDiffFile 
	
	# apppend to csv for easy comparison
	echo "Appending results to results.csv"
	printf "%s,%s B,%s B,%s B,%s B,%s B,%s B\n"  "$testName" $oldFileSize $newFileSize $originalBsPatchDiffFileSize $armBsDiffFileSize $noCompressionDiffFileSize $nonCompressedBsPatchSizeAfterLZ4>> $csvFile
	
	oldFileSize_percentage=$(calcPercentageOfTwoNumber $newFileSize $oldFileSize)
	
	newFileSize_percentage=$(calcPercentageOfTwoNumber $newFileSize $newFileSize) # should be 100
	originalBsPatchDiffFileSize_percentage=$(calcPercentageOfTwoNumber $newFileSize $originalBsPatchDiffFileSize)
	armBsDiffFileSize_percentage=$(calcPercentageOfTwoNumber $newFileSize $armBsDiffFileSize)
	noCompressionDiffFileSize_percentage=$(calcPercentageOfTwoNumber $newFileSize $noCompressionDiffFileSize)
	nonCompressedBsPatchSizeAfterLZ4_percentage=$(calcPercentageOfTwoNumber $newFileSize $nonCompressedBsPatchSizeAfterLZ4)
	#relative results in next line
	printf "%s,%s%%,%s%%,%s%%,%s%%,%s%%,%s%%\n"  "$testName""relativeToNewFileSize(%)" $oldFileSize_percentage $newFileSize_percentage $originalBsPatchDiffFileSize_percentage $armBsDiffFileSize_percentage $noCompressionDiffFileSize_percentage $nonCompressedBsPatchSizeAfterLZ4_percentage>> $csvFile
	
	
	echo "$originalBsPatchDiffFileSize_percentage"
	#echo $diffFileSize
	#echo "compressing diffFile to see how small it gets"
	#lz4 $diffFile $diffFile$frameSize.lz4
	#echo "patched file to see how small it gets"
	#lz4 $patchedFile $patchedFile$frameSize.lz4
}


function run_bs_patch_test_with_frame() {
frameSize=$1
run_bs_patch_test "Test 1" "./test_data/old1.bin" "./test_data/new1.bin" "./test-folder/diff1.bsdiff" "./test-folder/patched1.bin"
run_bs_patch_test "Test 2" ./test_data/old2.bin ./test_data/new2.bin ./test-folder/diff2.bsdiff ./test-folder/patched2.bin
run_bs_patch_test "Test 3: string tweak" ./test_data/string_tweak_old.bin ./test_data/string_tweak_new.bin ./test-folder/string_tweak_diff.bsdiff ./test-folder/string_tweak_patched.bin
run_bs_patch_test "Test 4: driver add" ./test_data/driver_add_old.bin ./test_data/driver_add_new.bin ./test-folder/driver_add_diff.bsdiff ./test-folder/driver_add_patched.bin
run_bs_patch_test "Test 5: app update" ./test_data/app_update_old.bin ./test_data/app_update_new.bin ./test-folder/app_update_diff.bsdiff ./test-folder/app_update_patched.bin
run_bs_patch_test "Test 6: example from 2.0.0 to 2.1.0" ./test_data/mbed-cloud-client-example-2-0-0.bin ./test_data/mbed-cloud-client-example-2-1-0.bin ./test-folder/mbed-cloud-client-example_to_2-1-1.bsdiff ./test-folder/mbed-cloud-client-example-2-1-0_patched.bin

#very slow
#run_bs_patch_test "Test 7: edge rel 060 to 071" ./test_data/rpi-mbed-image-raspberrypi3-update-image.rootfs.060.tar ./test_data/rpi-mbed-image-raspberrypi3-update-image.rootfs.071.tar ./test-folder/rpi-mbed-image-raspberrypi3-update-image.rootfs.060to071.bsdiff ./test-folder/rpi-mbed-image-raspberrypi3-update-image.rootfs.071_patched.tar


}

printf "Case,Original File, New File,Original BS patched, ARM BS1, ARM BS0(nocompress), ARMBS0 compressed with LZ4\n" >> $csvFile
echo "*********************************"
: 
run_bs_patch_test_with_frame 64
run_bs_patch_test_with_frame 128
run_bs_patch_test_with_frame 256
run_bs_patch_test_with_frame 512
run_bs_patch_test_with_frame 1024
run_bs_patch_test_with_frame 2048
run_bs_patch_test_with_frame 4096
run_bs_patch_test_with_frame 8192
run_bs_patch_test_with_frame 32768
run_bs_patch_test_with_frame 65536
run_bs_patch_test_with_frame 131072
run_bs_patch_test_with_frame 1048576

#run_bs_patch_test_with_frame 512
echo "*********************************"
echo "See "$csvFile" for results" 
#ls -la test-folder	