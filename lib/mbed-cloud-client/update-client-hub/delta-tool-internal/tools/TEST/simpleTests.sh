#/bin/bash
# note you need to have manifest-tool from manifest-tool-internal using branch delta-tool-fixes to run this

set -x
mkdir test-results
echo -e "\e[4m Test1 generate with -f using pre generated delta \e[0m"
./generateDeltaManifest.sh testData/README.md testData/READMEnew.md test-results/readMeDelta.bin test-results/delta-manifest-from-manifest-tool.bin
./verifyManifestAndDeltaExists.sh test-results/readMeDelta.bin test-results/delta-manifest-from-manifest-tool.bin

echo -e "\e[4m Test2 generate with -b using bsdiff from script \e[0m"
./generateDeltaManifest_withBsDiffBinary.sh testData/README.md testData/READMEnew.md test-results/readMeDelta.bin test-results/delta-manifest-from-manifest-tool-withbin.bin
./verifyManifestAndDeltaExists.sh test-results/readMeDelta.bin test-results/delta-manifest-from-manifest-tool-withbin.bin
