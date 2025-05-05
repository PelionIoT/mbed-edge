#!/bin/bash
set -euxo pipefail

# Parse command line
#
# FIRMWARE

FIRMWARE=${1?candidate file name is missing.}

echo "Got firmware at $FIRMWARE"

# Perform firmware update
# exit 0 -> Success, anything else is failure
exit 0