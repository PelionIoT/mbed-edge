#!/bin/bash

# Enable core dumps
ulimit -c unlimited
mkdir -p /core
echo "Core dumps enabled. Core files will be written to /core"

# Path to the binary
CMD="./build/bin/edge-core $@"

echo "Starting: $CMD"

# Run + monitor
while true; do
    $CMD
    EXIT_CODE=$?
    echo "Process exited with code $EXIT_CODE"

    # If a core file was generated, print the stack trace
    CORE_FILE=$(ls /core/core.edge-core.* 2>/dev/null | tail -n 1)
    if [[ -f core ]]; then
        TIMESTAMP=$(date +%s)
        mv core "core.edge-core.${TIMESTAMP}"
        echo "==== Crash detected. Stack trace ===="
        gdb -batch -ex "thread apply all bt" -ex "quit" /usr/src/app/mbed-edge/build/bin/edge-core "core.edge-core.${TIMESTAMP}"
    fi

    echo "Restarting in 5s..."
    sleep 5
done
