#!/bin/bash

# Pass all arguments to the actual binary
CMD="./build/bin/edge-core $@"

echo "Starting: $CMD"

while true; do
    $CMD
    EXIT_CODE=$?
    echo "Process exited with code $EXIT_CODE, restarting in 5s..."
    sleep 5
done
