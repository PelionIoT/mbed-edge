# Stage 1: Build the edge-core binary
FROM ubuntu:22.04 AS builder

ARG developer_certificate=./config/mbed_cloud_dev_credentials.c
ARG update_certificate=./config/update_default_resources.c

WORKDIR /usr/src/app/mbed-edge

RUN apt-get update && \
    DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata && \
    apt-get install -y build-essential libc6-dev cmake python3.6 python3-pip python3-setuptools && \
    apt-get install -y vim python3-venv

COPY . .

RUN pip3 install --upgrade pip
RUN pip3 install manifest-tool

# Use existing test data for update certificates if the target file doesn't exist
RUN if [ ! -f lib/mbed-cloud-client/source/update_default_resources.c ]; then \
        echo "Using test data for update certificates..." && \
        cp edge-tool/test_data/update_default_resources.c lib/mbed-cloud-client/source/update_default_resources.c; \
    fi

RUN mkdir -p build && \
    cd build  &&  \
    cmake -DDEVELOPER_MODE=ON -DFIRMWARE_UPDATE=ON .. && \
    make

# Stage 2: SBOM Generation
FROM ubuntu:22.04 AS sbom-generator

# Install tools needed for binary analysis and SBOM generation
RUN apt-get update && \
    DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata && \
    apt-get install -y curl wget file binutils dpkg-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Syft for SBOM generation
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

WORKDIR /sbom-workspace

# Copy the built binary and its runtime environment
COPY --from=builder /usr/src/app/mbed-edge/build/bin/edge-core ./edge-core
COPY --from=builder /usr/src/app/mbed-edge/build ./build

# Copy system libraries that might be needed for analysis
COPY --from=builder /lib /lib
COPY --from=builder /usr/lib /usr/lib

# Create comprehensive binary analysis script
RUN cat > analyze_binary.sh << 'EOF'
#!/bin/bash
set -e

echo "=== EDGE-CORE BINARY ANALYSIS ==="
echo "Binary: $(file ./edge-core)"
echo "Size: $(stat -c%s ./edge-core) bytes"
echo ""

echo "=== DYNAMIC DEPENDENCIES (ldd) ==="
ldd ./edge-core > edge-core-dynamic-deps.txt
cat edge-core-dynamic-deps.txt
echo ""

echo "=== STATIC ANALYSIS (readelf) ==="
echo "Checking for statically linked libraries..."
readelf -d ./edge-core > edge-core-readelf.txt 2>/dev/null || echo "No dynamic section found"
if [ -s edge-core-readelf.txt ]; then
    echo "Dynamic section found - binary uses dynamic linking"
    grep "NEEDED" edge-core-readelf.txt > edge-core-needed-libs.txt || echo "No NEEDED entries"
else
    echo "No dynamic section - binary may be statically linked"
fi
echo ""

echo "=== SYMBOLS ANALYSIS ==="
echo "Checking for embedded library symbols..."
objdump -t ./edge-core 2>/dev/null | grep -E "(mbedtls|jansson|libevent|websocket)" > edge-core-embedded-symbols.txt || echo "No obvious embedded library symbols found"
echo ""

echo "=== PACKAGE MAPPING ==="
echo "Mapping dynamic libraries to system packages..."
> edge-core-package-mapping.txt
if [ -s edge-core-dynamic-deps.txt ]; then
    while IFS= read -r line; do
        if [[ $line =~ .*=>.*\(.*\) ]]; then
            lib_path=$(echo "$line" | awk '{print $3}')
            if [ "$lib_path" != "(0x" ] && [ -f "$lib_path" ]; then
                package=$(dpkg -S "$lib_path" 2>/dev/null | cut -d: -f1 || echo "unknown")
                echo "$lib_path -> $package" >> edge-core-package-mapping.txt
            fi
        fi
    done < edge-core-dynamic-deps.txt
fi
echo ""

echo "=== LICENSE ANALYSIS ==="
echo "Analyzing licenses of dependencies..."
> edge-core-license-analysis.txt
if [ -s edge-core-package-mapping.txt ]; then
    while IFS= read -r line; do
        package=$(echo "$line" | cut -d' ' -f3)
        if [ "$package" != "unknown" ] && [ "$package" != "" ]; then
            license=$(dpkg-query -W -f='${Package}: ${License}\n' "$package" 2>/dev/null || echo "$package: License info not available")
            echo "$license" >> edge-core-license-analysis.txt
        fi
    done < edge-core-package-mapping.txt
fi

echo "Analysis complete. Files generated:"
ls -la edge-core-*.txt
EOF

chmod +x analyze_binary.sh
./analyze_binary.sh

# Generate SBOM files with enhanced metadata
echo "=== GENERATING SBOM FILES ==="
echo "Generating comprehensive SBOM with all dependencies..."
syft ./edge-core -o spdx-json=sbom-full.spdx.json
syft ./edge-core -o spdx-tag=sbom-full.spdx.txt
syft ./edge-core -o cyclonedx-json=sbom-full.cyclonedx.json

echo "Generating SBOM excluding system libraries..."
syft ./edge-core --exclude-binary-overlap-by-ownership -o spdx-json=sbom-app-only.spdx.json
syft ./edge-core --exclude-binary-overlap-by-ownership -o spdx-tag=sbom-app-only.spdx.txt
syft ./edge-core --exclude-binary-overlap-by-ownership -o cyclonedx-json=sbom-app-only.cyclonedx.json

# Create a summary report
cat > sbom-analysis-report.md << 'EOF'
# Edge-Core SBOM Analysis Report

## Binary Analysis Summary

This report provides analysis of the edge-core binary and its dependencies for license compliance and SBOM generation.

### Linking Analysis
- **Dynamic Dependencies**: See `edge-core-dynamic-deps.txt`
- **Static Analysis**: See `edge-core-readelf.txt`
- **Package Mapping**: See `edge-core-package-mapping.txt`
- **License Analysis**: See `edge-core-license-analysis.txt`

### SBOM Files Generated

#### Full SBOM (includes all dependencies)
- `sbom-full.spdx.json` - Complete SPDX JSON format
- `sbom-full.spdx.txt` - Complete SPDX tag-value format  
- `sbom-full.cyclonedx.json` - Complete CycloneDX JSON format

#### Application-Only SBOM (excludes system libraries)
- `sbom-app-only.spdx.json` - Application SPDX JSON format
- `sbom-app-only.spdx.txt` - Application SPDX tag-value format
- `sbom-app-only.cyclonedx.json` - Application CycloneDX JSON format

### License Compliance Notes

**Apache 2.0 Project Boundaries:**
- The edge-core application itself remains under Apache 2.0 license
- System libraries are runtime dependencies, not distributed components
- Dynamic linking to GPL libraries does not affect Apache 2.0 licensing of the application
- Static linking would require careful license compatibility review

### Recommendations

1. Use `sbom-app-only.*` files for distribution SBOM
2. Use `sbom-full.*` files for complete dependency tracking
3. Review `edge-core-license-analysis.txt` for any GPL dependencies
4. Verify static vs dynamic linking status in analysis files

EOF

echo "SBOM generation complete with analysis"

# Stage 3: Runtime image
FROM ubuntu:22.04 AS runtime

ARG developer_certificate=./config/mbed_cloud_dev_credentials.c
ARG update_certificate=./config/update_default_resources.c

WORKDIR /usr/src/app/mbed-edge

# Install only runtime dependencies
RUN apt-get update && \
    DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata && \
    apt-get install -y python3 python3-pip && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN pip3 install --upgrade pip
RUN pip3 install manifest-tool

# Copy the built binary and necessary files
COPY --from=builder /usr/src/app/mbed-edge/build ./build
COPY --from=builder /usr/src/app/mbed-edge/config ./config

# Copy SBOM files and analysis to the runtime image
COPY --from=sbom-generator /sbom-workspace/sbom-full.spdx.json ./sbom-full.spdx.json
COPY --from=sbom-generator /sbom-workspace/sbom-full.spdx.txt ./sbom-full.spdx.txt
COPY --from=sbom-generator /sbom-workspace/sbom-full.cyclonedx.json ./sbom-full.cyclonedx.json
COPY --from=sbom-generator /sbom-workspace/sbom-app-only.spdx.json ./sbom-app-only.spdx.json
COPY --from=sbom-generator /sbom-workspace/sbom-app-only.spdx.txt ./sbom-app-only.spdx.txt
COPY --from=sbom-generator /sbom-workspace/sbom-app-only.cyclonedx.json ./sbom-app-only.cyclonedx.json
COPY --from=sbom-generator /sbom-workspace/edge-core-dynamic-deps.txt ./edge-core-dynamic-deps.txt
COPY --from=sbom-generator /sbom-workspace/edge-core-readelf.txt ./edge-core-readelf.txt
COPY --from=sbom-generator /sbom-workspace/edge-core-package-mapping.txt ./edge-core-package-mapping.txt
COPY --from=sbom-generator /sbom-workspace/edge-core-license-analysis.txt ./edge-core-license-analysis.txt
COPY --from=sbom-generator /sbom-workspace/sbom-analysis-report.md ./sbom-analysis-report.md

CMD [ "./build/bin/edge-core", "--http-port", "8080", "--edge-pt-domain-socket", "/tmp/edge.sock" ]

EXPOSE 8080
