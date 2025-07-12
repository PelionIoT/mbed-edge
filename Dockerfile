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

# Copy system libraries that might be needed
COPY --from=builder /lib /lib
COPY --from=builder /usr/lib /usr/lib

# Generate SBOM files focusing on the binary and its dependencies
RUN echo "Analyzing edge-core binary dependencies..." && \
    ldd ./edge-core > edge-core-dependencies.txt && \
    echo "Generating SBOM files..." && \
    syft ./edge-core -o spdx-json=sbom.spdx.json && \
    syft ./edge-core -o spdx-tag=sbom.spdx.txt && \
    syft ./edge-core -o cyclonedx-json=sbom.cyclonedx.json && \
    echo "SBOM generation complete"

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

# Copy SBOM files to the runtime image
COPY --from=sbom-generator /sbom-workspace/sbom.spdx.json ./sbom.spdx.json
COPY --from=sbom-generator /sbom-workspace/sbom.spdx.txt ./sbom.spdx.txt
COPY --from=sbom-generator /sbom-workspace/sbom.cyclonedx.json ./sbom.cyclonedx.json
COPY --from=sbom-generator /sbom-workspace/edge-core-dependencies.txt ./edge-core-dependencies.txt

CMD [ "./build/bin/edge-core", "--http-port", "8080", "--edge-pt-domain-socket", "/tmp/edge.sock" ]

EXPOSE 8080
