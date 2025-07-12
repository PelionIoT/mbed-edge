JOBS:=$(shell nproc)

.PHONY: clean build-developer build-developer-debug \
	build-byoc build-byoc-debug build-factory \
	generate-cli-parsers run-edge-core all \
	run-edge-core-resetting-storage build-doc \
	build-with-sbom extract-sbom

clean:
	rm -rf build build-doc build-nondebug config/edge_version_info.h

build:
	mkdir -p build

generate-cli-parsers:
	cd edge-core && ./gen_docopt.sh

lib/mbed-cloud-client/source/update_default_resources.c: lib/mbed-cloud-client
	manifest-dev-tool init

build-developer-debug: lib/mbed-cloud-client/source/update_default_resources.c generate-cli-parsers build
	cd build && cmake -DDEBUG=ON -DDEVELOPER_MODE=ON -DFIRMWARE_UPDATE=ON -DTRACE_COAP_PAYLOAD=ON -DTRACE_LEVEL=DEBUG -DCMAKE_BUILD_TYPE=Debug .. && make -j ${JOBS} && cd ..

build-developer: lib/mbed-cloud-client/source/update_default_resources.c generate-cli-parsers build
	cd build && cmake -DDEVELOPER_MODE=ON -DFIRMWARE_UPDATE=ON -DTRACE_COAP_PAYLOAD=ON -DTRACE_LEVEL=INFO -DCMAKE_BUILD_TYPE=Debug .. && make -j ${JOBS} && cd ..

build-developer-thread: lib/mbed-cloud-client/source/update_default_resources.c generate-cli-parsers build
	cd build && cmake -DENABLE_THREAD_SANITIZE=1 -DDEVELOPER_MODE=ON -DFIRMWARE_UPDATE=ON -DTRACE_COAP_PAYLOAD=ON -DTRACE_LEVEL=ERROR -DCMAKE_BUILD_TYPE=Debug .. && make -j ${JOBS} && cd ..

build-developer-with-coverage: lib/mbed-cloud-client/source/update_default_resources.c generate-cli-parsers build
	cd build && cmake -DENABLE_COVERAGE=1 -DDEVELOPER_MODE=ON -DFIRMWARE_UPDATE=ON -DTRACE_COAP_PAYLOAD=ON -DTRACE_LEVEL=INFO -DCMAKE_BUILD_TYPE=Debug .. && make -j ${JOBS} && cd ..

build-byoc-with-coverage: lib/mbed-cloud-client/source/update_default_resources.c generate-cli-parsers build
	cd build && cmake -DENABLE_COVERAGE=1 -DBYOC_MODE=ON -DFIRMWARE_UPDATE=ON -DTRACE_COAP_PAYLOAD=ON -DTRACE_LEVEL=INFO -DCMAKE_BUILD_TYPE=Debug .. && make -j ${JOBS} && cd ..

build-byoc: lib/mbed-cloud-client/source/update_default_resources.c generate-cli-parsers build
	cd build && cmake -DBYOC_MODE=ON -DFIRMWARE_UPDATE=ON -DTRACE_LEVEL=INFO -DCMAKE_BUILD_TYPE=Debug .. && make -j ${JOBS} && cd ..

build-byoc-thread: lib/mbed-cloud-client/source/update_default_resources.c generate-cli-parsers build
	cd build && cmake -DENABLE_THREAD_SANITIZE=1 -DBYOC_MODE=ON -DFIRMWARE_UPDATE=ON -DTRACE_LEVEL=INFO -DCMAKE_BUILD_TYPE=Debug .. && make -j ${JOBS} && cd ..

build-byoc-debug: lib/mbed-cloud-client/source/update_default_resources.c generate-cli-parsers build
	cd build && cmake -DBYOC_MODE=ON -DFIRMWARE_UPDATE=ON -DTRACE_LEVEL=DEBUG -DTRACE_COAP_PAYLOAD=ON -DCMAKE_BUILD_TYPE=Debug .. && make -j ${JOBS} && cd ..

build-byoc-debug-udp: lib/mbed-cloud-client/source/update_default_resources.c generate-cli-parsers build
	cd build && cmake -DBYOC_MODE=ON -DFIRMWARE_UPDATE=ON -DTRACE_LEVEL=DEBUG -DTRACE_COAP_PAYLOAD=ON -DCMAKE_BUILD_TYPE=Debug -DCLOUD_CLIENT_CONFIG=../config/mbed_cloud_client_udp_user_config.h .. && make -j ${JOBS} && cd ..

build-factory: lib/mbed-cloud-client/source/update_default_resources.c generate-cli-parsers build
	cd build && cmake -DFACTORY_MODE=ON -DFIRMWARE_UPDATE=ON -DTRACE_LEVEL=INFO -DCMAKE_BUILD_TYPE=Debug .. && make -j ${JOBS} && cd ..

build-doc:
	mkdir -p build-doc && cd build-doc && cmake -DBUILD_DOCUMENTATION=ON .. && make edge-doc
	echo "\033[0;33mDocumentation is at ./build-doc/doxygen/index.html\033[0m"

run-edge-core:
	./build/bin/edge-core -p 22225 -o 8080

run-edge-core-resetting-storage:
	./build/bin/edge-core -p 22225 -o 8080 --reset-storage

# SBOM generation targets
build-with-sbom: lib/mbed-cloud-client/source/update_default_resources.c generate-cli-parsers
	docker build -t edge-core:sbom-latest .

extract-sbom: build-with-sbom
	@echo "Extracting SBOM files from Docker image..."
	@docker create --name temp-sbom-container edge-core:sbom-latest
	@docker cp temp-sbom-container:/usr/src/app/mbed-edge/sbom.spdx.json ./sbom.spdx.json
	@docker cp temp-sbom-container:/usr/src/app/mbed-edge/sbom.spdx.txt ./sbom.spdx.txt
	@docker cp temp-sbom-container:/usr/src/app/mbed-edge/sbom.cyclonedx.json ./sbom.cyclonedx.json
	@docker cp temp-sbom-container:/usr/src/app/mbed-edge/edge-core-dependencies.txt ./edge-core-dependencies.txt
	@docker rm temp-sbom-container
	@echo "SBOM files extracted to current directory:"
	@echo "  - sbom.spdx.json"
	@echo "  - sbom.spdx.txt" 
	@echo "  - sbom.cyclonedx.json"
	@echo "  - edge-core-dependencies.txt"

all: build-byoc build-doc
