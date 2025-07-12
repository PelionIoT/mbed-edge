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
build-with-sbom: generate-cli-parsers
	docker build -t edge-core:sbom-latest .

extract-sbom: build-with-sbom
	@echo "Extracting SBOM files and analysis from Docker image..."
	@docker create --name temp-sbom-container edge-core:sbom-latest
	@echo "Extracting full SBOM files..."
	@docker cp temp-sbom-container:/usr/src/app/mbed-edge/sbom-full.spdx.json ./sbom-full.spdx.json
	@docker cp temp-sbom-container:/usr/src/app/mbed-edge/sbom-full.spdx.txt ./sbom-full.spdx.txt
	@docker cp temp-sbom-container:/usr/src/app/mbed-edge/sbom-full.cyclonedx.json ./sbom-full.cyclonedx.json
	@echo "Extracting application-only SBOM files..."
	@docker cp temp-sbom-container:/usr/src/app/mbed-edge/sbom-app-only.spdx.json ./sbom-app-only.spdx.json
	@docker cp temp-sbom-container:/usr/src/app/mbed-edge/sbom-app-only.spdx.txt ./sbom-app-only.spdx.txt
	@docker cp temp-sbom-container:/usr/src/app/mbed-edge/sbom-app-only.cyclonedx.json ./sbom-app-only.cyclonedx.json
	@echo "Extracting analysis files..."
	@docker cp temp-sbom-container:/usr/src/app/mbed-edge/edge-core-dynamic-deps.txt ./edge-core-dynamic-deps.txt
	@docker cp temp-sbom-container:/usr/src/app/mbed-edge/edge-core-readelf.txt ./edge-core-readelf.txt
	@docker cp temp-sbom-container:/usr/src/app/mbed-edge/edge-core-package-mapping.txt ./edge-core-package-mapping.txt
	@docker cp temp-sbom-container:/usr/src/app/mbed-edge/edge-core-license-analysis.txt ./edge-core-license-analysis.txt
	@docker cp temp-sbom-container:/usr/src/app/mbed-edge/sbom-analysis-report.md ./sbom-analysis-report.md
	@docker rm temp-sbom-container
	@echo ""
	@echo "SBOM files and analysis extracted to current directory:"
	@echo ""
	@echo "📋 FULL SBOM FILES (includes all dependencies):"
	@echo "  - sbom-full.spdx.json"
	@echo "  - sbom-full.spdx.txt"
	@echo "  - sbom-full.cyclonedx.json"
	@echo ""
	@echo "📦 APPLICATION-ONLY SBOM FILES (excludes system libraries):"
	@echo "  - sbom-app-only.spdx.json"
	@echo "  - sbom-app-only.spdx.txt"
	@echo "  - sbom-app-only.cyclonedx.json"
	@echo ""
	@echo "🔍 ANALYSIS FILES:"
	@echo "  - edge-core-dynamic-deps.txt (ldd output)"
	@echo "  - edge-core-readelf.txt (static/dynamic analysis)"
	@echo "  - edge-core-package-mapping.txt (lib to package mapping)"
	@echo "  - edge-core-license-analysis.txt (license information)"
	@echo "  - sbom-analysis-report.md (comprehensive report)"
	@echo ""
	@echo "📖 Next steps:"
	@echo "  1. Review sbom-analysis-report.md for overview"
	@echo "  2. Check edge-core-license-analysis.txt for GPL dependencies"
	@echo "  3. Use sbom-app-only.* for distribution SBOM"
	@echo "  4. Use sbom-full.* for complete dependency tracking"

all: build-byoc build-doc
