#!/bin/bash

# Mbed Cloud Client Test Builder and Runner Script
# This script builds and runs the PAL (Platform Abstraction Layer) tests
# for the mbed-cloud-client library

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_header() {
    echo -e "${BLUE}===========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}===========================================${NC}"
}

print_step() {
    echo -e "${GREEN}[STEP]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Configuration
BUILD_DIR="build-tests"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"

# Test modules available
TEST_MODULES=(
    "sanityTests"
    "RTOSTests" 
    "ROTTests"
    "EntropyTests"
    "NetworkTests"
    "DRBGTests"
    "FileSystemTests"
    "TimeTests"
    "TLSTests"
    "UpdateTests"
    "FlashTests"
    "SotpTests"
    "palTests"  # All tests combined
)

# Function to check prerequisites
check_prerequisites() {
    print_step "Checking prerequisites..."
    
    # Check if git submodules are initialized
    if [ ! -f "lib/libwebsockets/libwebsockets/CMakeLists.txt" ] || \
       [ ! -f "lib/jansson/jansson/CMakeLists.txt" ] || \
       [ ! -f "lib/libevent/libevent/CMakeLists.txt" ] || \
       [ ! -d "lib/mbedtls/library" ]; then
        print_error "Git submodules not initialized. Running 'git submodule update --init --recursive'..."
        git submodule update --init --recursive
    fi
    
    # Check for required tools
    command -v cmake >/dev/null 2>&1 || { print_error "cmake is required but not installed. Aborting."; exit 1; }
    command -v make >/dev/null 2>&1 || { print_error "make is required but not installed. Aborting."; exit 1; }
    command -v gcc >/dev/null 2>&1 || { print_error "gcc is required but not installed. Aborting."; exit 1; }
    
    print_success "Prerequisites check completed."
}

# Function to clean build directory
clean_build() {
    print_step "Cleaning build directory..."
    if [ -d "$BUILD_DIR" ]; then
        rm -rf "$BUILD_DIR"
        print_success "Build directory cleaned."
    else
        print_warning "Build directory doesn't exist, nothing to clean."
    fi
}

# Function to configure CMake for tests
configure_cmake() {
    print_step "Configuring CMake for tests..."
    
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    
    # Configure CMake with tests enabled
    # Note: Setting DISABLE_PAL_TESTS=OFF to enable PAL tests
    cmake \
        -DCMAKE_BUILD_TYPE=Debug \
        -DBUILD_TARGET=test \
        -DTARGET_GROUP=test \
        -DDISABLE_PAL_TESTS=OFF \
        -DPAL_USE_FILESYSTEM=1 \
        -DPAL_USE_HW_ROT=0 \
        -DPAL_USE_HW_TRNG=0 \
        -DOS_BRAND=Linux \
        -DPAL_TARGET_DEVICE=x86_x64 \
        -DENABLE_COVERAGE=1 \
        ..
    
    cd "$PROJECT_ROOT"
    print_success "CMake configuration completed."
}

# Function to build the tests
build_tests() {
    print_step "Building PAL tests..."
    
    cd "$BUILD_DIR"
    
    # Build the PAL library first
    if make pal -j$(nproc); then
        print_success "PAL library built successfully"
    else
        print_error "Failed to build PAL library"
        exit 1
    fi
    
    # Check if Unity test framework is available
    print_step "Checking for Unity test framework..."
    if make help 2>/dev/null | grep -q "palunity\|unity"; then
        print_step "Building Unity test framework..."
        if make palunity -j$(nproc); then
            print_success "Unity test framework built successfully"
        else
            print_error "Failed to build Unity test framework"
        fi
    else
        print_warning "Unity test framework not available in this build configuration"
        print_warning "PAL unit tests appear to be disabled"
        print_warning ""
        print_warning "To enable PAL tests, you may need to:"
        print_warning "1. Reconfigure with DISABLE_PAL_TESTS=OFF"
        print_warning "2. Ensure Unity test framework is properly configured"
        print_warning ""
        print_warning "Available targets include:"
        make help 2>/dev/null | grep -E "(test|Test|pal)" | head -15
        echo ""
        print_warning "Continuing with available test targets..."
    fi
    
    # Build platform common components
    if make help 2>/dev/null | grep -q "platformCommon"; then
        make platformCommon -j$(nproc) || print_warning "platformCommon target failed, continuing..."
    fi
    
    # Build mbedTrace
    if make help 2>/dev/null | grep -q "mbedTrace"; then
        make mbedTrace -j$(nproc) || print_warning "mbedTrace target failed, continuing..."
    fi
    
    # Find and build actual available test targets
    print_step "Finding available test targets..."
    available_tests=$(make help 2>/dev/null | grep -E "test$" | grep -v "cmake" | sed 's/^\.\.\. //' | head -10)
    
    if [ -n "$available_tests" ]; then
        print_success "Found available test targets:"
        echo "$available_tests"
        echo ""
        
        # Build available test targets
        echo "$available_tests" | while read -r test_target; do
            if [ -n "$test_target" ]; then
                clean_target=$(echo "$test_target" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')
                if [ -n "$clean_target" ]; then
                    print_step "Building $clean_target..."
                    if make "$clean_target" -j$(nproc); then
                        print_success "Built $clean_target successfully"
                    else
                        print_warning "Failed to build $clean_target, continuing..."
                    fi
                fi
            fi
        done
    else
        print_warning "No conventional test targets found"
        print_warning "Available targets:"
        make help 2>/dev/null | grep -E "(pal|test)" | head -10
    fi
    
    cd "$PROJECT_ROOT"
    print_success "Test building completed."
}

# Function to run a specific test module
run_test_module() {
    local module="$1"
    local test_executable
    
    print_step "Running $module tests..."
    
    cd "$BUILD_DIR"
    
    # Look for the test executable with various patterns
    test_executable=$(find . -name "*$module*" -type f -executable 2>/dev/null | head -1)
    
    # If not found, try different patterns
    if [ -z "$test_executable" ]; then
        test_executable=$(find . -name "*${module}*test*" -type f -executable 2>/dev/null | head -1)
    fi
    
    # If still not found, try without the module name but with "test" in name
    if [ -z "$test_executable" ]; then
        test_executable=$(find . -name "*test*" -type f -executable 2>/dev/null | grep -i "$module" | head -1)
    fi
    
    if [ -n "$test_executable" ]; then
        print_step "Found test executable: $test_executable"
        echo "----------------------------------------"
        if timeout 300 "$test_executable" 2>&1; then
            print_success "$module tests completed successfully."
        else
            local exit_code=$?
            if [ $exit_code -eq 124 ]; then
                print_error "$module tests timed out after 5 minutes."
            else
                print_error "$module tests failed with exit code: $exit_code"
            fi
            return $exit_code
        fi
        echo "----------------------------------------"
    else
        print_warning "No executable found for $module. Skipping..."
        print_warning "Available test executables:"
        find . -name "*test*" -type f -executable 2>/dev/null | head -5
    fi
    
    cd "$PROJECT_ROOT"
}

# Function to run all available tests
run_all_tests() {
    print_step "Running all available tests..."
    
    local failed_tests=()
    local passed_tests=()
    
    cd "$BUILD_DIR"
    
    # Find all test executables
    print_step "Finding available test executables..."
    test_executables=$(find . -name "*test*" -type f -executable 2>/dev/null | sort)
    
    if [ -z "$test_executables" ]; then
        print_warning "No test executables found in build directory"
        print_warning "Available files:"
        find . -name "*test*" -type f 2>/dev/null | head -10
        cd "$PROJECT_ROOT"
        return 1
    fi
    
    print_success "Found test executables:"
    echo "$test_executables"
    echo ""
    
    # Run each test executable
    echo "$test_executables" | while read -r test_exec; do
        if [ -n "$test_exec" ] && [ -x "$test_exec" ]; then
            test_name=$(basename "$test_exec")
            print_step "Running $test_name..."
            echo "========================================="
            
            if timeout 300 "$test_exec" 2>&1; then
                print_success "$test_name completed successfully"
                passed_tests+=("$test_name")
            else
                local exit_code=$?
                if [ $exit_code -eq 124 ]; then
                    print_error "$test_name timed out after 5 minutes"
                else
                    print_error "$test_name failed with exit code: $exit_code"
                fi
                failed_tests+=("$test_name")
            fi
            echo "========================================="
            echo ""
        fi
    done
    
    cd "$PROJECT_ROOT"
    
    # Print summary
    print_header "TEST SUMMARY"
    
    if [ ${#passed_tests[@]} -gt 0 ]; then
        print_success "Passed tests (${#passed_tests[@]}):"
        for test in "${passed_tests[@]}"; do
            echo "  ✅ $test"
        done
    fi
    
    if [ ${#failed_tests[@]} -gt 0 ]; then
        print_error "Failed tests (${#failed_tests[@]}):"
        for test in "${failed_tests[@]}"; do
            echo "  ❌ $test"
        done
        return 1
    else
        print_success "All tests passed!"
        return 0
    fi
}

# Function to run comprehensive tests (palTests - all combined)
run_comprehensive_tests() {
    print_step "Running comprehensive PAL tests (all modules combined)..."
    run_test_module "palTests"
}

# Function to show test information
show_test_info() {
    print_header "Available Test Modules"
    echo "This script can build and run the following PAL test modules:"
    echo ""
    for module in "${TEST_MODULES[@]}"; do
        case $module in
            "sanityTests") echo "  • $module - Basic sanity checks" ;;
            "RTOSTests") echo "  • $module - Real-time OS operations, threading, synchronization" ;;
            "ROTTests") echo "  • $module - Root of Trust operations" ;;
            "EntropyTests") echo "  • $module - Entropy generation for cryptographic operations" ;;
            "NetworkTests") echo "  • $module - Socket operations, network connectivity" ;;
            "DRBGTests") echo "  • $module - Deterministic Random Bit Generator" ;;
            "FileSystemTests") echo "  • $module - File operations, directory operations, storage management" ;;
            "TimeTests") echo "  • $module - Time-related functions" ;;
            "TLSTests") echo "  • $module - TLS/SSL operations" ;;
            "UpdateTests") echo "  • $module - Firmware update operations" ;;
            "FlashTests") echo "  • $module - Flash storage operations" ;;
            "SotpTests") echo "  • $module - Secure One Time Programming" ;;
            "palTests") echo "  • $module - All test modules combined" ;;
        esac
    done
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --help, -h          Show this help message"
    echo "  --info              Show test module information"
    echo "  --clean             Clean build directory only"
    echo "  --build-only        Build tests without running them"
    echo "  --run-only          Run tests without building (assumes already built)"
    echo "  --module <name>     Run specific test module"
    echo "  --comprehensive     Run comprehensive tests (all modules combined)"
    echo "  --list-modules      List available test modules"
    echo "  --no-clean          Don't clean build directory before building"
    echo ""
}

# Function to list available modules
list_modules() {
    echo "Available test modules:"
    for module in "${TEST_MODULES[@]}"; do
        echo "  - $module"
    done
}

# Main script logic
main() {
    local clean=true
    local build=true
    local run=true
    local specific_module=""
    local comprehensive=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                show_test_info
                exit 0
                ;;
            --info)
                show_test_info
                exit 0
                ;;
            --clean)
                clean_build
                exit 0
                ;;
            --build-only)
                run=false
                shift
                ;;
            --run-only)
                build=false
                clean=false
                shift
                ;;
            --module)
                specific_module="$2"
                shift 2
                ;;
            --comprehensive)
                comprehensive=true
                shift
                ;;
            --list-modules)
                list_modules
                exit 0
                ;;
            --no-clean)
                clean=false
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_test_info
                exit 1
                ;;
        esac
    done
    
    # Validate specific module if provided
    if [ -n "$specific_module" ]; then
        local valid_module=false
        for module in "${TEST_MODULES[@]}"; do
            if [ "$module" = "$specific_module" ]; then
                valid_module=true
                break
            fi
        done
        if [ "$valid_module" = false ]; then
            print_error "Invalid module: $specific_module"
            list_modules
            exit 1
        fi
    fi
    
    print_header "Mbed Cloud Client Test Builder and Runner"
    
    # Check prerequisites
    check_prerequisites
    
    # Clean if requested
    if [ "$clean" = true ]; then
        clean_build
    fi
    
    # Build if requested
    if [ "$build" = true ]; then
        configure_cmake
        build_tests
    fi
    
    # Run tests if requested
    if [ "$run" = true ]; then
        if [ -n "$specific_module" ]; then
            run_test_module "$specific_module"
        elif [ "$comprehensive" = true ]; then
            run_comprehensive_tests
        else
            run_all_tests
        fi
    fi
    
    print_success "Script completed successfully!"
}

# Run main function with all arguments
main "$@" 