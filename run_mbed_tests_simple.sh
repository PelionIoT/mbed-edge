#!/bin/bash

# Simple Mbed Edge Test Runner with SSL Platform Backend Selection
# This script builds and runs the available mbed-edge tests

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}===========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}===========================================${NC}"
}

print_step() {
    echo -e "${GREEN}[STEP]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Simple Mbed Edge Test Runner with SSL Platform Backend Selection

OPTIONS:
    -s, --ssl-backend BACKEND   Set SSL platform backend:
                                  1 = mbed-TLS (default)
                                  2 = OpenSSL
    -h, --help                  Show this help message
    --build-only               Only build tests, don't run them
    --run-only                 Only run tests (assumes already built)
    --clean                    Clean build directory before building

EXAMPLES:
    $0                         # Use default mbed-TLS backend
    $0 --ssl-backend 1         # Explicitly use mbed-TLS backend
    $0 --ssl-backend 2         # Use OpenSSL backend
    $0 --ssl-backend 1 --build-only  # Build with mbed-TLS, don't run
    $0 --clean --ssl-backend 2 # Clean build and use OpenSSL backend

SSL PLATFORM BACKENDS:
    1 (mbed-TLS):  Default backend using mbed-TLS library
    2 (OpenSSL):   Alternative backend using system OpenSSL

EOF
}

# Default options
SSL_BACKEND=1
BUILD_ONLY=false
RUN_ONLY=false
CLEAN_BUILD=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--ssl-backend)
            SSL_BACKEND="$2"
            if [[ ! "$SSL_BACKEND" =~ ^[12]$ ]]; then
                print_error "Invalid SSL backend: $SSL_BACKEND. Must be 1 (mbed-TLS) or 2 (OpenSSL)"
                exit 1
            fi
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        --build-only)
            BUILD_ONLY=true
            shift
            ;;
        --run-only)
            RUN_ONLY=true
            shift
            ;;
        --clean)
            CLEAN_BUILD=true
            shift
            ;;
        *)
            print_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

PROJECT_ROOT=$(pwd)
BUILD_DIR="$PROJECT_ROOT/build-tests"

print_header "Mbed Edge Test Runner"

# Display SSL backend selection
case $SSL_BACKEND in
    1)
        print_step "SSL Platform Backend: mbed-TLS (backend $SSL_BACKEND)"
        ;;
    2)
        print_step "SSL Platform Backend: OpenSSL (backend $SSL_BACKEND)"
        ;;
esac

# Clean build directory if requested
if [ "$CLEAN_BUILD" = true ]; then
    print_step "Cleaning build directory..."
    rm -rf "$BUILD_DIR"
    print_success "Build directory cleaned"
fi

# Skip build if run-only mode
if [ "$RUN_ONLY" = false ]; then
    # Create and configure build directory
    print_step "Configuring build..."
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    cmake .. \
        -DDEVELOPER_MODE=ON \
        -DDISABLE_PAL_TESTS=OFF \
        -DBUILD_TYPE=test \
        -DCMAKE_BUILD_TYPE=Debug \
        -DSSL_PLATFORM_BACKEND=$SSL_BACKEND

    print_success "Build configured with SSL backend $SSL_BACKEND"

    # Find available test targets
    print_step "Finding available test targets..."
    available_tests=$(make help 2>/dev/null | grep -E "test$" | grep -v -E "(cmake|ContinuousTest|ExperimentalTest|NightlyTest)" | sed 's/^\.\.\. //' | head -10)

    if [ -z "$available_tests" ]; then
        print_error "No test targets found"
        exit 1
    fi

    print_success "Found test targets:"
    echo "$available_tests"
    echo ""

    # Build tests
    print_step "Building tests..."
    failed_builds=()
    successful_builds=()

    echo "$available_tests" | while read -r test_target; do
        if [ -n "$test_target" ]; then
            print_step "Building $test_target..."
            if make "$test_target" -j$(nproc) 2>&1; then
                print_success "Built $test_target successfully"
                echo "$test_target" >> successful_builds.tmp
            else
                print_warning "Failed to build $test_target"
                echo "$test_target" >> failed_builds.tmp
            fi
        fi
    done

    # Read results back from temp files
    if [ -f successful_builds.tmp ]; then
        successful_builds=($(cat successful_builds.tmp))
        rm -f successful_builds.tmp
    fi

    if [ -f failed_builds.tmp ]; then
        failed_builds=($(cat failed_builds.tmp))
        rm -f failed_builds.tmp
    fi

    print_header "Build Summary"
    if [ ${#successful_builds[@]} -gt 0 ]; then
        print_success "Successfully built tests:"
        for test in "${successful_builds[@]}"; do
            echo "  ✅ $test"
        done
    fi

    if [ ${#failed_builds[@]} -gt 0 ]; then
        print_warning "Failed to build tests:"
        for test in "${failed_builds[@]}"; do
            echo "  ❌ $test"
        done
    fi
else
    # Run-only mode: check if build directory exists
    if [ ! -d "$BUILD_DIR" ]; then
        print_error "Build directory not found. Please run without --run-only first."
        exit 1
    fi
    cd "$BUILD_DIR"
    
    # Get successful builds from previous run or discover
    successful_builds=($(find . -name "*test" -type f -executable | sed 's|.*/||' | head -10))
fi

# Exit if build-only mode
if [ "$BUILD_ONLY" = true ]; then
    print_success "Build completed (build-only mode)"
    exit 0
fi

# Run tests
if [ ${#successful_builds[@]} -gt 0 ]; then
    print_header "Running Tests"
    
    test_passed=()
    test_failed=()
    
    # Find test executables
    print_step "Finding test executables..."
    for test_name in "${successful_builds[@]}"; do
        # Look for the executable
        executable=$(find . -name "$test_name" -type f -executable 2>/dev/null | head -1)
        
        if [ -n "$executable" ]; then
            print_step "Running $test_name..."
            echo "========================================="
            if timeout 300 "$executable" 2>&1; then
                print_success "$test_name PASSED"
                test_passed+=("$test_name")
            else
                exit_code=$?
                if [ $exit_code -eq 124 ]; then
                    print_error "$test_name TIMED OUT (5 minutes)"
                else
                    print_error "$test_name FAILED (exit code: $exit_code)"
                fi
                test_failed+=("$test_name")
            fi
            echo "========================================="
            echo ""
        else
            print_warning "Executable not found for $test_name"
            test_failed+=("$test_name (not found)")
        fi
    done
    
    # Final summary
    print_header "TEST RESULTS"
    
    case $SSL_BACKEND in
        1) backend_name="mbed-TLS" ;;
        2) backend_name="OpenSSL" ;;
    esac
    
    echo "SSL Backend Used: $backend_name (backend $SSL_BACKEND)"
    echo ""
    
    if [ ${#test_passed[@]} -gt 0 ]; then
        print_success "PASSED TESTS (${#test_passed[@]}):"
        for test in "${test_passed[@]}"; do
            echo "  ✅ $test"
        done
    fi
    
    if [ ${#test_failed[@]} -gt 0 ]; then
        print_error "FAILED TESTS (${#test_failed[@]}):"
        for test in "${test_failed[@]}"; do
            echo "  ❌ $test"
        done
        echo ""
        print_error "Some tests failed!"
        exit 1
    else
        echo ""
        print_success "All tests passed with $backend_name backend! 🎉"
    fi
else
    print_error "No tests were successfully built"
    exit 1
fi

cd "$PROJECT_ROOT"
print_success "Test run completed!" 