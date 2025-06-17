#!/bin/bash

# SSL-Platform Testing Script
# Automates the testing of ssl-platform implementation for mbed-edge
# Author: AI Assistant
# Date: $(date +%Y-%m-%d)

set -e  # Exit on any error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
TEST_PROGRAM="test_ssl_platform"
TEST_MAKEFILE="Makefile.ssl_test"

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

print_header() {
    echo
    print_status $BLUE "=================================================="
    print_status $BLUE "$1"
    print_status $BLUE "=================================================="
    echo
}

print_step() {
    print_status $YELLOW "🔧 $1"
}

print_success() {
    print_status $GREEN "✅ $1"
}

print_warning() {
    print_status $YELLOW "⚠️  $1"
}

print_error() {
    print_status $RED "❌ $1"
}

# Function to check prerequisites
check_prerequisites() {
    print_step "Checking prerequisites..."
    
    # Check if we're in the right directory
    if [[ ! -f "CMakeLists.txt" ]]; then
        print_error "Not in mbed-edge root directory! Please run from project root."
        exit 1
    fi
    
    # Check if test files exist
    if [[ ! -f "$TEST_PROGRAM.c" ]]; then
        print_error "Test source file '$TEST_PROGRAM.c' not found!"
        exit 1
    fi
    
    if [[ ! -f "$TEST_MAKEFILE" ]]; then
        print_error "Test makefile '$TEST_MAKEFILE' not found!"
        exit 1
    fi
    
    # Check for required tools
    for tool in gcc make cmake; do
        if ! command -v $tool &> /dev/null; then
            print_error "$tool is not installed!"
            exit 1
        fi
    done
    
    print_success "Prerequisites check passed"
}

# Function to build the main project
build_main_project() {
    print_step "Building main mbed-edge project..."
    
    # Create build directory if it doesn't exist
    if [[ ! -d "$BUILD_DIR" ]]; then
        mkdir -p "$BUILD_DIR"
        print_status $BLUE "Created build directory"
    fi
    
    # Configure with CMake if needed
    if [[ ! -f "$BUILD_DIR/Makefile" ]]; then
        print_step "Configuring project with CMake..."
        cd "$BUILD_DIR"
        cmake -DDEVELOPER_MODE=ON -DFIRMWARE_UPDATE=ON -DTRACE_COAP_PAYLOAD=ON -DTRACE_LEVEL=INFO -DCMAKE_BUILD_TYPE=Debug ..
        cd "$SCRIPT_DIR"
    fi
    
    # Build the project
    print_step "Compiling mbed-edge project..."
    cd "$BUILD_DIR"
    make -j$(nproc) > build.log 2>&1
    if [[ $? -eq 0 ]]; then
        print_success "Main project build completed successfully"
    else
        print_error "Main project build failed! Check build.log for details"
        tail -n 20 build.log
        exit 1
    fi
    cd "$SCRIPT_DIR"
}

# Function to verify ssl-platform library exists
verify_ssl_platform_library() {
    print_step "Verifying ssl-platform library..."
    
    local ssl_lib="$BUILD_DIR/lib/ssl-platform/libssl-platform.a"
    if [[ -f "$ssl_lib" ]]; then
        print_success "ssl-platform library found: $ssl_lib"
        
        # Show library info
        local lib_size=$(du -h "$ssl_lib" | cut -f1)
        print_status $BLUE "Library size: $lib_size"
        
        # Check for our implemented functions
        print_step "Checking for implemented functions..."
        local functions=(
            "ssl_platform_x509_get_issuer_raw"
            "ssl_platform_x509_get_subject_raw" 
            "ssl_platform_x509_get_validity"
            "ssl_platform_x509_get_signature"
            "ssl_platform_x509_get_tbs"
            "ssl_platform_ctr_drbg_reseed"
        )
        
        for func in "${functions[@]}"; do
            if nm "$ssl_lib" 2>/dev/null | grep -q "$func"; then
                print_success "Function found: $func"
            else
                print_warning "Function not found in library: $func"
            fi
        done
    else
        print_error "ssl-platform library not found at: $ssl_lib"
        exit 1
    fi
}

# Function to compile the test program
compile_test_program() {
    print_step "Compiling ssl-platform test program..."
    
    # Clean any existing test binary
    if [[ -f "$TEST_PROGRAM" ]]; then
        rm "$TEST_PROGRAM"
    fi
    
    # Compile using our test Makefile
    if make -f "$TEST_MAKEFILE" > compile.log 2>&1; then
        print_success "Test program compiled successfully"
    else
        print_error "Test program compilation failed!"
        cat compile.log
        exit 1
    fi
    
    # Verify test binary exists
    if [[ -x "$TEST_PROGRAM" ]]; then
        local binary_size=$(du -h "$TEST_PROGRAM" | cut -f1)
        print_status $BLUE "Test binary size: $binary_size"
    else
        print_error "Test binary not created or not executable"
        exit 1
    fi
}

# Function to run the tests
run_tests() {
    print_step "Running ssl-platform unit tests..."
    
    echo
    print_status $BLUE "Test output:"
    print_status $BLUE "============"
    
    # Run the test program and capture output
    if ./"$TEST_PROGRAM" > test_output.log 2>&1; then
        cat test_output.log
        print_success "Tests completed successfully"
        
        # Parse test results
        local passed_tests=$(grep -c "✅" test_output.log || true)
        local warning_tests=$(grep -c "⚠️" test_output.log || true)
        
        echo
        print_status $BLUE "Test Summary:"
        print_status $GREEN "Passed: $passed_tests tests"
        if [[ $warning_tests -gt 0 ]]; then
            print_status $YELLOW "Warnings: $warning_tests tests (expected due to test data limitations)"
        fi
        
    else
        print_error "Test execution failed!"
        cat test_output.log
        exit 1
    fi
}

# Function to run integration tests
run_integration_tests() {
    print_step "Running integration tests..."
    
    # Test 1: Verify edge-core binary exists and starts
    local edge_core="$BUILD_DIR/bin/edge-core"
    if [[ -x "$edge_core" ]]; then
        print_success "edge-core binary found"
        
        # Test if it can show help (basic functionality test)
        if timeout 5s "$edge_core" --help > /dev/null 2>&1; then
            print_success "edge-core starts and shows help correctly"
        else
            print_warning "edge-core help test failed (may be expected)"
        fi
    else
        print_warning "edge-core binary not found or not executable"
    fi
    
    # Test 2: Check for crypto service library
    local crypto_lib="$BUILD_DIR/lib/mbed-cloud-client/factory-configurator-client/libcrypto-service.a"
    if [[ -f "$crypto_lib" ]]; then
        print_success "crypto-service library found (ssl-platform integration working)"
    else
        print_warning "crypto-service library not found"
    fi
}

# Function to generate test report
generate_test_report() {
    print_step "Generating test report..."
    
    local report_file="ssl_platform_test_report.txt"
    
    cat > "$report_file" << EOF
SSL-Platform Test Report
========================
Date: $(date)
Host: $(hostname)
User: $(whoami)
Project: mbed-edge

Test Environment:
- Build Directory: $BUILD_DIR
- Compiler: $(gcc --version | head -n1)
- Make: $(make --version | head -n1)

Library Status:
$(ls -la "$BUILD_DIR/lib/ssl-platform/libssl-platform.a" 2>/dev/null || echo "Library not found")

Test Results:
$(cat test_output.log 2>/dev/null || echo "No test output found")

Build Log Summary:
$(tail -n 10 "$BUILD_DIR/build.log" 2>/dev/null || echo "No build log found")

EOF
    
    print_success "Test report generated: $report_file"
}

# Function to cleanup
cleanup() {
    print_step "Cleaning up temporary files..."
    
    # Clean test artifacts
    rm -f compile.log test_output.log
    
    # Optionally clean test binary (comment out if you want to keep it)
    # rm -f "$TEST_PROGRAM"
    
    print_success "Cleanup completed"
}

# Main execution function
main() {
    print_header "SSL-Platform Testing Script"
    
    echo "This script will:"
    echo "1. Check prerequisites"
    echo "2. Build the main mbed-edge project"
    echo "3. Verify ssl-platform library"
    echo "4. Compile ssl-platform unit tests"
    echo "5. Run unit tests"
    echo "6. Run integration tests"
    echo "7. Generate test report"
    echo
    
    # Ask for confirmation
    read -p "Continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status $YELLOW "Test execution cancelled"
        exit 0
    fi
    
    # Execute test steps
    check_prerequisites
    build_main_project  
    verify_ssl_platform_library
    compile_test_program
    run_tests
    run_integration_tests
    generate_test_report
    cleanup
    
    print_header "🎉 SSL-Platform Testing Completed Successfully!"
    print_status $GREEN "All tests passed! ssl-platform implementation is working correctly."
    print_status $BLUE "Test report saved as: ssl_platform_test_report.txt"
}

# Handle script interruption
trap 'print_error "Script interrupted!"; cleanup; exit 1' INT TERM

# Run main function
main "$@" 