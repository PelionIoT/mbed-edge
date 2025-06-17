#!/bin/bash

# SSL Backend Comparison Test Runner
# This script runs mbed-edge tests with both mbed-TLS and OpenSSL backends for comparison

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
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

print_comparison() {
    echo -e "${PURPLE}[COMPARE]${NC} $1"
}

show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

SSL Backend Comparison Test Runner

This script runs mbed-edge tests with both mbed-TLS and OpenSSL backends
to compare their behavior and performance.

OPTIONS:
    --working-tests            Run only working/stable tests (default)
    --all-tests                Run all available tests
    --skip-openssl             Skip OpenSSL backend tests (mbed-TLS only)
    --skip-mbedtls             Skip mbed-TLS backend tests (OpenSSL only)
    --clean                    Clean build directories before testing
    -h, --help                 Show this help message

EXAMPLES:
    $0                         # Compare both backends with working tests
    $0 --all-tests             # Compare both backends with all tests
    $0 --skip-openssl          # Test only mbed-TLS backend
    $0 --clean --working-tests # Clean and test both backends

This script will:
1. Test mbed-TLS backend (backend 1)
2. Test OpenSSL backend (backend 2)
3. Compare results and show differences

EOF
}

# Default options
RUN_WORKING_TESTS=true
CLEAN_BUILD=false
SKIP_OPENSSL=false
SKIP_MBEDTLS=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --working-tests)
            RUN_WORKING_TESTS=true
            shift
            ;;
        --all-tests)
            RUN_WORKING_TESTS=false
            shift
            ;;
        --skip-openssl)
            SKIP_OPENSSL=true
            shift
            ;;
        --skip-mbedtls)
            SKIP_MBEDTLS=true
            shift
            ;;
        --clean)
            CLEAN_BUILD=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Validation
if [ "$SKIP_OPENSSL" = true ] && [ "$SKIP_MBEDTLS" = true ]; then
    print_error "Cannot skip both backends. Please specify at least one to test."
    exit 1
fi

PROJECT_ROOT=$(pwd)

print_header "SSL Backend Comparison Test Runner"

if [ "$RUN_WORKING_TESTS" = true ]; then
    test_script="run_mbed_edge_tests_working.sh"
    test_type="Working Tests"
else
    test_script="run_mbed_tests_simple.sh"
    test_type="All Tests"
fi

echo "Test Type: $test_type"
echo "Script: $test_script"
echo ""

# Results storage
declare -A results
declare -A test_counts
declare -A errors

# Clean if requested
if [ "$CLEAN_BUILD" = true ]; then
    print_step "Cleaning build directories..."
    rm -rf build-tests
    print_success "Build directories cleaned"
fi

# Test mbed-TLS backend
if [ "$SKIP_MBEDTLS" = false ]; then
    print_header "Testing mbed-TLS Backend (Backend 1)"
    
    start_time=$(date +%s)
    
    if [ "$CLEAN_BUILD" = true ]; then
        extra_args="--rebuild"
    else
        extra_args=""
    fi
    
    if ./"$test_script" --ssl-backend 1 $extra_args > mbedtls_test_output.log 2>&1; then
        results["mbedtls"]="PASSED"
        print_success "mbed-TLS backend tests completed successfully"
    else
        results["mbedtls"]="FAILED"
        print_error "mbed-TLS backend tests failed"
        errors["mbedtls"]="Check mbedtls_test_output.log for details"
    fi
    
    end_time=$(date +%s)
    test_counts["mbedtls_time"]=$((end_time - start_time))
    
    # Extract test statistics if available
    if grep -q "PASSED TESTS" mbedtls_test_output.log; then
        passed_count=$(grep -o "PASSED TESTS ([0-9]*)" mbedtls_test_output.log | grep -o "[0-9]*" || echo "N/A")
        test_counts["mbedtls_passed"]=$passed_count
    fi
    
    echo ""
fi

# Test OpenSSL backend
if [ "$SKIP_OPENSSL" = false ]; then
    print_header "Testing OpenSSL Backend (Backend 2)"
    
    start_time=$(date +%s)
    
    if ./"$test_script" --ssl-backend 2 --rebuild > openssl_test_output.log 2>&1; then
        results["openssl"]="PASSED"
        print_success "OpenSSL backend tests completed successfully"
    else
        results["openssl"]="FAILED"
        print_error "OpenSSL backend tests failed"
        errors["openssl"]="Check openssl_test_output.log for details"
    fi
    
    end_time=$(date +%s)
    test_counts["openssl_time"]=$((end_time - start_time))
    
    # Extract test statistics if available
    if grep -q "PASSED TESTS" openssl_test_output.log; then
        passed_count=$(grep -o "PASSED TESTS ([0-9]*)" openssl_test_output.log | grep -o "[0-9]*" || echo "N/A")
        test_counts["openssl_passed"]=$passed_count
    fi
    
    echo ""
fi

print_header "COMPARISON RESULTS"

echo -e "${CYAN}📊 Backend Comparison Summary${NC}"
echo "================================="

if [ "$SKIP_MBEDTLS" = false ]; then
    echo -e "🔐 mbed-TLS Backend (Backend 1):"
    echo -e "   Status: ${results["mbedtls"]}"
    echo -e "   Runtime: ${test_counts["mbedtls_time"]}s"
    if [ -n "${test_counts["mbedtls_passed"]}" ]; then
        echo -e "   Passed Tests: ${test_counts["mbedtls_passed"]}"
    fi
    if [ -n "${errors["mbedtls"]}" ]; then
        echo -e "   Error: ${errors["mbedtls"]}"
    fi
    echo ""
fi

if [ "$SKIP_OPENSSL" = false ]; then
    echo -e "🔒 OpenSSL Backend (Backend 2):"
    echo -e "   Status: ${results["openssl"]}"
    echo -e "   Runtime: ${test_counts["openssl_time"]}s"
    if [ -n "${test_counts["openssl_passed"]}" ]; then
        echo -e "   Passed Tests: ${test_counts["openssl_passed"]}"
    fi
    if [ -n "${errors["openssl"]}" ]; then
        echo -e "   Error: ${errors["openssl"]}"
    fi
    echo ""
fi

# Performance comparison
if [ "$SKIP_MBEDTLS" = false ] && [ "$SKIP_OPENSSL" = false ]; then
    print_comparison "Performance Analysis"
    
    mbedtls_time=${test_counts["mbedtls_time"]}
    openssl_time=${test_counts["openssl_time"]}
    
    if [ $mbedtls_time -lt $openssl_time ]; then
        diff=$((openssl_time - mbedtls_time))
        echo "⚡ mbed-TLS was faster by ${diff}s"
    elif [ $openssl_time -lt $mbedtls_time ]; then
        diff=$((mbedtls_time - openssl_time))
        echo "⚡ OpenSSL was faster by ${diff}s"
    else
        echo "🤝 Both backends took the same time"
    fi
    echo ""
fi

# Results analysis
print_comparison "Results Analysis"

both_passed=false
if [ "$SKIP_MBEDTLS" = false ] && [ "$SKIP_OPENSSL" = false ]; then
    if [ "${results["mbedtls"]}" = "PASSED" ] && [ "${results["openssl"]}" = "PASSED" ]; then
        both_passed=true
        print_success "✅ Both SSL backends passed all tests successfully!"
        echo "   This indicates good SSL platform abstraction implementation."
    elif [ "${results["mbedtls"]}" = "PASSED" ] && [ "${results["openssl"]}" = "FAILED" ]; then
        print_warning "⚠️  mbed-TLS passed but OpenSSL failed"
        echo "   This may indicate OpenSSL-specific configuration issues."
    elif [ "${results["mbedtls"]}" = "FAILED" ] && [ "${results["openssl"]}" = "PASSED" ]; then
        print_warning "⚠️  OpenSSL passed but mbed-TLS failed"
        echo "   This may indicate mbed-TLS-specific configuration issues."
    else
        print_error "❌ Both backends failed"
        echo "   This indicates systemic issues that need investigation."
    fi
else
    # Single backend test
    if [ "$SKIP_OPENSSL" = true ] && [ "${results["mbedtls"]}" = "PASSED" ]; then
        print_success "✅ mbed-TLS backend tests passed successfully!"
    elif [ "$SKIP_MBEDTLS" = true ] && [ "${results["openssl"]}" = "PASSED" ]; then
        print_success "✅ OpenSSL backend tests passed successfully!"
    else
        print_error "❌ Tests failed for the selected backend"
    fi
fi

print_header "LOG FILES"

echo "📝 Detailed logs available:"
if [ "$SKIP_MBEDTLS" = false ]; then
    echo "   - mbed-TLS: mbedtls_test_output.log"
fi
if [ "$SKIP_OPENSSL" = false ]; then
    echo "   - OpenSSL: openssl_test_output.log"
fi

echo ""
echo "💡 Use 'cat <logfile>' to view detailed test output"

# Exit with appropriate code
if [ "$both_passed" = true ] || ([ "$SKIP_MBEDTLS" = true ] && [ "${results["openssl"]}" = "PASSED" ]) || ([ "$SKIP_OPENSSL" = true ] && [ "${results["mbedtls"]}" = "PASSED" ]); then
    exit 0
else
    exit 1
fi 