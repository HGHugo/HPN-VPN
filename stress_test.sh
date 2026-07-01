#!/bin/bash
#
# Stress test script for HPN-PQ VPN
#
# Tests:
# 1. Memory leak detection (24h continuous operation)
# 2. High connection count (1000+ concurrent sessions)
# 3. Throughput validation (target: 2.5 Gbps)
# 4. CPU usage monitoring
#
# Usage: ./stress_test.sh [test_name]
#   test_name: memory|connections|throughput|cpu|all

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SERVER_BIN="./target/release/hpn-server"
SERVER_CONFIG="./config/server.example.toml"
LOG_DIR="./stress_test_logs"
RESULTS_FILE="${LOG_DIR}/results_$(date +%Y%m%d_%H%M%S).txt"

# Ensure log directory exists
mkdir -p "${LOG_DIR}"

echo "==================================="
echo "HPN-PQ VPN Stress Test Suite"
echo "==================================="
echo ""
echo "Results will be saved to: ${RESULTS_FILE}"
echo "" | tee -a "${RESULTS_FILE}"

# Function to print colored output
print_test() {
    echo -e "${YELLOW}[TEST]${NC} $1" | tee -a "${RESULTS_FILE}"
}

print_pass() {
    echo -e "${GREEN}[PASS]${NC} $1" | tee -a "${RESULTS_FILE}"
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1" | tee -a "${RESULTS_FILE}"
}

# Check if binaries exist
check_binaries() {
    print_test "Checking if binaries exist..."
    
    if [ ! -f "${SERVER_BIN}" ]; then
        print_fail "Server binary not found. Run: cargo build --release"
        exit 1
    fi
    
    print_pass "Binaries found"
}

# Test 1: Memory leak detection
test_memory_leaks() {
    print_test "Memory Leak Test (24h continuous operation)"
    print_test "WARNING: This test takes 24 hours. Press Ctrl+C to skip."
    
    echo "Starting server with memory monitoring..."
    
    # Start server in background
    "${SERVER_BIN}" run -c "${SERVER_CONFIG}" &
    SERVER_PID=$!
    
    # Monitor memory for 24 hours
    DURATION=86400  # 24 hours in seconds
    SAMPLE_INTERVAL=60  # Sample every minute
    SAMPLES=$((DURATION / SAMPLE_INTERVAL))
    
    echo "Monitoring memory for ${DURATION}s (${SAMPLES} samples)..." | tee -a "${RESULTS_FILE}"
    
    INITIAL_MEM=0
    FINAL_MEM=0
    
    for i in $(seq 1 ${SAMPLES}); do
        # Get memory usage (RSS in KB)
        MEM=$(ps -p ${SERVER_PID} -o rss= 2>/dev/null || echo "0")
        
        if [ "${MEM}" = "0" ]; then
            print_fail "Server process died unexpectedly"
            return 1
        fi
        
        if [ ${i} -eq 1 ]; then
            INITIAL_MEM=${MEM}
        fi
        FINAL_MEM=${MEM}
        
        # Print progress every hour
        if [ $((i % 60)) -eq 0 ]; then
            HOURS=$((i / 60))
            echo "  Hour ${HOURS}/24: Memory = ${MEM} KB" | tee -a "${RESULTS_FILE}"
        fi
        
        sleep ${SAMPLE_INTERVAL}
    done
    
    # Stop server
    kill ${SERVER_PID} 2>/dev/null || true
    wait ${SERVER_PID} 2>/dev/null || true
    
    # Calculate memory growth
    MEM_GROWTH=$((FINAL_MEM - INITIAL_MEM))
    MEM_GROWTH_PERCENT=$((MEM_GROWTH * 100 / INITIAL_MEM))
    
    echo "Initial memory: ${INITIAL_MEM} KB" | tee -a "${RESULTS_FILE}"
    echo "Final memory: ${FINAL_MEM} KB" | tee -a "${RESULTS_FILE}"
    echo "Memory growth: ${MEM_GROWTH} KB (${MEM_GROWTH_PERCENT}%)" | tee -a "${RESULTS_FILE}"
    
    # Pass if memory growth < 10%
    if [ ${MEM_GROWTH_PERCENT} -lt 10 ]; then
        print_pass "No significant memory leak detected (growth: ${MEM_GROWTH_PERCENT}%)"
    else
        print_fail "Possible memory leak (growth: ${MEM_GROWTH_PERCENT}%)"
    fi
}

# Test 2: High connection count
test_high_connections() {
    print_test "High Connection Count Test (1000+ concurrent sessions)"
    
    # This would require actual client implementations
    # For now, just document the test approach
    echo "Manual test required:" | tee -a "${RESULTS_FILE}"
    echo "1. Start server with max_sessions = 2000" | tee -a "${RESULTS_FILE}"
    echo "2. Connect 1000+ clients simultaneously" | tee -a "${RESULTS_FILE}"
    echo "3. Monitor CPU and memory usage" | tee -a "${RESULTS_FILE}"
    echo "4. Verify all sessions establish successfully" | tee -a "${RESULTS_FILE}"
    
    print_test "Skipped (requires client implementation)"
}

# Test 3: Throughput validation
test_throughput() {
    print_test "Throughput Test (target: 2.5 Gbps)"
    
    echo "Manual test required:" | tee -a "${RESULTS_FILE}"
    echo "1. Start server" | tee -a "${RESULTS_FILE}"
    echo "2. Connect client" | tee -a "${RESULTS_FILE}"
    echo "3. Run: iperf3 -c <client_tunnel_ip> -t 60 -P 8" | tee -a "${RESULTS_FILE}"
    echo "4. Verify throughput >= 2.5 Gbps with multiqueue enabled" | tee -a "${RESULTS_FILE}"
    
    print_test "Skipped (requires client+iperf3 setup)"
}

# Test 4: CPU usage monitoring
test_cpu_usage() {
    print_test "CPU Usage Test (under load)"
    
    echo "Manual test required:" | tee -a "${RESULTS_FILE}"
    echo "1. Start server with multiqueue enabled" | tee -a "${RESULTS_FILE}"
    echo "2. Generate traffic load" | tee -a "${RESULTS_FILE}"
    echo "3. Monitor with: top -p \$(pgrep hpn-server)" | tee -a "${RESULTS_FILE}"
    echo "4. Verify CPU usage scales with number of cores" | tee -a "${RESULTS_FILE}"
    echo "5. Verify CPU affinity is working (check with taskset -cp PID)" | tee -a "${RESULTS_FILE}"
    
    print_test "Skipped (requires traffic generation)"
}

# Test 5: Benchmark suite
test_benchmarks() {
    print_test "Running Criterion benchmarks..."
    
    cargo bench --package hpn-core 2>&1 | tee -a "${RESULTS_FILE}"
    
    print_pass "Benchmarks completed (see target/criterion for detailed results)"
}

# Main test runner
run_tests() {
    local test_type="${1:-all}"
    
    check_binaries
    
    case "${test_type}" in
        memory)
            test_memory_leaks
            ;;
        connections)
            test_high_connections
            ;;
        throughput)
            test_throughput
            ;;
        cpu)
            test_cpu_usage
            ;;
        bench)
            test_benchmarks
            ;;
        all)
            test_benchmarks
            echo ""
            echo "Note: Memory, connections, throughput, and CPU tests require manual setup."
            echo "Run individual tests with: $0 [memory|connections|throughput|cpu]"
            ;;
        *)
            echo "Usage: $0 [memory|connections|throughput|cpu|bench|all]"
            exit 1
            ;;
    esac
}

# Run tests
run_tests "${1:-all}"

echo ""
echo "==================================="
echo "Stress Test Complete"
echo "==================================="
echo "Results saved to: ${RESULTS_FILE}"
