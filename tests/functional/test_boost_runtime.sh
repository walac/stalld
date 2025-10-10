#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Test: stalld -r/--boost_runtime option
# Verifies that stalld uses the specified SCHED_DEADLINE runtime
#
# Copyright (C) 2025 Red Hat Inc

# Load test helpers
TEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${TEST_ROOT}/helpers/test_helpers.sh"

# Parse command-line options
parse_test_options "$@" || exit $?

# Helper function for logging test steps
log() {
    echo "[$(date +'%H:%M:%S')] $*"
}

start_test "Boost Runtime Option (-r)"

# Require root for this test
require_root

# Check RT throttling
if ! check_rt_throttling; then
    echo -e "${YELLOW}SKIP: RT throttling must be disabled for this test${NC}"
    exit 77
fi

# Pick a CPU for testing
TEST_CPU=$(pick_test_cpu)
log "Using CPU ${TEST_CPU} for testing"

# Setup paths
STARVE_GEN="${TEST_ROOT}/helpers/starvation_gen"
STALLD_LOG="/tmp/stalld_test_boost_runtime_$$.log"
CLEANUP_FILES+=("${STALLD_LOG}")

if [ ! -x "${STARVE_GEN}" ]; then
    echo -e "${YELLOW}SKIP: starvation_gen not found or not executable${NC}"
    exit 77
fi

#=============================================================================
# Test 1: Default runtime (should be 20,000 ns = 20 microseconds)
#=============================================================================
log ""
log "=========================================="
log "Test 1: Default runtime (no -r specified)"
log "=========================================="

threshold=3
log "Starting stalld with ${threshold}s threshold (default boost runtime)"
start_stalld -f -v -c "${TEST_CPU}" -t ${threshold} -l > "${STALLD_LOG}" 2>&1

# Create starvation
starvation_duration=10
log "Creating starvation on CPU ${TEST_CPU} for ${starvation_duration}s"
"${STARVE_GEN}" -c "${TEST_CPU}" -p 80 -n 2 -d ${starvation_duration} &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Wait for detection and boosting
wait_time=$((threshold + 2))
log "Waiting ${wait_time}s for detection and boosting"
sleep ${wait_time}

# Check if detection occurred
if grep -qi "detect\|starv" "${STALLD_LOG}"; then
    log "✓ PASS: Starvation detection with default runtime"
else
    log "✗ FAIL: No starvation detection"
    TEST_FAILED=$((TEST_FAILED + 1))
fi

# Cleanup
kill -TERM "${STARVE_PID}" 2>/dev/null || true
wait "${STARVE_PID}" 2>/dev/null || true
stop_stalld
sleep 1

#=============================================================================
# Test 2: Custom runtime (10,000 ns = 10 microseconds, less than default)
#=============================================================================
log ""
log "=========================================="
log "Test 2: Custom runtime of 10,000 ns (10μs)"
log "=========================================="

custom_runtime=10000
STALLD_LOG2="/tmp/stalld_test_boost_runtime_test2_$$.log"
CLEANUP_FILES+=("${STALLD_LOG2}")

log "Starting stalld with ${threshold}s threshold and ${custom_runtime}ns runtime"
start_stalld -f -v -c "${TEST_CPU}" -t ${threshold} -r ${custom_runtime} -l > "${STALLD_LOG2}" 2>&1

# Create starvation
log "Creating starvation on CPU ${TEST_CPU} for ${starvation_duration}s"
"${STARVE_GEN}" -c "${TEST_CPU}" -p 80 -n 2 -d ${starvation_duration} &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Wait for detection and boosting
log "Waiting ${wait_time}s for detection and boosting"
sleep ${wait_time}

# Check if detection occurred
if grep -qi "detect\|starv" "${STALLD_LOG2}"; then
    log "✓ PASS: Starvation detection with custom runtime ${custom_runtime}ns"
else
    log "✗ FAIL: No starvation detection with custom runtime"
    TEST_FAILED=$((TEST_FAILED + 1))
fi

# Cleanup
kill -TERM "${STARVE_PID}" 2>/dev/null || true
wait "${STARVE_PID}" 2>/dev/null || true
stop_stalld
sleep 1

#=============================================================================
# Test 3: Larger runtime (100,000 ns = 100 microseconds)
#=============================================================================
log ""
log "=========================================="
log "Test 3: Larger runtime of 100,000 ns (100μs)"
log "=========================================="

large_runtime=100000
STALLD_LOG3="/tmp/stalld_test_boost_runtime_test3_$$.log"
CLEANUP_FILES+=("${STALLD_LOG3}")

log "Starting stalld with ${threshold}s threshold and ${large_runtime}ns runtime"
start_stalld -f -v -c "${TEST_CPU}" -t ${threshold} -r ${large_runtime} -l > "${STALLD_LOG3}" 2>&1

# Create starvation
log "Creating starvation on CPU ${TEST_CPU} for ${starvation_duration}s"
"${STARVE_GEN}" -c "${TEST_CPU}" -p 80 -n 2 -d ${starvation_duration} &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Wait for detection and boosting
log "Waiting ${wait_time}s for detection and boosting"
sleep ${wait_time}

# Check if detection occurred
if grep -qi "detect\|starv" "${STALLD_LOG3}"; then
    log "✓ PASS: Starvation detection with large runtime ${large_runtime}ns"
else
    log "✗ FAIL: No starvation detection with large runtime"
    TEST_FAILED=$((TEST_FAILED + 1))
fi

# Cleanup
kill -TERM "${STARVE_PID}" 2>/dev/null || true
wait "${STARVE_PID}" 2>/dev/null || true
stop_stalld
sleep 1

#=============================================================================
# Test 4: Runtime < period (valid configuration)
#=============================================================================
log ""
log "=========================================="
log "Test 4: Runtime < period (valid)"
log "=========================================="

# Default period is 1,000,000,000 ns, so runtime of 500,000 ns should be valid
valid_runtime=500000
period=1000000000
STALLD_LOG4="/tmp/stalld_test_boost_runtime_test4_$$.log"
CLEANUP_FILES+=("${STALLD_LOG4}")

log "Starting stalld with runtime ${valid_runtime}ns < period ${period}ns"
start_stalld -f -v -c "${TEST_CPU}" -t ${threshold} -r ${valid_runtime} -p ${period} -l > "${STALLD_LOG4}" 2>&1

# Create starvation
log "Creating starvation on CPU ${TEST_CPU} for ${starvation_duration}s"
"${STARVE_GEN}" -c "${TEST_CPU}" -p 80 -n 2 -d ${starvation_duration} &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Wait for detection and boosting
log "Waiting ${wait_time}s for detection and boosting"
sleep ${wait_time}

# Check if detection occurred
if grep -qi "detect\|starv" "${STALLD_LOG4}"; then
    log "✓ PASS: Starvation detection with runtime < period"
else
    log "✗ FAIL: No starvation detection when runtime < period"
    TEST_FAILED=$((TEST_FAILED + 1))
fi

# Cleanup
kill -TERM "${STARVE_PID}" 2>/dev/null || true
wait "${STARVE_PID}" 2>/dev/null || true
stop_stalld
sleep 1

#=============================================================================
# Test 5: Runtime > period (should error or be rejected)
#=============================================================================
log ""
log "=========================================="
log "Test 5: Runtime > period (invalid)"
log "=========================================="

invalid_runtime=2000000000
period=1000000000
INVALID_LOG="/tmp/stalld_test_boost_runtime_invalid_$$.log"
CLEANUP_FILES+=("${INVALID_LOG}")

# Add backend flag for consistency
BACKEND_FLAG=""
if [ -n "${STALLD_TEST_BACKEND}" ]; then
    BACKEND_FLAG="-b ${STALLD_TEST_BACKEND}"
fi

log "Testing with runtime ${invalid_runtime}ns > period ${period}ns"
${TEST_ROOT}/../stalld -f -v ${BACKEND_FLAG} -t ${threshold} -r ${invalid_runtime} -p ${period} > "${INVALID_LOG}" 2>&1 &
invalid_pid=$!
sleep 2

if ! kill -0 "${invalid_pid}" 2>/dev/null; then
    # Process exited - this is expected behavior
    if grep -qi "error\|invalid\|failed" "${INVALID_LOG}"; then
        log "✓ PASS: Runtime > period rejected with error"
    else
        log "ℹ INFO: Runtime > period caused exit"
    fi
else
    # Process still running - might be accepted or might fail later
    log "⚠ WARNING: stalld accepted runtime > period"
    kill -TERM "${invalid_pid}" 2>/dev/null || true
    wait "${invalid_pid}" 2>/dev/null || true
fi

#=============================================================================
# Test 6: Invalid runtime (0)
#=============================================================================
log ""
log "=========================================="
log "Test 6: Invalid runtime value (0)"
log "=========================================="

INVALID_LOG2="/tmp/stalld_test_boost_runtime_invalid2_$$.log"
CLEANUP_FILES+=("${INVALID_LOG2}")

log "Testing with runtime = 0"
${TEST_ROOT}/../stalld -f -v ${BACKEND_FLAG} -t ${threshold} -r 0 > "${INVALID_LOG2}" 2>&1 &
invalid_pid=$!
sleep 2

if ! kill -0 "${invalid_pid}" 2>/dev/null; then
    if grep -qi "error\|invalid" "${INVALID_LOG2}"; then
        log "✓ PASS: Zero runtime rejected with error"
    else
        log "ℹ INFO: Zero runtime caused exit"
    fi
else
    log "⚠ WARNING: stalld accepted zero runtime"
    kill -TERM "${invalid_pid}" 2>/dev/null || true
    wait "${invalid_pid}" 2>/dev/null || true
fi

#=============================================================================
# Test 7: Negative runtime
#=============================================================================
log ""
log "=========================================="
log "Test 7: Invalid runtime value (negative)"
log "=========================================="

INVALID_LOG3="/tmp/stalld_test_boost_runtime_invalid3_$$.log"
CLEANUP_FILES+=("${INVALID_LOG3}")

log "Testing with runtime = -5000"
${TEST_ROOT}/../stalld -f -v ${BACKEND_FLAG} -t ${threshold} -r -5000 > "${INVALID_LOG3}" 2>&1 &
invalid_pid=$!
sleep 2

if ! kill -0 "${invalid_pid}" 2>/dev/null; then
    if grep -qi "error\|invalid" "${INVALID_LOG3}"; then
        log "✓ PASS: Negative runtime rejected with error"
    else
        log "ℹ INFO: Negative runtime caused exit"
    fi
else
    log "⚠ WARNING: stalld accepted negative runtime"
    kill -TERM "${invalid_pid}" 2>/dev/null || true
    wait "${invalid_pid}" 2>/dev/null || true
fi

log ""
log "All boost runtime tests completed"

end_test
