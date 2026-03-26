#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Test: stalld -t/--starving_threshold option
# Verifies that stalld detects starvation after the configured threshold
#
# IMPORTANT: stalld must run on a different CPU than the test CPU to avoid
# interference with the starvation scenario. This test uses CPU affinity (-a)
# to ensure stalld runs on a separate CPU.
#
# Copyright (C) 2025 Red Hat Inc

# Load test helpers
TEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${TEST_ROOT}/helpers/test_helpers.sh"

# Parse command-line options
parse_test_options "$@" || exit $?

start_test "Starvation Threshold Option (-t)"

# Setup test environment
setup_test_environment

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

# Pick a different CPU for stalld to run on (avoid interference)
STALLD_CPU=0
if [ ${TEST_CPU} -eq 0 ]; then
    STALLD_CPU=1
fi
log "Stalld will run on CPU ${STALLD_CPU}"

# Setup paths
STARVE_GEN="${TEST_ROOT}/helpers/starvation_gen"
STALLD_LOG="/tmp/stalld_test_threshold_$$.log"
CLEANUP_FILES+=("${STALLD_LOG}")

if [ ! -x "${STARVE_GEN}" ]; then
    echo -e "${YELLOW}SKIP: starvation_gen not found or not executable${NC}"
    exit 77
fi

#=============================================================================
# Test 1: Custom threshold (5 seconds)
#=============================================================================
log ""
log "=========================================="
log "Test 1: Custom threshold of 5 seconds"
log "=========================================="

threshold=5

# Create starvation BEFORE starting stalld (avoid detecting kworker tasks)
starvation_duration=10
log "Creating starvation on CPU ${TEST_CPU} for ${starvation_duration}s"
start_starvation_gen -c "${TEST_CPU}" -p 80 -n 2 -d ${starvation_duration}

log "Starting stalld with ${threshold}s threshold"
# Use -i to ignore kernel workers that may starve before our test tasks
start_stalld -f -v -N -M -g 1 -i "ksoftirqd,kworker" -c "${TEST_CPU}" -a "${STALLD_CPU}" -t ${threshold} > "${STALLD_LOG}" 2>&1

# Wait for threshold + granularity + buffer time
# With -g 1, stalld checks every 1 second. In worst case, it checks just before
# threshold is reached, then waits another granularity period.
# So we need: threshold + granularity + buffer for processing
wait_time=$((threshold + 1 + 3))
log "Waiting ${wait_time}s for detection (threshold: ${threshold}s, granularity: 1s)"
sleep ${wait_time}

# Check if starvation was detected - specifically look for starvation_gen tasks
if grep -qE "starvation_gen.*starved on CPU ${TEST_CPU}|starved on CPU ${TEST_CPU}.*starvation_gen" "${STALLD_LOG}"; then
    log "✓ PASS: Starvation detected after ${threshold}s threshold"
else
    log "✗ FAIL: Starvation not detected after ${threshold}s threshold"
    log "Log contents:"
    cat "${STALLD_LOG}"
    TEST_FAILED=$((TEST_FAILED + 1))
fi

# Cleanup
kill -TERM "${STARVE_PID}" 2>/dev/null
wait "${STARVE_PID}" 2>/dev/null || true
stop_stalld

#=============================================================================
# Test 2: Verify no detection before threshold
#=============================================================================
log ""
log "=========================================="
log "Test 2: No detection before threshold"
log "=========================================="

threshold=10
STALLD_LOG2="/tmp/stalld_test_threshold_test2_$$.log"
CLEANUP_FILES+=("${STALLD_LOG2}")

# Create starvation BEFORE starting stalld (avoid detecting kworker tasks)
# Create starvation that will last 6 seconds (less than threshold)
starvation_duration=6
log "Creating short starvation (${starvation_duration}s) with threshold of ${threshold}s"
start_starvation_gen -c "${TEST_CPU}" -p 80 -n 2 -d ${starvation_duration}

log "Starting stalld with ${threshold}s threshold"
start_stalld -f -v -N -M -g 1 -c "${TEST_CPU}" -a "${STALLD_CPU}" -t ${threshold} > "${STALLD_LOG2}" 2>&1

# Wait for starvation duration + small buffer
sleep 8

# Wait for starvation generator to fully complete
wait "${STARVE_PID}" 2>/dev/null || true

# Give stalld time to process and log (if it were to detect)
sleep 2

# Check that starvation_gen was NOT detected (duration less than threshold)
if ! grep -qE "starvation_gen.*starved on CPU ${TEST_CPU}|starved on CPU ${TEST_CPU}.*starvation_gen" "${STALLD_LOG2}"; then
    log "✓ PASS: No starvation detected for duration less than threshold"
else
    log "✗ FAIL: Starvation detected before threshold"
    log "Found starvation_gen task in logs:"
    grep -E "starvation_gen.*starved on CPU|starved on CPU.*starvation_gen" "${STALLD_LOG2}"
    TEST_FAILED=$((TEST_FAILED + 1))
fi

# Cleanup
kill -TERM "${STARVE_PID}" 2>/dev/null
wait "${STARVE_PID}" 2>/dev/null || true
stop_stalld

#=============================================================================
# Test 3: Shorter threshold (3 seconds)
#=============================================================================
log ""
log "=========================================="
log "Test 3: Shorter threshold (3 seconds)"
log "=========================================="

threshold=3
STALLD_LOG3="/tmp/stalld_test_threshold_test3_$$.log"
CLEANUP_FILES+=("${STALLD_LOG3}")

# Create starvation BEFORE starting stalld (avoid detecting kworker tasks)
# Create starvation for 8 seconds
starvation_duration=8
log "Creating starvation for ${starvation_duration}s with threshold of ${threshold}s"
start_starvation_gen -c "${TEST_CPU}" -p 80 -n 2 -d ${starvation_duration}

log "Starting stalld with ${threshold}s threshold"
# Use -i to ignore kernel workers that may starve before our test tasks
start_stalld -f -v -N -M -g 1 -i "ksoftirqd,kworker" -c "${TEST_CPU}" -a "${STALLD_CPU}" -t ${threshold} > "${STALLD_LOG3}" 2>&1

# Wait for threshold + granularity + buffer
wait_time=$((threshold + 1 + 3))
log "Waiting ${wait_time}s for detection (threshold: ${threshold}s, granularity: 1s)"
sleep ${wait_time}

# Check if starvation_gen was detected
if grep -qE "starvation_gen.*starved on CPU ${TEST_CPU}|starved on CPU ${TEST_CPU}.*starvation_gen" "${STALLD_LOG3}"; then
    log "✓ PASS: Starvation detected with ${threshold}s threshold"
else
    log "✗ FAIL: Starvation not detected with ${threshold}s threshold"
    log "Log contents:"
    cat "${STALLD_LOG3}"
    TEST_FAILED=$((TEST_FAILED + 1))
fi

# Cleanup
kill -TERM "${STARVE_PID}" 2>/dev/null
wait "${STARVE_PID}" 2>/dev/null || true
stop_stalld

#=============================================================================
# Test 4: Invalid threshold values
#=============================================================================
log ""
log "=========================================="
log "Test 4: Invalid threshold values"
log "=========================================="

# Test with zero threshold
log "Testing with threshold = 0"
INVALID_LOG="/tmp/stalld_test_threshold_invalid_$$.log"
CLEANUP_FILES+=("${INVALID_LOG}")

${TEST_ROOT}/../stalld -f -v -t 0 > "${INVALID_LOG}" 2>&1 &
invalid_pid=$!
sleep 2

if ! kill -0 "${invalid_pid}" 2>/dev/null; then
    if grep -qi "error\|invalid" "${INVALID_LOG}"; then
        log "✓ PASS: Zero threshold rejected with error"
    else
        log "ℹ INFO: Zero threshold caused exit (may have been rejected)"
    fi
else
    log "⚠ WARNING: stalld accepted zero threshold"
    kill -TERM "${invalid_pid}" 2>/dev/null
    wait "${invalid_pid}" 2>/dev/null || true
fi

# Test with negative threshold
log "Testing with threshold = -5"
INVALID_LOG2="/tmp/stalld_test_threshold_invalid2_$$.log"
CLEANUP_FILES+=("${INVALID_LOG2}")

${TEST_ROOT}/../stalld -f -v -t -5 > "${INVALID_LOG2}" 2>&1 &
invalid_pid=$!
sleep 2

if ! kill -0 "${invalid_pid}" 2>/dev/null; then
    if grep -qi "error\|invalid" "${INVALID_LOG2}"; then
        log "✓ PASS: Negative threshold rejected with error"
    else
        log "ℹ INFO: Negative threshold caused exit"
    fi
else
    log "⚠ WARNING: stalld accepted negative threshold"
    kill -TERM "${invalid_pid}" 2>/dev/null
    wait "${invalid_pid}" 2>/dev/null || true
fi

log ""
log "All starvation threshold tests completed"

end_test
