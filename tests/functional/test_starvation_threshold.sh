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
start_stalld_with_log "${STALLD_LOG}" -f -v -N -M -g 1 -i "ksoftirqd,kworker" -c "${TEST_CPU}" -a "${STALLD_CPU}" -t ${threshold}

# Wait for starvation detection
log "Waiting for detection (threshold: ${threshold}s)"

# Check if starvation was detected - specifically look for starvation_gen tasks
if wait_for_starvation_detected "${STALLD_LOG}"; then
    pass "Starvation detected after ${threshold}s threshold"
else
    fail "Starvation not detected after ${threshold}s threshold"
    log "Log contents:"
    cat "${STALLD_LOG}"
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
start_stalld_with_log "${STALLD_LOG2}" -f -v -N -M -g 1 -c "${TEST_CPU}" -a "${STALLD_CPU}" -t ${threshold}

# Wait for starvation duration + small buffer
sleep 8

# Wait for starvation generator to fully complete
wait "${STARVE_PID}" 2>/dev/null || true

# Give stalld time to process and log (if it were to detect)
sleep 2

# Check that starvation_gen was NOT detected (duration less than threshold)
if ! grep -qE "starvation_gen.*starved on CPU ${TEST_CPU}|starved on CPU ${TEST_CPU}.*starvation_gen" "${STALLD_LOG2}"; then
    pass "No starvation detected for duration less than threshold"
else
    fail "Starvation detected before threshold"
    log "Found starvation_gen task in logs:"
    grep -E "starvation_gen.*starved on CPU|starved on CPU.*starvation_gen" "${STALLD_LOG2}"
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
start_stalld_with_log "${STALLD_LOG3}" -f -v -N -M -g 1 -i "ksoftirqd,kworker" -c "${TEST_CPU}" -a "${STALLD_CPU}" -t ${threshold}

# Wait for starvation detection
log "Waiting for detection (threshold: ${threshold}s)"

# Check if starvation_gen was detected
if wait_for_starvation_detected "${STALLD_LOG3}"; then
    pass "Starvation detected with ${threshold}s threshold"
else
    fail "Starvation not detected with ${threshold}s threshold"
    log "Log contents:"
    cat "${STALLD_LOG3}"
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

timeout 5 ${TEST_ROOT}/../stalld -f -v -t 0 > "${INVALID_LOG}" 2>&1
ret=$?

if [ $ret -ne 0 ] && [ $ret -ne 124 ]; then
    pass "Zero threshold rejected with error"
else
    fail "stalld did not reject invalid threshold value 0"
fi

# Test with negative threshold
log "Testing with threshold = -5"
INVALID_LOG2="/tmp/stalld_test_threshold_invalid2_$$.log"
CLEANUP_FILES+=("${INVALID_LOG2}")

timeout 5 ${TEST_ROOT}/../stalld -f -v -t -5 > "${INVALID_LOG2}" 2>&1
ret=$?

if [ $ret -ne 0 ] && [ $ret -ne 124 ]; then
    pass "Negative threshold rejected with error"
else
    fail "stalld did not reject invalid negative threshold"
fi

log ""
log "All starvation threshold tests completed"

end_test
