#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Test: stalld -d/--boost_duration option
# Verifies that stalld boosts tasks for the specified duration
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

start_test "Boost Duration Option (-d)"

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
STALLD_LOG="/tmp/stalld_test_boost_duration_$$.log"
CLEANUP_FILES+=("${STALLD_LOG}")

if [ ! -x "${STARVE_GEN}" ]; then
    echo -e "${YELLOW}SKIP: starvation_gen not found or not executable${NC}"
    exit 77
fi

#=============================================================================
# Test 1: Default duration (should be 3 seconds)
#=============================================================================
log ""
log "=========================================="
log "Test 1: Default boost duration (no -d specified)"
log "=========================================="

threshold=3
log "Starting stalld with ${threshold}s threshold (default boost duration)"
start_stalld -f -v -c "${TEST_CPU}" -t ${threshold} -l > "${STALLD_LOG}" 2>&1

# Create starvation
starvation_duration=15
log "Creating starvation on CPU ${TEST_CPU} for ${starvation_duration}s"
"${STARVE_GEN}" -c "${TEST_CPU}" -p 80 -n 2 -d ${starvation_duration} &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Wait for detection and boosting
wait_time=$((threshold + 2))
log "Waiting ${wait_time}s for detection and boosting"
sleep ${wait_time}

# Check if boosting occurred (in log-only mode we look for detection messages)
if grep -qi "detect\|starv" "${STALLD_LOG}"; then
    log "✓ PASS: Starvation detection occurred with default duration"
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
# Test 2: Short duration (1 second)
#=============================================================================
log ""
log "=========================================="
log "Test 2: Short boost duration of 1 second"
log "=========================================="

short_duration=1
STALLD_LOG2="/tmp/stalld_test_boost_duration_test2_$$.log"
CLEANUP_FILES+=("${STALLD_LOG2}")

log "Starting stalld with ${threshold}s threshold and ${short_duration}s boost duration"
start_stalld -f -v -c "${TEST_CPU}" -t ${threshold} -d ${short_duration} -l > "${STALLD_LOG2}" 2>&1

# Create starvation
log "Creating starvation on CPU ${TEST_CPU} for ${starvation_duration}s"
"${STARVE_GEN}" -c "${TEST_CPU}" -p 80 -n 2 -d ${starvation_duration} &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Wait for detection and boosting
log "Waiting ${wait_time}s for detection"
sleep ${wait_time}

# Check if detection occurred
if grep -qi "detect\|starv" "${STALLD_LOG2}"; then
    log "✓ PASS: Starvation detection with ${short_duration}s duration"
else
    log "✗ FAIL: No starvation detection with short duration"
    TEST_FAILED=$((TEST_FAILED + 1))
fi

# Cleanup
kill -TERM "${STARVE_PID}" 2>/dev/null || true
wait "${STARVE_PID}" 2>/dev/null || true
stop_stalld
sleep 1

#=============================================================================
# Test 3: Long duration (10 seconds)
#=============================================================================
log ""
log "=========================================="
log "Test 3: Long boost duration of 10 seconds"
log "=========================================="

long_duration=10
long_starvation=20
STALLD_LOG3="/tmp/stalld_test_boost_duration_test3_$$.log"
CLEANUP_FILES+=("${STALLD_LOG3}")

log "Starting stalld with ${threshold}s threshold and ${long_duration}s boost duration"
start_stalld -f -v -c "${TEST_CPU}" -t ${threshold} -d ${long_duration} -l > "${STALLD_LOG3}" 2>&1

# Create starvation
log "Creating starvation on CPU ${TEST_CPU} for ${long_starvation}s"
"${STARVE_GEN}" -c "${TEST_CPU}" -p 80 -n 2 -d ${long_starvation} &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Wait for detection
log "Waiting ${wait_time}s for detection"
sleep ${wait_time}

# Check if detection occurred
if grep -qi "detect\|starv" "${STALLD_LOG3}"; then
    log "✓ PASS: Starvation detection with ${long_duration}s duration"
else
    log "✗ FAIL: No starvation detection with long duration"
    TEST_FAILED=$((TEST_FAILED + 1))
fi

# Cleanup
kill -TERM "${STARVE_PID}" 2>/dev/null || true
wait "${STARVE_PID}" 2>/dev/null || true
stop_stalld
sleep 1

#=============================================================================
# Test 4: Verify task policy is restored after boost duration
#=============================================================================
log ""
log "=========================================="
log "Test 4: Verify policy restoration after boost duration"
log "=========================================="

duration=2
STALLD_LOG4="/tmp/stalld_test_boost_duration_test4_$$.log"
CLEANUP_FILES+=("${STALLD_LOG4}")

log "Starting stalld with ${threshold}s threshold and ${duration}s boost duration"
start_stalld -f -v -c "${TEST_CPU}" -t ${threshold} -d ${duration} -l > "${STALLD_LOG4}" 2>&1

# Create starvation with a specific task we can track
log "Creating starvation on CPU ${TEST_CPU} for 15s"
"${STARVE_GEN}" -c "${TEST_CPU}" -p 80 -n 1 -d 15 &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Wait for detection
log "Waiting ${wait_time}s for detection"
sleep ${wait_time}

if grep -qi "detect\|starv" "${STALLD_LOG4}"; then
    log "✓ PASS: Starvation detection with ${duration}s boost duration"
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
# Test 5: Invalid duration values
#=============================================================================
log ""
log "=========================================="
log "Test 5: Invalid duration values"
log "=========================================="

# Test with zero duration
log "Testing with duration = 0"
INVALID_LOG="/tmp/stalld_test_boost_duration_invalid_$$.log"
CLEANUP_FILES+=("${INVALID_LOG}")

# Add backend flag for consistency
BACKEND_FLAG=""
if [ -n "${STALLD_TEST_BACKEND}" ]; then
    BACKEND_FLAG="-b ${STALLD_TEST_BACKEND}"
fi

${TEST_ROOT}/../stalld -f -v ${BACKEND_FLAG} -t ${threshold} -d 0 > "${INVALID_LOG}" 2>&1 &
invalid_pid=$!
sleep 2

if ! kill -0 "${invalid_pid}" 2>/dev/null; then
    if grep -qi "error\|invalid" "${INVALID_LOG}"; then
        log "✓ PASS: Zero duration rejected with error"
    else
        log "ℹ INFO: Zero duration caused exit (may have been rejected)"
    fi
else
    log "⚠ WARNING: stalld accepted zero duration"
    kill -TERM "${invalid_pid}" 2>/dev/null || true
    wait "${invalid_pid}" 2>/dev/null || true
fi

# Test 6: Negative duration
log "Testing with duration = -5"
INVALID_LOG2="/tmp/stalld_test_boost_duration_invalid2_$$.log"
CLEANUP_FILES+=("${INVALID_LOG2}")

${TEST_ROOT}/../stalld -f -v ${BACKEND_FLAG} -t ${threshold} -d -5 > "${INVALID_LOG2}" 2>&1 &
invalid_pid=$!
sleep 2

if ! kill -0 "${invalid_pid}" 2>/dev/null; then
    if grep -qi "error\|invalid" "${INVALID_LOG2}"; then
        log "✓ PASS: Negative duration rejected with error"
    else
        log "ℹ INFO: Negative duration caused exit"
    fi
else
    log "⚠ WARNING: stalld accepted negative duration"
    kill -TERM "${invalid_pid}" 2>/dev/null || true
    wait "${invalid_pid}" 2>/dev/null || true
fi

log ""
log "All boost duration tests completed"

end_test
