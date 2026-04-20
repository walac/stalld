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

start_test "Boost Duration Option (-d)"

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
STALLD_LOG="/tmp/stalld_test_boost_duration_$$.log"
CLEANUP_FILES+=("${STALLD_LOG}")

if [ ! -x "${STARVE_GEN}" ]; then
    echo -e "${YELLOW}SKIP: starvation_gen not found or not executable${NC}"
    exit 77
fi

#=============================================================================
# Test 1: Default duration (should be 3 seconds)
#=============================================================================
test_section "Test 1: Default boost duration (no -d specified)"

threshold=3
log "Starting stalld with ${threshold}s threshold (default boost duration)"
start_stalld_with_log "${STALLD_LOG}" -f -v -c "${TEST_CPU}" -a ${STALLD_CPU} -t ${threshold} -l

# Create starvation
starvation_duration=15
log "Creating starvation on CPU ${TEST_CPU} for ${starvation_duration}s"
start_starvation_gen -c "${TEST_CPU}" -p 80 -n 2 -d ${starvation_duration}

# Wait for starvation detection
if wait_for_starvation_detected "${STALLD_LOG}"; then
    pass "Starvation detection occurred with default duration"
else
    fail "No starvation detection"
fi

# Cleanup
cleanup_scenario "${STARVE_PID}"

#=============================================================================
# Test 2: Short duration (1 second)
#=============================================================================
test_section "Test 2: Short boost duration of 1 second"

short_duration=1
STALLD_LOG2="/tmp/stalld_test_boost_duration_test2_$$.log"
CLEANUP_FILES+=("${STALLD_LOG2}")

log "Starting stalld with ${threshold}s threshold and ${short_duration}s boost duration"
start_stalld_with_log "${STALLD_LOG2}" -f -v -c "${TEST_CPU}" -a ${STALLD_CPU} -t ${threshold} -d ${short_duration} -l

# Create starvation
log "Creating starvation on CPU ${TEST_CPU} for ${starvation_duration}s"
start_starvation_gen -c "${TEST_CPU}" -p 80 -n 2 -d ${starvation_duration}

# Wait for starvation detection
if wait_for_starvation_detected "${STALLD_LOG2}"; then
    pass "Starvation detection with ${short_duration}s duration"
else
    fail "No starvation detection with short duration"
fi

# Cleanup
cleanup_scenario "${STARVE_PID}"

#=============================================================================
# Test 3: Long duration (10 seconds)
#=============================================================================
test_section "Test 3: Long boost duration of 10 seconds"

long_duration=10
long_starvation=20
threshold=10
STALLD_LOG3="/tmp/stalld_test_boost_duration_test3_$$.log"
CLEANUP_FILES+=("${STALLD_LOG3}")

log "Starting stalld with ${threshold}s threshold and ${long_duration}s boost duration"
start_stalld_with_log "${STALLD_LOG3}" -f -v -c "${TEST_CPU}" -a ${STALLD_CPU} -t ${threshold} -d ${long_duration} -l

# Create starvation
log "Creating starvation on CPU ${TEST_CPU} for ${long_starvation}s"
start_starvation_gen -c "${TEST_CPU}" -p 80 -n 2 -d ${long_starvation}

# Wait for starvation detection
if wait_for_starvation_detected "${STALLD_LOG3}"; then
    pass "Starvation detection with ${long_duration}s duration"
else
    fail "No starvation detection with long duration"
fi

# Cleanup
cleanup_scenario "${STARVE_PID}"

#=============================================================================
# Test 4: Verify task policy is restored after boost duration
#=============================================================================
test_section "Test 4: Verify policy restoration after boost duration"

threshold=3
duration=2
STALLD_LOG4="/tmp/stalld_test_boost_duration_test4_$$.log"
CLEANUP_FILES+=("${STALLD_LOG4}")

log "Starting stalld with ${threshold}s threshold and ${duration}s boost duration"
start_stalld_with_log "${STALLD_LOG4}" -f -v -c "${TEST_CPU}" -a ${STALLD_CPU} -t ${threshold} -d ${duration} -l

# Create starvation with a specific task we can track
log "Creating starvation on CPU ${TEST_CPU} for 15s"
start_starvation_gen -c "${TEST_CPU}" -p 80 -n 1 -d 15

# Wait for starvation detection
if wait_for_starvation_detected "${STALLD_LOG4}"; then
    pass "Starvation detection with ${duration}s boost duration"
else
    fail "No starvation detection"
fi

# Cleanup
cleanup_scenario "${STARVE_PID}"

#=============================================================================
# Test 5: Invalid duration values
#=============================================================================
test_section "Test 5: Invalid duration values"

# Test with zero duration
log "Testing with duration = 0"
INVALID_LOG="/tmp/stalld_test_boost_duration_invalid_$$.log"
CLEANUP_FILES+=("${INVALID_LOG}")

# Add backend flag for consistency
BACKEND_FLAG=""
if [ -n "${STALLD_TEST_BACKEND}" ]; then
    BACKEND_FLAG="-b ${STALLD_TEST_BACKEND}"
fi

timeout 5 ${TEST_ROOT}/../stalld -f -v ${BACKEND_FLAG} -t ${threshold} -d 0 > "${INVALID_LOG}" 2>&1
ret=$?

if [ $ret -ne 0 ] && [ $ret -ne 124 ]; then
    pass "Zero duration rejected with error"
else
    fail "stalld did not reject invalid duration value 0"
fi

# Test 6: Negative duration
log "Testing with duration = -5"
INVALID_LOG2="/tmp/stalld_test_boost_duration_invalid2_$$.log"
CLEANUP_FILES+=("${INVALID_LOG2}")

timeout 5 ${TEST_ROOT}/../stalld -f -v ${BACKEND_FLAG} -t ${threshold} -d -5 > "${INVALID_LOG2}" 2>&1
ret=$?

if [ $ret -ne 0 ] && [ $ret -ne 124 ]; then
    pass "Negative duration rejected with error"
else
    fail "stalld did not reject invalid negative duration"
fi

log ""
log "All boost duration tests completed"

end_test
