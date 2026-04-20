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

start_test "Boost Runtime Option (-r)"

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
STALLD_LOG="/tmp/stalld_test_boost_runtime_$$.log"
CLEANUP_FILES+=("${STALLD_LOG}")

if [ ! -x "${STARVE_GEN}" ]; then
    echo -e "${YELLOW}SKIP: starvation_gen not found or not executable${NC}"
    exit 77
fi

#=============================================================================
# Test 1: Default runtime (should be 20,000 ns = 20 microseconds)
#=============================================================================
test_section "Test 1: Default runtime (no -r specified)"

threshold=3
log "Starting stalld with ${threshold}s threshold (default boost runtime)"
start_stalld_with_log "${STALLD_LOG}" -f -v -c "${TEST_CPU}" -a ${STALLD_CPU} -t ${threshold} -l

# Create starvation
starvation_duration=10
log "Creating starvation on CPU ${TEST_CPU} for ${starvation_duration}s"
start_starvation_gen -c "${TEST_CPU}" -p 80 -n 2 -d ${starvation_duration}

# Wait for detection and boosting
assert_starvation_detected "${STALLD_LOG}" "Starvation detection with default runtime"

# Cleanup
cleanup_scenario "${STARVE_PID}"

#=============================================================================
# Test 2: Custom runtime (10,000 ns = 10 microseconds, less than default)
#=============================================================================
test_section "Test 2: Custom runtime of 10,000 ns (10μs)"

custom_runtime=10000
STALLD_LOG2="/tmp/stalld_test_boost_runtime_test2_$$.log"
CLEANUP_FILES+=("${STALLD_LOG2}")

log "Starting stalld with ${threshold}s threshold and ${custom_runtime}ns runtime"
start_stalld_with_log "${STALLD_LOG2}" -f -v -c "${TEST_CPU}" -a ${STALLD_CPU} -t ${threshold} -r ${custom_runtime} -l

# Create starvation
log "Creating starvation on CPU ${TEST_CPU} for ${starvation_duration}s"
start_starvation_gen -c "${TEST_CPU}" -p 80 -n 2 -d ${starvation_duration}

# Wait for detection and boosting
assert_starvation_detected "${STALLD_LOG2}" "Starvation detection with custom runtime ${custom_runtime}ns"

# Cleanup
cleanup_scenario "${STARVE_PID}"

#=============================================================================
# Test 3: Larger runtime (100,000 ns = 100 microseconds)
#=============================================================================
test_section "Test 3: Larger runtime of 100,000 ns (100μs)"

large_runtime=100000
STALLD_LOG3="/tmp/stalld_test_boost_runtime_test3_$$.log"
CLEANUP_FILES+=("${STALLD_LOG3}")

log "Starting stalld with ${threshold}s threshold and ${large_runtime}ns runtime"
start_stalld_with_log "${STALLD_LOG3}" -f -v -c "${TEST_CPU}" -a ${STALLD_CPU} -t ${threshold} -r ${large_runtime} -l

# Create starvation
log "Creating starvation on CPU ${TEST_CPU} for ${starvation_duration}s"
start_starvation_gen -c "${TEST_CPU}" -p 80 -n 2 -d ${starvation_duration}

# Wait for detection and boosting
assert_starvation_detected "${STALLD_LOG3}" "Starvation detection with large runtime ${large_runtime}ns"

# Cleanup
cleanup_scenario "${STARVE_PID}"

#=============================================================================
# Test 4: Runtime < period (valid configuration)
#=============================================================================
test_section "Test 4: Runtime < period (valid)"

# Default period is 1,000,000,000 ns, so runtime of 500,000 ns should be valid
valid_runtime=500000
period=1000000000
STALLD_LOG4="/tmp/stalld_test_boost_runtime_test4_$$.log"
CLEANUP_FILES+=("${STALLD_LOG4}")

log "Starting stalld with runtime ${valid_runtime}ns < period ${period}ns"
start_stalld_with_log "${STALLD_LOG4}" -f -v -c "${TEST_CPU}" -a ${STALLD_CPU} -t ${threshold} -r ${valid_runtime} -p ${period} -l

# Create starvation
log "Creating starvation on CPU ${TEST_CPU} for ${starvation_duration}s"
start_starvation_gen -c "${TEST_CPU}" -p 80 -n 2 -d ${starvation_duration}

# Wait for detection and boosting
assert_starvation_detected "${STALLD_LOG4}" "Starvation detection with runtime < period"

# Cleanup
cleanup_scenario "${STARVE_PID}"

#=============================================================================
# Test 5: Runtime > period (should error or be rejected)
#=============================================================================
test_section "Test 5: Runtime > period (invalid)"

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
timeout 5 ${TEST_ROOT}/../stalld -f -v ${BACKEND_FLAG} -t ${threshold} -r ${invalid_runtime} -p ${period} > "${INVALID_LOG}" 2>&1
ret=$?

if [ $ret -ne 0 ] && [ $ret -ne 124 ]; then
    pass "Runtime > period rejected with error"
else
    fail "stalld did not reject invalid runtime > period"
fi

#=============================================================================
# Test 6: Invalid runtime (0)
#=============================================================================
test_section "Test 6: Invalid runtime value (0)"

INVALID_LOG2="/tmp/stalld_test_boost_runtime_invalid2_$$.log"
CLEANUP_FILES+=("${INVALID_LOG2}")

log "Testing with runtime = 0"
timeout 5 ${TEST_ROOT}/../stalld -f -v ${BACKEND_FLAG} -t ${threshold} -r 0 > "${INVALID_LOG2}" 2>&1
ret=$?

if [ $ret -ne 0 ] && [ $ret -ne 124 ]; then
    pass "Zero runtime rejected with error"
else
    fail "stalld did not reject invalid runtime value 0"
fi

#=============================================================================
# Test 7: Negative runtime
#=============================================================================
test_section "Test 7: Invalid runtime value (negative)"

INVALID_LOG3="/tmp/stalld_test_boost_runtime_invalid3_$$.log"
CLEANUP_FILES+=("${INVALID_LOG3}")

log "Testing with runtime = -5000"
timeout 5 ${TEST_ROOT}/../stalld -f -v ${BACKEND_FLAG} -t ${threshold} -r -5000 > "${INVALID_LOG3}" 2>&1
ret=$?

if [ $ret -ne 0 ] && [ $ret -ne 124 ]; then
    pass "Negative runtime rejected with error"
else
    fail "stalld did not reject invalid negative runtime"
fi

log ""
log "All boost runtime tests completed"

end_test
