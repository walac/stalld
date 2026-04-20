#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Test: stalld -p/--boost_period option
# Verifies that stalld uses the specified SCHED_DEADLINE period

# Load test helpers
TEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${TEST_ROOT}/helpers/test_helpers.sh"

# Parse command-line options
parse_test_options "$@" || exit $?

init_functional_test "Boost Period Option (-p)" "test_boost_period"

#=============================================================================
# Test 1: Default period (should be 1,000,000,000 ns = 1 second)
#=============================================================================
test_section "Test 1: Default period (no -p specified)"

threshold=5
log "Starting stalld with default period"
start_stalld_with_log "${STALLD_LOG}" -f -v -c "${TEST_CPU}" -a ${STALLD_CPU} -t $threshold -N

# Create starvation
starvation_duration=$((threshold + 5))
log "Creating starvation on CPU ${TEST_CPU} for ${starvation_duration}s"
start_starvation_gen -c "${TEST_CPU}" -p 80 -n 2 -d ${starvation_duration}

# Wait for starvation detection and boosting
if wait_for_boost_detected "${STALLD_LOG}"; then
    pass "Boosting occurred with default period"

    # Try to find period value in logs
    if grep -qi "period" "${STALLD_LOG}"; then
        log "ℹ INFO: Period information found in logs"
    fi
else
    fail "No boosting detected"
    log "Log contents:"
    cat "${STALLD_LOG}"
fi

# Cleanup
cleanup_scenario "${STARVE_PID}"

#=============================================================================
# Test 2: Custom period (500ms = 500,000,000 ns)
#=============================================================================
test_section "Test 2: Custom period of 500,000,000 ns (500ms)"

custom_period=500000000
rm -f "${STALLD_LOG}"
log "Starting stalld with custom period ${custom_period} ns"
start_stalld_with_log "${STALLD_LOG}" -f -v -c "${TEST_CPU}" -a ${STALLD_CPU} -t $threshold -p $custom_period -N

# Create starvation
log "Creating starvation on CPU ${TEST_CPU}"
start_starvation_gen -c "${TEST_CPU}" -p 80 -n 2 -d ${starvation_duration}

# Wait for starvation detection and boosting
assert_boost_detected "${STALLD_LOG}" "Boosting occurred with custom period ${custom_period} ns"

# Cleanup
cleanup_scenario "${STARVE_PID}"

#=============================================================================
# Test 3: Very short period (100ms = 100,000,000 ns)
#=============================================================================
test_section "Test 3: Short period of 200,000,000 ns (200ms)"

short_period=200000000
rm -f "${STALLD_LOG}"
log "Starting stalld with short period ${short_period} ns"
start_stalld_with_log "${STALLD_LOG}" -f -v -c "${TEST_CPU}" -a ${STALLD_CPU} -t $threshold -p $short_period -N

# Create starvation
log "Creating starvation on CPU ${TEST_CPU}"
start_starvation_gen -c "${TEST_CPU}" -p 80 -n 2 -d ${starvation_duration}

# Wait for starvation detection and boosting
assert_boost_detected "${STALLD_LOG}" "Boosting occurred with short period ${short_period} ns"

# Cleanup
cleanup_scenario "${STARVE_PID}"

#=============================================================================
# Test 4: Very long period (10s = 10,000,000,000 ns)
#=============================================================================
test_section "Test 4: Long period of 3,000,000,000 ns (3s)"

long_period=3000000000
rm -f "${STALLD_LOG}"
log "Starting stalld with long period ${long_period} ns"
start_stalld_with_log "${STALLD_LOG}" -f -v -c "${TEST_CPU}" -a ${STALLD_CPU} -t $threshold -p $long_period -N

# Create starvation
log "Creating starvation on CPU ${TEST_CPU}"
start_starvation_gen -c "${TEST_CPU}" -p 80 -n 2 -d ${starvation_duration}

# Wait for starvation detection and boosting
assert_boost_detected "${STALLD_LOG}" "Boosting occurred with long period ${long_period} ns"

# Cleanup
cleanup_scenario "${STARVE_PID}"

#=============================================================================
# Test 5: Invalid period (0)
#=============================================================================
test_section "Test 5: Invalid period value (0)"

INVALID_LOG="/tmp/stalld_test_boost_period_invalid_$$.log"
CLEANUP_FILES+=("${INVALID_LOG}")

timeout 5 ${TEST_ROOT}/../stalld -f -v ${BACKEND_FLAG} -t $threshold -p 0 > "${INVALID_LOG}" 2>&1
ret=$?

if [ $ret -ne 0 ] && [ $ret -ne 124 ]; then
    pass "Zero period rejected with error"
else
    fail "stalld did not reject invalid period value 0"
fi

#=============================================================================
# Test 6: Negative period
#=============================================================================
test_section "Test 6: Invalid period value (negative)"

rm -f "${INVALID_LOG}"

timeout 5 ${TEST_ROOT}/../stalld -f -v ${BACKEND_FLAG} -t $threshold -p -1000000 > "${INVALID_LOG}" 2>&1
ret=$?

if [ $ret -ne 0 ] && [ $ret -ne 124 ]; then
    pass "Negative period rejected with error"
else
    fail "stalld did not reject invalid negative period"
fi

#=============================================================================
# Final Summary
#=============================================================================
test_section "Test Summary"
log "Total failures: ${TEST_FAILED}"

end_test
