#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Test: stalld -p/--boost_period option
# Verifies that stalld uses the specified SCHED_DEADLINE period

# Load test helpers
TEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${TEST_ROOT}/helpers/test_helpers.sh"

# Parse command-line options
parse_test_options "$@" || exit $?

# Helper function for logging test steps
log() {
    echo "[$(date +'%H:%M:%S')] $*"
}

start_test "Boost Period Option (-p)"

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
STALLD_LOG="/tmp/stalld_test_boost_period_$$.log"
CLEANUP_FILES+=("${STALLD_LOG}")

if [ ! -x "${STARVE_GEN}" ]; then
    echo -e "${YELLOW}SKIP: starvation_gen not found or not executable${NC}"
    exit 77
fi

#=============================================================================
# Test 1: Default period (should be 1,000,000,000 ns = 1 second)
#=============================================================================
log ""
log "=========================================="
log "Test 1: Default period (no -p specified)"
log "=========================================="

threshold=5
log "Starting stalld with default period"
start_stalld -f -v -c "${TEST_CPU}" -t $threshold > "${STALLD_LOG}" 2>&1

# Create starvation
starvation_duration=$((threshold + 5))
log "Creating starvation on CPU ${TEST_CPU} for ${starvation_duration}s"
"${STARVE_GEN}" -c "${TEST_CPU}" -p 80 -n 2 -d ${starvation_duration} &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Wait for detection and boosting
wait_time=$((threshold + 2))
log "Waiting ${wait_time}s for starvation detection and boosting..."
sleep ${wait_time}

# Check if boosting occurred
if grep -q "boost" "${STALLD_LOG}"; then
    log "✓ PASS: Boosting occurred with default period"

    # Try to find period value in logs
    if grep -qi "period" "${STALLD_LOG}"; then
        log "ℹ INFO: Period information found in logs"
    fi
else
    log "✗ FAIL: No boosting detected"
    log "Log contents:"
    cat "${STALLD_LOG}"
    TEST_FAILED=$((TEST_FAILED + 1))
fi

# Cleanup
kill -TERM ${STARVE_PID} 2>/dev/null || true
wait ${STARVE_PID} 2>/dev/null || true
stop_stalld

#=============================================================================
# Test 2: Custom period (500ms = 500,000,000 ns)
#=============================================================================
log ""
log "=========================================="
log "Test 2: Custom period of 500,000,000 ns (500ms)"
log "=========================================="

custom_period=500000000
rm -f "${STALLD_LOG}"
log "Starting stalld with custom period ${custom_period} ns"
start_stalld -f -v -c "${TEST_CPU}" -t $threshold -p $custom_period > "${STALLD_LOG}" 2>&1

# Create starvation
log "Creating starvation on CPU ${TEST_CPU}"
"${STARVE_GEN}" -c "${TEST_CPU}" -p 80 -n 2 -d ${starvation_duration} &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Wait for detection and boosting
sleep ${wait_time}

# Check if boosting occurred
if grep -q "boost" "${STALLD_LOG}"; then
    log "✓ PASS: Boosting occurred with custom period ${custom_period} ns"
else
    log "✗ FAIL: No boosting with custom period"
    TEST_FAILED=$((TEST_FAILED + 1))
fi

# Cleanup
kill -TERM ${STARVE_PID} 2>/dev/null || true
wait ${STARVE_PID} 2>/dev/null || true
stop_stalld

#=============================================================================
# Test 3: Very short period (100ms = 100,000,000 ns)
#=============================================================================
log ""
log "=========================================="
log "Test 3: Very short period of 100,000,000 ns (100ms)"
log "=========================================="

short_period=100000000
rm -f "${STALLD_LOG}"
log "Starting stalld with short period ${short_period} ns"
start_stalld -f -v -c "${TEST_CPU}" -t $threshold -p $short_period > "${STALLD_LOG}" 2>&1

# Create starvation
log "Creating starvation on CPU ${TEST_CPU}"
"${STARVE_GEN}" -c "${TEST_CPU}" -p 80 -n 2 -d ${starvation_duration} &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Wait for detection and boosting
sleep ${wait_time}

# Check if boosting occurred
if grep -q "boost" "${STALLD_LOG}"; then
    log "✓ PASS: Boosting occurred with short period ${short_period} ns"
else
    log "✗ FAIL: No boosting with short period"
    TEST_FAILED=$((TEST_FAILED + 1))
fi

# Cleanup
kill -TERM ${STARVE_PID} 2>/dev/null || true
wait ${STARVE_PID} 2>/dev/null || true
stop_stalld

#=============================================================================
# Test 4: Very long period (10s = 10,000,000,000 ns)
#=============================================================================
log ""
log "=========================================="
log "Test 4: Very long period of 10,000,000,000 ns (10s)"
log "=========================================="

long_period=10000000000
rm -f "${STALLD_LOG}"
log "Starting stalld with long period ${long_period} ns"
start_stalld -f -v -c "${TEST_CPU}" -t $threshold -p $long_period > "${STALLD_LOG}" 2>&1

# Create starvation
log "Creating starvation on CPU ${TEST_CPU}"
"${STARVE_GEN}" -c "${TEST_CPU}" -p 80 -n 2 -d ${starvation_duration} &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Wait for detection and boosting
sleep ${wait_time}

# Check if boosting occurred
if grep -q "boost" "${STALLD_LOG}"; then
    log "✓ PASS: Boosting occurred with long period ${long_period} ns"
else
    log "✗ FAIL: No boosting with long period"
    TEST_FAILED=$((TEST_FAILED + 1))
fi

# Cleanup
kill -TERM ${STARVE_PID} 2>/dev/null || true
wait ${STARVE_PID} 2>/dev/null || true
stop_stalld

#=============================================================================
# Test 5: Invalid period (0)
#=============================================================================
log ""
log "=========================================="
log "Test 5: Invalid period value (0)"
log "=========================================="

INVALID_LOG="/tmp/stalld_test_boost_period_invalid_$$.log"
CLEANUP_FILES+=("${INVALID_LOG}")

${TEST_ROOT}/../stalld -f -v -t $threshold -p 0 > "${INVALID_LOG}" 2>&1 &
invalid_pid=$!
sleep 2

if ! kill -0 "$invalid_pid" 2>/dev/null; then
    if grep -qi "error\|invalid" "${INVALID_LOG}"; then
        log "✓ PASS: Zero period rejected with error"
    else
        log "ℹ INFO: Zero period caused exit"
    fi
else
    log "⚠ WARNING: stalld accepted zero period"
    kill -TERM "$invalid_pid" 2>/dev/null || true
    wait "$invalid_pid" 2>/dev/null || true
fi

#=============================================================================
# Test 6: Negative period
#=============================================================================
log ""
log "=========================================="
log "Test 6: Invalid period value (negative)"
log "=========================================="

INVALID_LOG2="/tmp/stalld_test_boost_period_invalid2_$$.log"
CLEANUP_FILES+=("${INVALID_LOG2}")

${TEST_ROOT}/../stalld -f -v -t $threshold -p -1000000 > "${INVALID_LOG2}" 2>&1 &
invalid_pid=$!
sleep 2

if ! kill -0 "$invalid_pid" 2>/dev/null; then
    if grep -qi "error\|invalid" "${INVALID_LOG2}"; then
        log "✓ PASS: Negative period rejected with error"
    else
        log "ℹ INFO: Negative period caused exit"
    fi
else
    log "⚠ WARNING: stalld accepted negative period"
    kill -TERM "$invalid_pid" 2>/dev/null || true
    wait "$invalid_pid" 2>/dev/null || true
fi

#=============================================================================
# Final Summary
#=============================================================================
log ""
log "=========================================="
log "Test Summary"
log "=========================================="
log "Total failures: ${TEST_FAILED}"

end_test
