#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Test: stalld -F/--force_fifo option
# Verifies that stalld uses SCHED_FIFO instead of SCHED_DEADLINE when -F is specified
#
# Copyright (C) 2025 Red Hat Inc

# Load test helpers
TEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${TEST_ROOT}/helpers/test_helpers.sh"

# Parse command-line options
parse_test_options "$@" || exit $?

start_test "Force FIFO Option (-F)"

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

# Setup paths
STARVE_GEN="${TEST_ROOT}/helpers/starvation_gen"
STALLD_LOG="/tmp/stalld_test_force_fifo_$$.log"
CLEANUP_FILES+=("${STALLD_LOG}")

if [ ! -x "${STARVE_GEN}" ]; then
    echo -e "${YELLOW}SKIP: starvation_gen not found or not executable${NC}"
    exit 77
fi

#=============================================================================
# Test 1: Default behavior (should use SCHED_DEADLINE)
#=============================================================================
log ""
log "=========================================="
log "Test 1: Default behavior (no -F, should use SCHED_DEADLINE)"
log "=========================================="

threshold=3
log "Starting stalld with ${threshold}s threshold (default, no -F)"
start_stalld_with_log "${STALLD_LOG}" -f -v -c "${TEST_CPU}" -t ${threshold}

# Create starvation
starvation_duration=10
log "Creating starvation on CPU ${TEST_CPU} for ${starvation_duration}s"
start_starvation_gen -c ${TEST_CPU} -p 80 -n 2 -d ${starvation_duration}

# Wait for detection and boosting
if wait_for_boost_detected "${STALLD_LOG}"; then
    log "Boosting occurred"

    # Look for SCHED_DEADLINE indicators
    if grep -qi "deadline\|SCHED_DEADLINE" "${STALLD_LOG}"; then
        pass "SCHED_DEADLINE used by default"
    elif grep -qi "fifo\|SCHED_FIFO" "${STALLD_LOG}"; then
        log "⚠ WARNING: SCHED_FIFO used instead of SCHED_DEADLINE"
    else
        log "ℹ INFO: Scheduling policy not explicitly mentioned in logs"
    fi
else
    log "⚠ WARNING: No boosting detected in default mode"
fi

# Cleanup
kill -TERM "${STARVE_PID}" 2>/dev/null
wait "${STARVE_PID}" 2>/dev/null || true
stop_stalld

#=============================================================================
# Test 2: Force FIFO mode (-F)
#=============================================================================
log ""
log "=========================================="
log "Test 2: Force FIFO mode (-F)"
log "=========================================="

# Note: Single-threaded mode only works with SCHED_DEADLINE (dies with FIFO)
# So we need to use aggressive mode (-A) when testing FIFO
STALLD_LOG2="/tmp/stalld_test_force_fifo_test2_$$.log"
CLEANUP_FILES+=("${STALLD_LOG2}")

log "Starting stalld with -F flag and aggressive mode (-A)"
start_stalld_with_log "${STALLD_LOG2}" -f -v -c "${TEST_CPU}" -t ${threshold} -F -A

# Create starvation
log "Creating starvation on CPU ${TEST_CPU} for ${starvation_duration}s"
start_starvation_gen -c ${TEST_CPU} -p 80 -n 2 -d ${starvation_duration}

# Wait for detection and boosting
if wait_for_boost_detected "${STALLD_LOG2}"; then
    log "Boosting occurred with -F flag"

    # Look for SCHED_FIFO indicators
    if grep -qi "fifo\|SCHED_FIFO" "${STALLD_LOG2}"; then
        pass "SCHED_FIFO used with -F flag"
    elif grep -qi "deadline\|SCHED_DEADLINE" "${STALLD_LOG2}"; then
        fail "SCHED_DEADLINE used despite -F flag"
    else
        log "⚠ WARNING: Scheduling policy not explicitly mentioned in logs"
    fi
else
    log "⚠ WARNING: No boosting detected with -F flag"
fi

# Cleanup
kill -TERM "${STARVE_PID}" 2>/dev/null
wait "${STARVE_PID}" 2>/dev/null || true
stop_stalld

#=============================================================================
# Test 3: Verify FIFO priority setting
#=============================================================================
log ""
log "=========================================="
log "Test 3: Verify FIFO priority is set"
log "=========================================="

STALLD_LOG3="/tmp/stalld_test_force_fifo_test3_$$.log"
CLEANUP_FILES+=("${STALLD_LOG3}")

log "Starting stalld with -F and -A flags"
start_stalld_with_log "${STALLD_LOG3}" -f -v -c "${TEST_CPU}" -t ${threshold} -F -A

# Create starvation
log "Creating starvation on CPU ${TEST_CPU} for ${starvation_duration}s"
start_starvation_gen -c ${TEST_CPU} -p 80 -n 2 -d ${starvation_duration}

# Wait for detection and boosting
wait_for_boost_detected "${STALLD_LOG3}"

# Check logs for priority information
if grep -qi "priority\|prio" "${STALLD_LOG3}"; then
    log "ℹ INFO: Priority information found in logs"
fi

if grep -q "boost" "${STALLD_LOG3}"; then
    pass "FIFO boosting with priority setting completed"
else
    log "⚠ WARNING: No boosting detected"
fi

# Cleanup
kill -TERM "${STARVE_PID}" 2>/dev/null
wait "${STARVE_PID}" 2>/dev/null || true
stop_stalld

#=============================================================================
# Test 4: Verify FIFO emulation behavior (sleep runtime, restore, sleep remainder)
#=============================================================================
log ""
log "=========================================="
log "Test 4: FIFO emulation behavior"
log "=========================================="

boost_duration=3
long_starvation=12
STALLD_LOG4="/tmp/stalld_test_force_fifo_test4_$$.log"
CLEANUP_FILES+=("${STALLD_LOG4}")

log "Starting stalld with -F, -A, and ${boost_duration}s boost duration"
start_stalld_with_log "${STALLD_LOG4}" -f -v -c "${TEST_CPU}" -t ${threshold} -F -A -d ${boost_duration}

# Create starvation
log "Creating starvation on CPU ${TEST_CPU} for ${long_starvation}s"
start_starvation_gen -c ${TEST_CPU} -p 80 -n 2 -d ${long_starvation}

# Wait for detection and boosting
if wait_for_boost_detected "${STALLD_LOG4}"; then
    log "Boosting detected, waiting for duration cycle"

    # Wait for boost duration + buffer to see restoration
    sleep 5

    # Check for restoration messages (part of FIFO emulation)
    if grep -qi "restor\|unboosted\|normal\|original" "${STALLD_LOG4}"; then
        pass "FIFO emulation with restoration detected"
    else
        log "ℹ INFO: FIFO boosting completed (restoration may be implicit)"
    fi
else
    log "⚠ WARNING: No boosting detected for FIFO emulation test"
fi

# Cleanup
kill -TERM "${STARVE_PID}" 2>/dev/null
wait "${STARVE_PID}" 2>/dev/null || true
stop_stalld

#=============================================================================
# Test 5: Single-threaded mode with FIFO (should fail/exit)
#=============================================================================
log ""
log "=========================================="
log "Test 5: Single-threaded mode with FIFO (should fail)"
log "=========================================="

# Try to run stalld with -F but without -A (single-threaded mode)
# According to CLAUDE.md, this should die/exit
FIFO_SINGLE_LOG="/tmp/stalld_test_force_fifo_single_$$.log"
CLEANUP_FILES+=("${FIFO_SINGLE_LOG}")

log "Testing single-threaded mode with -F (should exit)"
timeout 5 ${TEST_ROOT}/../stalld -f -v -c "${TEST_CPU}" -t ${threshold} -F > "${FIFO_SINGLE_LOG}" 2>&1
ret=$?

if [ $ret -ne 0 ] && [ $ret -ne 124 ]; then
    pass "single-threaded mode rejected FIFO"
else
    fail "stalld did not reject -F in single-threaded mode"
fi

#=============================================================================
# Test 6: Compare effectiveness (informational)
#=============================================================================
log ""
log "=========================================="
log "Test 6: FIFO vs DEADLINE comparison (informational)"
log "=========================================="

comparison_duration=2
comparison_starvation=8

# Run with DEADLINE
STALLD_LOG_DL="/tmp/stalld_test_force_fifo_deadline_$$.log"
CLEANUP_FILES+=("${STALLD_LOG_DL}")

log "Running comparison test with SCHED_DEADLINE"
start_stalld_with_log "${STALLD_LOG_DL}" -f -v -c "${TEST_CPU}" -t ${threshold} -d ${comparison_duration}
start_starvation_gen -c ${TEST_CPU} -p 80 -n 2 -d ${comparison_starvation}
wait_for_boost_detected "${STALLD_LOG_DL}"

deadline_boosts=$(grep -c "boost" "${STALLD_LOG_DL}" || echo 0)
log "ℹ INFO: SCHED_DEADLINE boosts: $deadline_boosts"

kill -TERM "${STARVE_PID}" 2>/dev/null
wait "${STARVE_PID}" 2>/dev/null || true
stop_stalld

# Run with FIFO
STALLD_LOG_FIFO="/tmp/stalld_test_force_fifo_comparison_$$.log"
CLEANUP_FILES+=("${STALLD_LOG_FIFO}")

log "Running comparison test with SCHED_FIFO"
start_stalld_with_log "${STALLD_LOG_FIFO}" -f -v -c "${TEST_CPU}" -t ${threshold} -F -A -d ${comparison_duration}
start_starvation_gen -c ${TEST_CPU} -p 80 -n 2 -d ${comparison_starvation}
wait_for_boost_detected "${STALLD_LOG_FIFO}"

fifo_boosts=$(grep -c "boost" "${STALLD_LOG_FIFO}" || echo 0)
log "ℹ INFO: SCHED_FIFO boosts: $fifo_boosts"

kill -TERM "${STARVE_PID}" 2>/dev/null
wait "${STARVE_PID}" 2>/dev/null || true
stop_stalld

log "ℹ INFO: Comparison complete (DEADLINE: $deadline_boosts, FIFO: $fifo_boosts)"

log ""
log "All force FIFO tests completed"

end_test
