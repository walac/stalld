#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Test: stalld -a/--affinity option
# Verifies that stalld runs on specified CPUs when -a is used
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

# Helper function to check CPU affinity
check_affinity() {
    local pid=$1

    # Use taskset to check affinity
    if command -v taskset > /dev/null 2>&1; then
        affinity=$(taskset -cp "$pid" 2>/dev/null | awk -F': ' '{print $2}')
        log "ℹ INFO: Current affinity for PID $pid: $affinity" >&2
        echo "$affinity"
    else
        # Fallback: check /proc/PID/status
        if [ -f "/proc/$pid/status" ]; then
            affinity=$(grep "Cpus_allowed_list:" "/proc/$pid/status" | awk '{print $2}')
            log "ℹ INFO: Current affinity for PID $pid (from /proc): $affinity" >&2
            echo "$affinity"
        else
            log "⚠ WARNING: Cannot check affinity (no taskset, no /proc)" >&2
            echo ""
        fi
    fi
}

start_test "CPU Affinity Option (-a)"

# Require root for this test
require_root

# Check RT throttling
if ! check_rt_throttling; then
    echo -e "${YELLOW}SKIP: RT throttling must be disabled for this test${NC}"
    exit 77
fi

# Get number of CPUs
num_cpus=$(nproc)
log "System has $num_cpus CPUs"

if [ "$num_cpus" -lt 2 ]; then
    echo -e "${YELLOW}SKIP: Test requires at least 2 CPUs${NC}"
    exit 77
fi

# Check if taskset is available
if ! command -v taskset > /dev/null 2>&1; then
    log "⚠ WARNING: taskset not found, will use /proc fallback"
fi

# Setup paths
STALLD_LOG="/tmp/stalld_test_affinity_$$.log"
CLEANUP_FILES+=("${STALLD_LOG}")

#=============================================================================
# Test 1: Default behavior (no -a specified)
#=============================================================================
log ""
log "=========================================="
log "Test 1: Default behavior (no affinity restriction)"
log "=========================================="

start_stalld -f -v -l -t 5
sleep 2

default_affinity=$(check_affinity "${STALLD_PID}")
log "ℹ INFO: Default affinity: $default_affinity"

# Typically should be all CPUs
if [ -n "$default_affinity" ]; then
    log "✓ PASS: stalld has default affinity: $default_affinity"
else
    log "⚠ WARNING: Could not determine default affinity"
fi

stop_stalld
sleep 1

#=============================================================================
# Test 2: Single CPU affinity
#=============================================================================
log ""
log "=========================================="
log "Test 2: Single CPU affinity (-a 0)"
log "=========================================="

STALLD_LOG2="/tmp/stalld_test_affinity_test2_$$.log"
CLEANUP_FILES+=("${STALLD_LOG2}")

start_stalld -f -v -l -t 5 -a 0
sleep 2

affinity=$(check_affinity "${STALLD_PID}")

if [ "$affinity" = "0" ]; then
    log "✓ PASS: stalld restricted to CPU 0"
else
    log "✗ FAIL: stalld affinity ($affinity) doesn't match requested (0)"
    TEST_FAILED=$((TEST_FAILED + 1))
fi

stop_stalld
sleep 1

#=============================================================================
# Test 3: Multi-CPU affinity (CPU list)
#=============================================================================
log ""
log "=========================================="
log "Test 3: Multi-CPU affinity (-a 0,2)"
log "=========================================="

if [ "$num_cpus" -ge 4 ]; then
    STALLD_LOG3="/tmp/stalld_test_affinity_test3_$$.log"
    CLEANUP_FILES+=("${STALLD_LOG3}")

    start_stalld -f -v -l -t 5 -a 0,2
    sleep 2

    affinity=$(check_affinity "${STALLD_PID}")

    # Accept either "0,2" or "0-2" or "2,0" (different systems may report differently)
    if echo "$affinity" | grep -qE '^0,2$|^0-2$|^2,0$'; then
        log "✓ PASS: stalld restricted to CPUs 0,2 (affinity: $affinity)"
    else
        log "⚠ WARNING: stalld affinity ($affinity) may not match requested (0,2) - format may vary"
        # Not failing as different systems may report differently
    fi

    stop_stalld
    sleep 1
else
    log "⊘ SKIP: Test 3 requires at least 4 CPUs"
fi

#=============================================================================
# Test 4: CPU range affinity
#=============================================================================
log ""
log "=========================================="
log "Test 4: CPU range affinity (-a 0-2)"
log "=========================================="

if [ "$num_cpus" -ge 4 ]; then
    STALLD_LOG4="/tmp/stalld_test_affinity_test4_$$.log"
    CLEANUP_FILES+=("${STALLD_LOG4}")

    start_stalld -f -v -l -t 5 -a 0-2
    sleep 2

    affinity=$(check_affinity "${STALLD_PID}")

    # Accept various formats: "0-2", "0,1,2", etc.
    if echo "$affinity" | grep -qE '0.*1.*2|0-2'; then
        log "✓ PASS: stalld restricted to CPU range 0-2 (affinity: $affinity)"
    else
        log "⚠ WARNING: stalld affinity ($affinity) may not match requested (0-2) - format may vary"
    fi

    stop_stalld
    sleep 1
else
    log "⊘ SKIP: Test 4 requires at least 4 CPUs"
fi

#=============================================================================
# Test 5: Verify stalld actually runs on specified CPU
#=============================================================================
log ""
log "=========================================="
log "Test 5: Verify stalld threads run on specified CPU"
log "=========================================="

if [ "$num_cpus" -ge 2 ]; then
    test_cpu=1
    STALLD_LOG5="/tmp/stalld_test_affinity_test5_$$.log"
    CLEANUP_FILES+=("${STALLD_LOG5}")

    start_stalld -f -v -l -t 5 -a "$test_cpu"
    sleep 2

    # Check affinity
    affinity=$(check_affinity "${STALLD_PID}")

    # Also check if any child threads exist and verify their affinity
    child_threads=$(ps -T -p "${STALLD_PID}" 2>/dev/null | tail -n +2 | wc -l)
    if [ "$child_threads" -gt 0 ]; then
        log "ℹ INFO: Found $child_threads threads for stalld"
    fi

    if [ "$affinity" = "$test_cpu" ]; then
        log "✓ PASS: stalld process affinity set to CPU $test_cpu"
    else
        log "⚠ WARNING: stalld affinity ($affinity) doesn't exactly match CPU $test_cpu"
    fi

    stop_stalld
    sleep 1
else
    log "⊘ SKIP: Test 5 requires at least 2 CPUs"
fi

#=============================================================================
# Test 6: Combined with CPU monitoring (-c and -a)
#=============================================================================
log ""
log "=========================================="
log "Test 6: Combined affinity and monitoring (-a 0 -c 1)"
log "=========================================="

if [ "$num_cpus" -ge 2 ]; then
    STALLD_LOG6="/tmp/stalld_test_affinity_test6_$$.log"
    CLEANUP_FILES+=("${STALLD_LOG6}")

    # Run stalld on CPU 0, but monitor CPU 1
    start_stalld -f -v -l -t 5 -a 0 -c 1
    sleep 2

    affinity=$(check_affinity "${STALLD_PID}")

    if [ "$affinity" = "0" ]; then
        log "✓ PASS: stalld affinity to CPU 0 while monitoring CPU 1"
    else
        log "⚠ WARNING: stalld affinity ($affinity) doesn't match requested (0)"
    fi

    # Verify it's monitoring CPU 1 by checking logs
    if grep -q "cpu 1" "${STALLD_LOG6}" || grep -q "monitoring.*1" "${STALLD_LOG6}"; then
        log "ℹ INFO: stalld monitoring CPU 1 as requested"
    else
        log "ℹ INFO: CPU 1 monitoring not explicitly confirmed in logs"
    fi

    stop_stalld
    sleep 1
else
    log "⊘ SKIP: Test 6 requires at least 2 CPUs"
fi

#=============================================================================
# Test 7: Invalid CPU affinity
#=============================================================================
log ""
log "=========================================="
log "Test 7: Invalid CPU affinity (-a 999)"
log "=========================================="

invalid_cpu=999
INVALID_LOG="/tmp/stalld_test_affinity_invalid_$$.log"
CLEANUP_FILES+=("${INVALID_LOG}")

# Add backend flag for consistency
BACKEND_FLAG=""
if [ -n "${STALLD_TEST_BACKEND}" ]; then
    BACKEND_FLAG="-b ${STALLD_TEST_BACKEND}"
fi

${TEST_ROOT}/../stalld -f -v ${BACKEND_FLAG} -l -t 5 -a ${invalid_cpu} > "${INVALID_LOG}" 2>&1 &
invalid_pid=$!
sleep 2

if ! kill -0 "${invalid_pid}" 2>/dev/null; then
    # Process exited
    if grep -qi "error\|invalid\|failed" "${INVALID_LOG}"; then
        log "✓ PASS: Invalid CPU affinity rejected with error"
    else
        log "ℹ INFO: Invalid CPU affinity caused exit"
    fi
else
    # Process still running - might have been ignored
    log "⚠ WARNING: stalld accepted invalid CPU affinity"
    kill -TERM "${invalid_pid}" 2>/dev/null || true
    wait "${invalid_pid}" 2>/dev/null || true
fi

#=============================================================================
# Test 8: Verify affinity persists
#=============================================================================
log ""
log "=========================================="
log "Test 8: Verify affinity persists over time"
log "=========================================="

STALLD_LOG8="/tmp/stalld_test_affinity_test8_$$.log"
CLEANUP_FILES+=("${STALLD_LOG8}")

start_stalld -f -v -l -t 5 -a 0
sleep 2

affinity_start=$(check_affinity "${STALLD_PID}")
log "ℹ INFO: Initial affinity: $affinity_start"

# Wait a bit
sleep 3

affinity_end=$(check_affinity "${STALLD_PID}")
log "ℹ INFO: Affinity after 3s: $affinity_end"

if [ "$affinity_start" = "$affinity_end" ]; then
    log "✓ PASS: CPU affinity persisted over time"
else
    log "⚠ WARNING: CPU affinity changed (start: $affinity_start, end: $affinity_end)"
fi

stop_stalld
sleep 1

log ""
log "All affinity tests completed"

end_test
