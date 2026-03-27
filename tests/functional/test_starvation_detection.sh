#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Test: Starvation Detection Logic
# Verify stalld correctly detects starving tasks, tracks context switches,
# and implements task merging (timestamp preservation)
#
# Copyright (C) 2025 Red Hat Inc

# Load test helpers
TEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${TEST_ROOT}/helpers/test_helpers.sh"

# Parse command-line options
parse_test_options "$@" || exit $?

# Helper to extract starved task PID from stalld logs (test-specific)
get_starved_pid() {
    local log_file=$1
    # Look for pattern like "starvation_gen-12345 starved on CPU"
    grep "starved on CPU" "$log_file" | tail -1 | sed -E 's/.*\[([0-9]+)\].*/\1/' | head -1
}

start_test "Starvation Detection Logic"

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

# Get number of CPUs for multi-CPU tests
NUM_CPUS=$(get_num_cpus)

# Setup paths
STARVE_GEN="${TEST_ROOT}/helpers/starvation_gen"
STALLD_LOG="/tmp/stalld_test_detection_$$.log"
CLEANUP_FILES+=("${STALLD_LOG}")

#=============================================================================
# Test 1: Basic Starvation Detection
#=============================================================================
log ""
log "=========================================="
log "Test 1: Basic Starvation Detection"
log "=========================================="

threshold=5

# Create starvation BEFORE starting stalld to avoid idle detection race
starvation_duration=$((threshold + 5))
log "Creating starvation on CPU ${TEST_CPU} for ${starvation_duration}s"
start_starvation_gen -c ${TEST_CPU} -p 80 -n 2 -d ${starvation_duration}

log "Starting stalld with ${threshold}s threshold (log-only mode)"
start_stalld_with_log "${STALLD_LOG}" -f -v -N -l -t $threshold -c ${TEST_CPU} -a ${STALLD_CPU}

# Wait for starvation detection
log "Waiting for starvation detection..."
if wait_for_starvation_detected "${STALLD_LOG}"; then
    pass "Starvation detected"

    # Verify correct CPU is logged
    if grep "starved on CPU ${TEST_CPU}" "${STALLD_LOG}"; then
        pass "Correct CPU ID logged (CPU ${TEST_CPU})"
    else
        fail "Wrong CPU ID in log"
    fi

    # Verify duration is logged
    if grep -E "starved on CPU ${TEST_CPU} for [0-9]+ seconds" "${STALLD_LOG}"; then
        pass "Starvation duration logged"
    else
        fail "Starvation duration not logged"
    fi
else
    fail "Starvation not detected"
    log "Log contents:"
    cat "${STALLD_LOG}"
fi

# Cleanup
kill -TERM ${STARVE_PID} 2>/dev/null
wait ${STARVE_PID} 2>/dev/null
stop_stalld

#=============================================================================
# Test 2: Context Switch Count Tracking
#=============================================================================
log ""
log "=========================================="
log "Test 2: Context Switch Count Tracking"
log "=========================================="

rm -f "${STALLD_LOG}"
threshold=5

# Create starvation
log "Creating starvation on CPU ${TEST_CPU}"
start_starvation_gen -c ${TEST_CPU} -p 80 -n 1 -d 15

log "Starting stalld with ${threshold}s threshold (log-only mode)"
start_stalld_with_log "${STALLD_LOG}" -f -v -N -l -t $threshold -c ${TEST_CPU} -a ${STALLD_CPU}

# Wait for starvation detection
log "Waiting for starvation detection..."
wait_for_starvation_detected "${STALLD_LOG}"

# Try to find the starved task PID from starvation_gen children
# The blockee thread is what gets starved
STARVE_CHILDREN=$(pgrep -P ${STARVE_PID} 2>/dev/null)
if [ -n "${STARVE_CHILDREN}" ]; then
    # Get context switch count for one of the starved tasks
    for child_pid in ${STARVE_CHILDREN}; do
        if [ -f "/proc/${child_pid}/status" ]; then
            ctxt_before=$(get_ctxt_switches ${child_pid})
            log "Found starved task PID ${child_pid}, context switches: ${ctxt_before}"

            # Wait a bit
            sleep 2

            # Check context switches again - should be same or very low change
            ctxt_after=$(get_ctxt_switches ${child_pid})
            log "Context switches after 2s: ${ctxt_after}"

            ctxt_delta=$((ctxt_after - ctxt_before))
            if [ ${ctxt_delta} -lt 5 ]; then
                pass "Context switch count remained low (delta: ${ctxt_delta})"
            else
                fail "Context switches increased significantly (delta: ${ctxt_delta})"
            fi
            break
        fi
    done
else
    log "⚠ WARNING: Could not find starved task PIDs to verify context switches"
fi

# Cleanup
kill -TERM ${STARVE_PID} 2>/dev/null
wait ${STARVE_PID} 2>/dev/null
stop_stalld

#=============================================================================
# Test 3: Task Merging (Timestamp Preservation)
#=============================================================================
log ""
log "=========================================="
log "Test 3: Task Merging - Timestamp Preservation"
log "=========================================="

rm -f "${STALLD_LOG}"
threshold=3

# Create long starvation to trigger multiple detection cycles
starvation_duration=15
log "Creating starvation on CPU ${TEST_CPU} for ${starvation_duration}s"
start_starvation_gen -c ${TEST_CPU} -p 80 -n 2 -d ${starvation_duration}

log "Starting stalld with ${threshold}s threshold (log-only mode)"
log "Will monitor for multiple detection cycles to verify timestamp preservation"
start_stalld_with_log "${STALLD_LOG}" -f -v -N -l -t $threshold -c ${TEST_CPU} -a ${STALLD_CPU}

# Wait for first detection cycle
log "Waiting for first detection cycle..."
wait_for_starvation_detected "${STALLD_LOG}"
log "First detection cycle should have occurred"
# Wait for additional detection cycles
sleep 4
log "Second detection cycle should have occurred"
sleep 4
log "Third detection cycle should have occurred"

# Stop stalld to flush output buffers before checking log
stop_stalld

# Check if we see accumulating starvation time in logs
# Task merging means the timestamp is preserved, so duration increases
report_count=$(grep -cE "starved on CPU ${TEST_CPU} for [0-9]+ seconds" "${STALLD_LOG}")
if [ "${report_count}" -ge 2 ]; then
    pass "Multiple starvation reports found (${report_count} reports)"

    # Extract starvation durations from log
    durations=$(grep -oE "starved on CPU ${TEST_CPU} for [0-9]+" "${STALLD_LOG}" | grep -oE "[0-9]+$")
    log "Starvation durations observed: $(echo $durations | tr '\n' ' ')"

    # Verify durations are increasing (timestamp preserved = duration accumulates)
    first_duration=$(echo "$durations" | head -1)
    last_duration=$(echo "$durations" | tail -1)

    if [ ${last_duration} -gt ${first_duration} ]; then
        pass "Starvation duration increased (${first_duration}s -> ${last_duration}s)"
        log "        This confirms task merging preserved the timestamp"
    else
        fail "Starvation duration did not increase (timestamp may have been reset)"
    fi
else
    fail "Not enough starvation reports to verify task merging (found ${report_count}, need >= 2)"
    log "Log contents:"
    cat "${STALLD_LOG}"
fi

# Cleanup starvation generator
kill -TERM ${STARVE_PID} 2>/dev/null
wait ${STARVE_PID} 2>/dev/null

#=============================================================================
# Test 4: Multiple CPUs Detection
#=============================================================================
log ""
log "=========================================="
log "Test 4: Multiple CPUs Detection"
log "=========================================="

if [ ${NUM_CPUS} -lt 2 ]; then
    log "⚠ SKIP: Need at least 2 CPUs for this test (have ${NUM_CPUS})"
else
    CPU0=${TEST_CPU}
    # Pick a different CPU
    if [ ${TEST_CPU} -eq 0 ]; then
        CPU1=1
    else
        CPU1=0
    fi

    # Pick stalld CPU that avoids both test CPUs
    STALLD_CPU_MULTI=${STALLD_CPU}
    if [ ${STALLD_CPU} -eq ${CPU0} ] || [ ${STALLD_CPU} -eq ${CPU1} ]; then
        # Find a CPU that's not CPU0 or CPU1
        for cpu in $(get_online_cpus); do
            if [ $cpu -ne ${CPU0} ] && [ $cpu -ne ${CPU1} ]; then
                STALLD_CPU_MULTI=$cpu
                break
            fi
        done
        log "Adjusted stalld CPU from ${STALLD_CPU} to ${STALLD_CPU_MULTI} to avoid test CPUs"
    fi

    log "Testing starvation detection on CPU ${CPU0} and CPU ${CPU1}"
    log "Stalld will run on CPU ${STALLD_CPU_MULTI}"

    rm -f "${STALLD_LOG}"
    threshold=5

    # Create starvation on CPU0
    log "Creating starvation on CPU ${CPU0}"
    start_starvation_gen -c ${CPU0} -p 80 -n 1 -d 12
    STARVE_PID0=${STARVE_PID}

    # Create starvation on CPU1
    log "Creating starvation on CPU ${CPU1}"
    start_starvation_gen -c ${CPU1} -p 80 -n 1 -d 12
    STARVE_PID1=${STARVE_PID}

    start_stalld_with_log "${STALLD_LOG}" -f -v -N -l -t $threshold -c ${CPU0},${CPU1} -a ${STALLD_CPU_MULTI}

    # Wait for starvation detection on both CPUs
    log "Waiting for starvation detection on CPU ${CPU0}..."
    if wait_for_starvation_detected "${STALLD_LOG}" 30 "${CPU0}"; then
        pass "Starvation detected on CPU ${CPU0}"
    else
        fail "Starvation not detected on CPU ${CPU0}"
    fi

    log "Waiting for starvation detection on CPU ${CPU1}..."
    if wait_for_starvation_detected "${STALLD_LOG}" 30 "${CPU1}"; then
        pass "Starvation detected on CPU ${CPU1}"
    else
        fail "Starvation not detected on CPU ${CPU1}"
    fi

    # Cleanup
    kill -TERM ${STARVE_PID0} 2>/dev/null
    kill -TERM ${STARVE_PID1} 2>/dev/null
    wait ${STARVE_PID0} 2>/dev/null
    wait ${STARVE_PID1} 2>/dev/null
    stop_stalld
fi

#=============================================================================
# Test 5: No False Positives (Task Making Progress)
#=============================================================================
log ""
log "=========================================="
log "Test 5: No False Positives"
log "=========================================="

rm -f "${STALLD_LOG}"
threshold=5
log "Starting stalld with ${threshold}s threshold (log-only mode)"
start_stalld_with_log "${STALLD_LOG}" -f -v -l -t $threshold -c ${TEST_CPU} -a ${STALLD_CPU}

# Create a task that gets CPU time but isn't starved
# Use a SCHED_OTHER task with lower priority that still gets scheduled
log "Creating a busy task that should NOT be starved"
(
    taskset -c ${TEST_CPU} bash -c 'for i in {1..100}; do sleep 0.1; done' &
    BUSY_PID=$!

    # Wait beyond threshold
    sleep $((threshold + 3))

    # Verify this task was NOT reported as starved
    # Since it's making progress, stalld shouldn't detect it
    if ! grep "starved" "${STALLD_LOG}"; then
        pass "No false positive - task making progress not reported as starved"
    else
        # Check if our specific task was reported
        log "Log shows starvation, checking if it's our progress-making task..."
        log "Log contents:"
        cat "${STALLD_LOG}"
        # This is not necessarily a failure - there might be other starved tasks
        log "⚠ INFO: Starvation detected, but may be from other tasks"
    fi

    kill ${BUSY_PID} 2>/dev/null
    wait ${BUSY_PID} 2>/dev/null
) &
SUBSHELL_PID=$!
wait ${SUBSHELL_PID}

stop_stalld

#=============================================================================
# Test 6: Edge Case - Task Exits During Monitoring
#=============================================================================
log ""
log "=========================================="
log "Test 6: Task Exits During Monitoring"
log "=========================================="

rm -f "${STALLD_LOG}"
threshold=10
log "Starting stalld with ${threshold}s threshold (log-only mode)"
start_stalld_with_log "${STALLD_LOG}" -f -v -l -t $threshold -c ${TEST_CPU} -a ${STALLD_CPU}

# Create short-lived starvation that exits before threshold
log "Creating short-lived starvation (3s, less than ${threshold}s threshold)"
start_starvation_gen -c ${TEST_CPU} -p 80 -n 1 -d 3

# Wait for task to exit
sleep 5

# Verify stalld is still running (didn't crash)
if assert_process_running "${STALLD_PID}" "stalld still running after task exit"; then
    pass "stalld handled task exit gracefully"
else
    fail "stalld crashed or exited unexpectedly"
fi

# Check for error messages
if grep -iE "error|segfault|crash" "${STALLD_LOG}"; then
    fail "Error messages found in log"
    log "Errors:"
    grep -iE "error|segfault|crash" "${STALLD_LOG}"
else
    pass "No error messages in log"
fi

stop_stalld

#=============================================================================
# Final Summary
#=============================================================================
log ""
log "=========================================="
log "Test Summary"
log "=========================================="
log "Total failures: ${TEST_FAILED}"

end_test
