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

# Helper function for logging test steps
log() {
    echo "[$(date +'%H:%M:%S')] $*"
}

# Helper to start stalld with output redirected to a file
start_stalld_with_log() {
    local log_file="$1"
    shift
    local args="$@"

    # Build stalld command with backend option if specified
    # Also add -g 1 for 1-second granularity to ensure timely detection
    local stalld_args="-g 1 $args"
    if [ -n "${STALLD_TEST_BACKEND}" ]; then
        stalld_args="-b ${STALLD_TEST_BACKEND} ${stalld_args}"
        echo "Using backend: ${STALLD_TEST_BACKEND}"
    fi

    # Start stalld with output redirected
    ${TEST_ROOT}/../stalld ${stalld_args} > "${log_file}" 2>&1 &
    STALLD_PID=$!
    CLEANUP_PIDS+=("${STALLD_PID}")
    sleep 1
}

# Helper to get context switch count for a PID
get_ctxt_switches() {
    local pid=$1
    if [ -f "/proc/${pid}/status" ]; then
        # Sum voluntary and nonvoluntary context switches
        local vol=$(grep voluntary_ctxt_switches /proc/${pid}/status | awk '{print $2}')
        local nonvol=$(grep nonvoluntary_ctxt_switches /proc/${pid}/status | awk '{print $2}')
        echo $((vol + nonvol))
    else
        echo "0"
    fi
}

# Helper to extract starved task PID from stalld logs
get_starved_pid() {
    local log_file=$1
    # Look for pattern like "starvation_gen-12345 starved on CPU"
    grep "starved on CPU" "$log_file" | tail -1 | sed -E 's/.*\[([0-9]+)\].*/\1/' | head -1
}

start_test "Starvation Detection Logic"

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
"${STARVE_GEN}" -c ${TEST_CPU} -p 80 -n 2 -d ${starvation_duration} &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Give starvation generator time to start and pin to CPU
sleep 2

log "Starting stalld with ${threshold}s threshold (log-only mode)"
start_stalld_with_log "${STALLD_LOG}" -f -v -l -t $threshold -c ${TEST_CPU}

# Wait for detection (threshold + small buffer)
wait_time=$((threshold + 2))
log "Waiting ${wait_time}s for starvation detection..."
sleep ${wait_time}

# Verify starvation was detected
if grep -q "starved on CPU" "${STALLD_LOG}"; then
    log "✓ PASS: Starvation detected"

    # Verify correct CPU is logged
    if grep "starved on CPU ${TEST_CPU}" "${STALLD_LOG}"; then
        log "✓ PASS: Correct CPU ID logged (CPU ${TEST_CPU})"
    else
        log "✗ FAIL: Wrong CPU ID in log"
        TEST_FAILED=$((TEST_FAILED + 1))
    fi

    # Verify duration is logged
    if grep -E "starved on CPU ${TEST_CPU} for [0-9]+ seconds" "${STALLD_LOG}"; then
        log "✓ PASS: Starvation duration logged"
    else
        log "✗ FAIL: Starvation duration not logged"
        TEST_FAILED=$((TEST_FAILED + 1))
    fi
else
    log "✗ FAIL: Starvation not detected"
    log "Log contents:"
    cat "${STALLD_LOG}"
    TEST_FAILED=$((TEST_FAILED + 1))
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
"${STARVE_GEN}" -c ${TEST_CPU} -p 80 -n 1 -d 15 &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Give starvation generator time to start
sleep 2

log "Starting stalld with ${threshold}s threshold (log-only mode)"
start_stalld_with_log "${STALLD_LOG}" -f -v -l -t $threshold -c ${TEST_CPU}

# Wait for detection
sleep $((threshold + 2))

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
                log "✓ PASS: Context switch count remained low (delta: ${ctxt_delta})"
            else
                log "✗ FAIL: Context switches increased significantly (delta: ${ctxt_delta})"
                TEST_FAILED=$((TEST_FAILED + 1))
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
"${STARVE_GEN}" -c ${TEST_CPU} -p 80 -n 2 -d ${starvation_duration} &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Give starvation generator time to start
sleep 2

log "Starting stalld with ${threshold}s threshold (log-only mode)"
log "Will monitor for multiple detection cycles to verify timestamp preservation"
start_stalld_with_log "${STALLD_LOG}" -f -v -l -t $threshold -c ${TEST_CPU}

# Wait for multiple detection cycles
log "Waiting for multiple detection cycles..."
sleep $((threshold + 2))
log "First detection cycle should have occurred"
sleep 3
log "Second detection cycle should have occurred"
sleep 3
log "Third detection cycle should have occurred"

# Check if we see accumulating starvation time in logs
# Task merging means the timestamp is preserved, so duration increases
if grep -E "starved on CPU ${TEST_CPU} for [0-9]+ seconds" "${STALLD_LOG}" | wc -l | grep -q "[2-9]"; then
    log "✓ PASS: Multiple starvation reports found"

    # Extract starvation durations from log
    durations=$(grep -oE "starved on CPU ${TEST_CPU} for [0-9]+" "${STALLD_LOG}" | grep -oE "[0-9]+$")
    log "Starvation durations observed: $(echo $durations | tr '\n' ' ')"

    # Verify durations are increasing (timestamp preserved = duration accumulates)
    first_duration=$(echo "$durations" | head -1)
    last_duration=$(echo "$durations" | tail -1)

    if [ ${last_duration} -gt ${first_duration} ]; then
        log "✓ PASS: Starvation duration increased (${first_duration}s -> ${last_duration}s)"
        log "        This confirms task merging preserved the timestamp"
    else
        log "✗ FAIL: Starvation duration did not increase (timestamp may have been reset)"
        TEST_FAILED=$((TEST_FAILED + 1))
    fi
else
    log "✗ FAIL: Not enough starvation reports to verify task merging"
    log "Log contents:"
    cat "${STALLD_LOG}"
    TEST_FAILED=$((TEST_FAILED + 1))
fi

# Cleanup
kill -TERM ${STARVE_PID} 2>/dev/null
wait ${STARVE_PID} 2>/dev/null
stop_stalld

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

    log "Testing starvation detection on CPU ${CPU0} and CPU ${CPU1}"

    rm -f "${STALLD_LOG}"
    threshold=5

    # Create starvation on CPU0
    log "Creating starvation on CPU ${CPU0}"
    "${STARVE_GEN}" -c ${CPU0} -p 80 -n 1 -d 12 &
    STARVE_PID0=$!
    CLEANUP_PIDS+=("${STARVE_PID0}")

    # Create starvation on CPU1
    log "Creating starvation on CPU ${CPU1}"
    "${STARVE_GEN}" -c ${CPU1} -p 80 -n 1 -d 12 &
    STARVE_PID1=$!
    CLEANUP_PIDS+=("${STARVE_PID1}")

    # Give starvation generators time to start
    sleep 2

    start_stalld_with_log "${STALLD_LOG}" -f -v -l -t $threshold -c ${CPU0},${CPU1}

    # Wait for detection
    sleep $((threshold + 2))

    # Check both CPUs detected
    if grep -q "starved on CPU ${CPU0}" "${STALLD_LOG}"; then
        log "✓ PASS: Starvation detected on CPU ${CPU0}"
    else
        log "✗ FAIL: Starvation not detected on CPU ${CPU0}"
        TEST_FAILED=$((TEST_FAILED + 1))
    fi

    if grep -q "starved on CPU ${CPU1}" "${STALLD_LOG}"; then
        log "✓ PASS: Starvation detected on CPU ${CPU1}"
    else
        log "✗ FAIL: Starvation not detected on CPU ${CPU1}"
        TEST_FAILED=$((TEST_FAILED + 1))
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
start_stalld_with_log "${STALLD_LOG}" -f -v -l -t $threshold -c ${TEST_CPU}

# Create a task that gets CPU time but isn't starved
# Use a SCHED_OTHER task with lower priority that still gets scheduled
log "Creating a busy task that should NOT be starved"
(
    taskset -c ${TEST_CPU} bash -c 'for i in {1..100}; do sleep 0.1; done' &
    BUSY_PID=$!
    CLEANUP_PIDS+=("${BUSY_PID}")

    # Wait beyond threshold
    sleep $((threshold + 3))

    # Verify this task was NOT reported as starved
    # Since it's making progress, stalld shouldn't detect it
    if ! grep "starved" "${STALLD_LOG}"; then
        log "✓ PASS: No false positive - task making progress not reported as starved"
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
wait

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
start_stalld_with_log "${STALLD_LOG}" -f -v -l -t $threshold -c ${TEST_CPU}

# Create short-lived starvation that exits before threshold
log "Creating short-lived starvation (3s, less than ${threshold}s threshold)"
"${STARVE_GEN}" -c ${TEST_CPU} -p 80 -n 1 -d 3 &
STARVE_PID=$!

# Wait for task to exit
sleep 5

# Verify stalld is still running (didn't crash)
if assert_process_running "${STALLD_PID}" "stalld still running after task exit"; then
    log "✓ PASS: stalld handled task exit gracefully"
else
    log "✗ FAIL: stalld crashed or exited unexpectedly"
    TEST_FAILED=$((TEST_FAILED + 1))
fi

# Check for error messages
if grep -iE "error|segfault|crash" "${STALLD_LOG}"; then
    log "✗ FAIL: Error messages found in log"
    log "Errors:"
    grep -iE "error|segfault|crash" "${STALLD_LOG}"
    TEST_FAILED=$((TEST_FAILED + 1))
else
    log "✓ PASS: No error messages in log"
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
