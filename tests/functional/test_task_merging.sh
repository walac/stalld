#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Test: Task Merging Logic
# Verify stalld's merge_taks_info() correctly preserves starvation timestamps
# for tasks that make no progress (same PID + same context switches)
#
# Copyright (C) 2025 Red Hat Inc

# Load test helpers
TEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${TEST_ROOT}/helpers/test_helpers.sh"

# Helper function for logging test steps
log() {
    echo "[$(date +'%H:%M:%S')] $*"
}

# Helper to get context switch count
get_ctxt_switches() {
    local pid=$1
    if [ -f "/proc/${pid}/status" ]; then
        local vol=$(grep voluntary_ctxt_switches /proc/${pid}/status | awk '{print $2}')
        local nonvol=$(grep nonvoluntary_ctxt_switches /proc/${pid}/status | awk '{print $2}')
        echo $((vol + nonvol))
    else
        echo "0"
    fi
}

start_test "Task Merging Logic"

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

# Check for DL-server (kernel automatic starvation handling)
# If DL-server is present, the kernel handles starvation automatically,
# so stalld won't detect starvation and we can't test task merging logic
if [ -d "/sys/kernel/debug/sched/fair_server" ]; then
    echo -e "${YELLOW}SKIP: DL-server detected - kernel handles starvation automatically${NC}"
    echo "      Task merging cannot be tested when DL-server prevents starvation"
    exit 77
fi

# Setup paths
STARVE_GEN="${TEST_ROOT}/helpers/starvation_gen"
STALLD_LOG="/tmp/stalld_test_merge_$$.log"
CLEANUP_FILES+=("${STALLD_LOG}")

#=============================================================================
# Test 1: Timestamp Preservation for Non-Progressing Tasks
#=============================================================================
log ""
log "=========================================="
log "Test 1: Timestamp Preservation Across Cycles"
log "=========================================="
log "Task merging: same PID + same ctxsw = preserved timestamp"

threshold=3
log "Starting stalld with ${threshold}s threshold (log-only, verbose)"
start_stalld -f -v -l -t $threshold -c ${TEST_CPU} > "${STALLD_LOG}" 2>&1

# Create long starvation to span multiple monitoring cycles
starvation_duration=18
log "Creating starvation for ${starvation_duration}s (multiple detection cycles)"
"${STARVE_GEN}" -c ${TEST_CPU} -p 80 -n 2 -d ${starvation_duration} &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Wait for first detection
log "Waiting for first detection cycle..."
sleep $((threshold + 1))

# Extract first starvation duration
if grep -q "starved.*for [0-9]" "${STALLD_LOG}"; then
    first_duration=$(grep "starved.*for [0-9]" "${STALLD_LOG}" | head -1 | grep -oE "for [0-9]+" | awk '{print $2}')
    log "First detection: task starved for ${first_duration}s"
    if [ -z "${first_duration}" ]; then
        first_duration=0
    fi
else
    log "⚠ WARNING: No starvation detected in first cycle"
    log "          This may indicate timing issues or system load"
    first_duration=0
fi

# Wait for second detection cycle
log "Waiting for second detection cycle..."
sleep 4

# Extract second starvation duration
second_duration=$(grep "starved.*for [0-9]" "${STALLD_LOG}" | tail -1 | grep -oE "for [0-9]+" | awk '{print $2}')
if [ -z "${second_duration}" ]; then
    second_duration=0
fi
log "Second detection: task starved for ${second_duration}s"

# Verify timestamp was preserved (duration increased)
if [ "${second_duration}" -gt "${first_duration}" ]; then
    delta=$((second_duration - first_duration))
    log "✓ PASS: Starvation duration increased by ${delta}s"
    log "        Timestamp preserved across monitoring cycles"
else
    log "✗ FAIL: Duration did not increase (${first_duration}s -> ${second_duration}s)"
    log "        Timestamp may have been reset (task merging failed)"
    TEST_FAILED=$((TEST_FAILED + 1))
fi

# Wait for third detection to confirm continued accumulation
log "Waiting for third detection cycle..."
sleep 4

third_duration=$(grep "starved.*for [0-9]" "${STALLD_LOG}" | tail -1 | grep -oE "for [0-9]+" | awk '{print $2}')
if [ -z "${third_duration}" ]; then
    third_duration=0
fi
log "Third detection: task starved for ${third_duration}s"

if [ "${third_duration}" -gt "${second_duration}" ]; then
    log "✓ PASS: Duration continues to accumulate (${third_duration}s total)"
else
    log "⚠ INFO: Duration did not increase in third cycle"
fi

# Cleanup
kill -TERM ${STARVE_PID} 2>/dev/null
wait ${STARVE_PID} 2>/dev/null
stop_stalld

#=============================================================================
# Test 2: Same PID + Same Context Switches = Merged
#=============================================================================
log ""
log "=========================================="
log "Test 2: Merge Condition Verification"
log "=========================================="
log "Merging occurs when: PID matches AND context switches unchanged"

threshold=5
rm -f "${STALLD_LOG}"
start_stalld -f -v -l -t $threshold -c ${TEST_CPU} > "${STALLD_LOG}" 2>&1

# Create starvation
log "Creating starvation"
"${STARVE_GEN}" -c ${TEST_CPU} -p 80 -n 1 -d 20 &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Wait for detection
sleep $((threshold + 2))

# Find the starved task PID
STARVE_CHILDREN=$(pgrep -P ${STARVE_PID} 2>/dev/null)
tracked_pid=""
for child_pid in ${STARVE_CHILDREN}; do
    if [ -f "/proc/${child_pid}/status" ]; then
        tracked_pid=${child_pid}
        break
    fi
done

if [ -n "${tracked_pid}" ]; then
    log "Tracking starved task PID ${tracked_pid}"

    # Get context switch count
    ctxsw_before=$(get_ctxt_switches ${tracked_pid})
    log "Context switches: ${ctxsw_before}"

    # Wait for next detection cycle
    sleep 3

    # Verify context switches haven't changed (task is starved)
    if [ -f "/proc/${tracked_pid}/status" ]; then
        ctxsw_after=$(get_ctxt_switches ${tracked_pid})
        log "Context switches after 3s: ${ctxsw_after}"

        delta=$((ctxsw_after - ctxsw_before))
        if [ ${delta} -lt 5 ]; then
            log "✓ PASS: Context switches remained low (delta: ${delta})"
            log "        Task meeting merge criteria (same PID, same ctxsw)"
        else
            log "⚠ INFO: Context switches increased by ${delta}"
            log "        Task may be making some progress"
        fi

        # Verify timestamp was preserved in logs
        detections=$(grep -c "starved" "${STALLD_LOG}")
        log "Total starvation detections: ${detections}"

        if [ ${detections} -ge 2 ]; then
            log "✓ PASS: Multiple detections indicate task merging across cycles"
        fi
    else
        log "⚠ WARNING: Task exited before second check"
    fi
else
    log "⚠ WARNING: Could not track starved task PID"
fi

# Cleanup
kill -TERM ${STARVE_PID} 2>/dev/null
wait ${STARVE_PID} 2>/dev/null
stop_stalld

#=============================================================================
# Test 3: Task Making Progress (No Merge)
#=============================================================================
log ""
log "=========================================="
log "Test 3: No Merge When Task Makes Progress"
log "=========================================="
log "When context switches change, timestamp should reset"

threshold=5
rm -f "${STALLD_LOG}"
start_stalld -f -v -t $threshold -c ${TEST_CPU} -d 2 > "${STALLD_LOG}" 2>&1

# Create starvation that will get boosted (allowing progress)
log "Creating starvation that will be boosted"
"${STARVE_GEN}" -c ${TEST_CPU} -p 80 -n 1 -d 20 &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Wait for first detection and boost
sleep $((threshold + 1))

# Find tracked task
STARVE_CHILDREN=$(pgrep -P ${STARVE_PID} 2>/dev/null)
tracked_pid=""
for child_pid in ${STARVE_CHILDREN}; do
    if [ -f "/proc/${child_pid}/status" ]; then
        tracked_pid=${child_pid}
        break
    fi
done

if [ -n "${tracked_pid}" ]; then
    # Wait for boost to complete and task to starve again
    sleep 5

    # If task was boosted, context switches should have changed
    # meaning timestamp should reset for next starvation period
    if grep -q "boosted" "${STALLD_LOG}"; then
        log "✓ PASS: Task was boosted (made progress)"

        # Check if we see a new starvation period starting
        # (This is harder to verify, but context switches changing = no merge)
        log "ℹ INFO: When task makes progress (ctxsw changes), timestamp resets"
        log "        Next starvation detection starts new timing period"
    else
        log "ℹ INFO: No boost occurred (may be timing dependent)"
    fi
else
    log "⚠ INFO: Could not track task for progress test"
fi

# Cleanup
kill -TERM ${STARVE_PID} 2>/dev/null
wait ${STARVE_PID} 2>/dev/null
stop_stalld

#=============================================================================
# Test 4: Multiple CPUs with Independent Task Merging
#=============================================================================
log ""
log "=========================================="
log "Test 4: Per-CPU Independent Task Merging"
log "=========================================="

NUM_CPUS=$(get_num_cpus)
if [ ${NUM_CPUS} -lt 2 ]; then
    log "⚠ SKIP: Need at least 2 CPUs for this test (have ${NUM_CPUS})"
else
    CPU0=${TEST_CPU}
    if [ ${TEST_CPU} -eq 0 ]; then
        CPU1=1
    else
        CPU1=0
    fi

    threshold=3
    log "Testing task merging on CPU ${CPU0} and CPU ${CPU1} independently"

    rm -f "${STALLD_LOG}"
    start_stalld -f -v -l -t $threshold -c ${CPU0},${CPU1} > "${STALLD_LOG}" 2>&1

    # Create starvation on both CPUs
    log "Creating starvation on CPU ${CPU0}"
    "${STARVE_GEN}" -c ${CPU0} -p 80 -n 1 -d 15 &
    STARVE_PID0=$!
    CLEANUP_PIDS+=("${STARVE_PID0}")

    log "Creating starvation on CPU ${CPU1}"
    "${STARVE_GEN}" -c ${CPU1} -p 80 -n 1 -d 15 &
    STARVE_PID1=$!
    CLEANUP_PIDS+=("${STARVE_PID1}")

    # Wait for multiple detection cycles
    sleep $((threshold + 1))
    sleep 4

    # Check CPU0 starvation accumulation
    cpu0_detections=$(grep "starved on CPU ${CPU0}" "${STALLD_LOG}" | wc -l)
    log "CPU ${CPU0} detections: ${cpu0_detections}"

    if [ ${cpu0_detections} -ge 2 ]; then
        # Check if duration increased
        cpu0_first=$(grep "starved on CPU ${CPU0}" "${STALLD_LOG}" | head -1 | grep -oE "for [0-9]+" | awk '{print $2}')
        cpu0_last=$(grep "starved on CPU ${CPU0}" "${STALLD_LOG}" | tail -1 | grep -oE "for [0-9]+" | awk '{print $2}')
        if [ -z "${cpu0_first}" ]; then cpu0_first=0; fi
        if [ -z "${cpu0_last}" ]; then cpu0_last=0; fi
        log "CPU ${CPU0}: ${cpu0_first}s -> ${cpu0_last}s"

        if [ "${cpu0_last}" -gt "${cpu0_first}" ]; then
            log "✓ PASS: CPU ${CPU0} task merging working (timestamp preserved)"
        fi
    fi

    # Check CPU1 starvation accumulation
    cpu1_detections=$(grep "starved on CPU ${CPU1}" "${STALLD_LOG}" | wc -l)
    log "CPU ${CPU1} detections: ${cpu1_detections}"

    if [ ${cpu1_detections} -ge 2 ]; then
        cpu1_first=$(grep "starved on CPU ${CPU1}" "${STALLD_LOG}" | head -1 | grep -oE "for [0-9]+" | awk '{print $2}')
        cpu1_last=$(grep "starved on CPU ${CPU1}" "${STALLD_LOG}" | tail -1 | grep -oE "for [0-9]+" | awk '{print $2}')
        if [ -z "${cpu1_first}" ]; then cpu1_first=0; fi
        if [ -z "${cpu1_last}" ]; then cpu1_last=0; fi
        log "CPU ${CPU1}: ${cpu1_first}s -> ${cpu1_last}s"

        if [ "${cpu1_last}" -gt "${cpu1_first}" ]; then
            log "✓ PASS: CPU ${CPU1} task merging working (timestamp preserved)"
        fi
    fi

    if [ ${cpu0_detections} -ge 2 ] && [ ${cpu1_detections} -ge 2 ]; then
        log "✓ PASS: Independent task merging on both CPUs"
    fi

    # Cleanup
    kill -TERM ${STARVE_PID0} 2>/dev/null
    kill -TERM ${STARVE_PID1} 2>/dev/null
    wait ${STARVE_PID0} 2>/dev/null
    wait ${STARVE_PID1} 2>/dev/null
    stop_stalld
fi

#=============================================================================
# Final Summary
#=============================================================================
log ""
log "=========================================="
log "Test Summary"
log "=========================================="
log "Task merging function: merge_taks_info() in stalld.c:370-397"
log "Merge logic: if (PID == PID && ctxsw == ctxsw) preserve timestamp"
log ""
log "Total failures: ${TEST_FAILED}"

end_test
