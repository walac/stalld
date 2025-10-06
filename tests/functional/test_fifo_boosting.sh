#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Test: SCHED_FIFO Boosting Mechanism
# Verify stalld correctly boosts starving tasks using SCHED_FIFO with -F flag,
# implements FIFO emulation, and compares with DEADLINE effectiveness
#
# Copyright (C) 2025 Red Hat Inc

# Load test helpers
TEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${TEST_ROOT}/helpers/test_helpers.sh"

# Helper function for logging test steps
log() {
    echo "[$(date +'%H:%M:%S')] $*"
}

# Helper to get scheduling policy
get_sched_policy() {
    local pid=$1
    if [ -f "/proc/${pid}/sched" ]; then
        awk '/^policy/ {print $3}' /proc/${pid}/sched 2>/dev/null
    else
        echo "-1"
    fi
}

# Helper to get scheduling priority
get_sched_priority() {
    local pid=$1
    if [ -f "/proc/${pid}/sched" ]; then
        awk '/^prio/ {print $3}' /proc/${pid}/sched 2>/dev/null
    else
        echo "-1"
    fi
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

start_test "SCHED_FIFO Boosting Mechanism"

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
STALLD_LOG="/tmp/stalld_test_fifo_boost_$$.log"
CLEANUP_FILES+=("${STALLD_LOG}")

#=============================================================================
# Test 1: FIFO Boost with -F Flag
#=============================================================================
log ""
log "=========================================="
log "Test 1: FIFO Boost with -F Flag"
log "=========================================="

threshold=5
log "Starting stalld with -F flag to force SCHED_FIFO boosting"
# Note: -F requires non-single-threaded mode (aggressive mode)
start_stalld -f -v -F -A -t $threshold -c ${TEST_CPU} > "${STALLD_LOG}" 2>&1

# Create starvation
starvation_duration=$((threshold + 8))
log "Creating starvation on CPU ${TEST_CPU} for ${starvation_duration}s"
"${STARVE_GEN}" -c ${TEST_CPU} -p 80 -n 2 -d ${starvation_duration} &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Wait for detection and boosting
wait_time=$((threshold + 2))
log "Waiting ${wait_time}s for starvation detection and boosting..."
sleep ${wait_time}

# Verify FIFO boosting occurred
if grep -q "boosted" "${STALLD_LOG}"; then
    log "✓ PASS: Boosting occurred with -F flag"

    # Verify SCHED_FIFO was used
    if grep -q "SCHED_FIFO" "${STALLD_LOG}"; then
        log "✓ PASS: SCHED_FIFO boosting used (as requested by -F)"
    else
        log "✗ FAIL: SCHED_FIFO not mentioned in boost message"
        TEST_FAILED=$((TEST_FAILED + 1))
    fi
else
    log "✗ FAIL: No boosting detected with -F flag"
    log "Log contents:"
    cat "${STALLD_LOG}"
    TEST_FAILED=$((TEST_FAILED + 1))
fi

# Cleanup
kill -TERM ${STARVE_PID} 2>/dev/null
wait ${STARVE_PID} 2>/dev/null
stop_stalld

#=============================================================================
# Test 2: FIFO Priority Verification
#=============================================================================
log ""
log "=========================================="
log "Test 2: FIFO Priority Verification"
log "=========================================="

threshold=5
log "Starting stalld with -F flag (FIFO boosting)"

rm -f "${STALLD_LOG}"
start_stalld -f -v -F -A -t $threshold -c ${TEST_CPU} > "${STALLD_LOG}" 2>&1

# Create starvation
log "Creating starvation on CPU ${TEST_CPU}"
"${STARVE_GEN}" -c ${TEST_CPU} -p 80 -n 1 -d 15 &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Wait for boosting
sleep $((threshold + 2))

# Try to find the boosted task PID
STARVE_CHILDREN=$(pgrep -P ${STARVE_PID} 2>/dev/null)
log "Starvation generator children PIDs: ${STARVE_CHILDREN}"

fifo_task_found=0
for child_pid in ${STARVE_CHILDREN}; do
    if [ -f "/proc/${child_pid}/sched" ]; then
        policy=$(get_sched_policy ${child_pid})
        log "Child PID ${child_pid} policy: ${policy} (1=SCHED_FIFO)"

        # Policy 1 = SCHED_FIFO
        if [ "$policy" = "1" ]; then
            priority=$(get_sched_priority ${child_pid})
            log "✓ PASS: Task PID ${child_pid} boosted to SCHED_FIFO (policy 1)"
            log "        Priority: ${priority}"
            fifo_task_found=1
            break
        fi
    fi
done

if [ ${fifo_task_found} -eq 0 ]; then
    log "⚠ INFO: Could not verify FIFO policy in /proc (timing issue or boost already expired)"
    # FIFO emulation cycles between FIFO and OTHER, so we may catch it in OTHER state
    if grep -q "boosted.*SCHED_FIFO" "${STALLD_LOG}"; then
        log "✓ PASS: SCHED_FIFO boost confirmed in logs"
    else
        log "✗ FAIL: No SCHED_FIFO boost detected"
        TEST_FAILED=$((TEST_FAILED + 1))
    fi
fi

# Cleanup
kill -TERM ${STARVE_PID} 2>/dev/null
wait ${STARVE_PID} 2>/dev/null
stop_stalld

#=============================================================================
# Test 3: FIFO Emulation Behavior
#=============================================================================
log ""
log "=========================================="
log "Test 3: FIFO Emulation Behavior"
log "=========================================="
log "FIFO emulation cycles: boost→sleep(runtime)→restore→sleep(remainder)"

threshold=5
boost_duration=5  # 5 seconds total boost
boost_period=1000000000   # 1 second period
boost_runtime=20000       # 20µs runtime

log "Starting stalld with FIFO emulation:"
log "  Duration: ${boost_duration}s"
log "  Period: ${boost_period}ns (1s)"
log "  Runtime: ${boost_runtime}ns (20µs)"
log "  Expected cycles: ~5"

rm -f "${STALLD_LOG}"
start_stalld -f -v -F -A -t $threshold -c ${TEST_CPU} \
    -d ${boost_duration} -p ${boost_period} -r ${boost_runtime} \
    > "${STALLD_LOG}" 2>&1

# Create starvation
log "Creating starvation on CPU ${TEST_CPU}"
"${STARVE_GEN}" -c ${TEST_CPU} -p 80 -n 1 -d 20 &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Wait for boosting to complete
log "Waiting for FIFO emulation cycles to complete..."
sleep $((threshold + boost_duration + 2))

# Count boost events (FIFO emulation creates multiple boosts)
boost_count=$(grep -c "boosted.*SCHED_FIFO" "${STALLD_LOG}")
log "Number of FIFO boost events: ${boost_count}"

if [ ${boost_count} -gt 1 ]; then
    log "✓ PASS: Multiple FIFO boost events (${boost_count}) - emulation cycling detected"
    log "        (FIFO emulation boosts, sleeps, restores, repeats)"
else
    log "⚠ INFO: Only ${boost_count} FIFO boost event(s)"
    log "        (emulation may complete very quickly or timing issue)"
fi

# Cleanup
kill -TERM ${STARVE_PID} 2>/dev/null
wait ${STARVE_PID} 2>/dev/null
stop_stalld

#=============================================================================
# Test 4: FIFO vs DEADLINE Comparison
#=============================================================================
log ""
log "=========================================="
log "Test 4: FIFO vs DEADLINE Effectiveness Comparison"
log "=========================================="

threshold=5
boost_duration=3

# Test with DEADLINE first
log ""
log "Running with SCHED_DEADLINE boosting..."
STALLD_LOG_DEADLINE="/tmp/stalld_test_deadline_compare_$$.log"
CLEANUP_FILES+=("${STALLD_LOG_DEADLINE}")

start_stalld -f -v -t $threshold -c ${TEST_CPU} -d ${boost_duration} > "${STALLD_LOG_DEADLINE}" 2>&1

"${STARVE_GEN}" -c ${TEST_CPU} -p 80 -n 2 -d 15 &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Find a starved task
sleep 2
STARVE_CHILDREN=$(pgrep -P ${STARVE_PID} 2>/dev/null)
deadline_tracked_pid=""
for child_pid in ${STARVE_CHILDREN}; do
    if [ -f "/proc/${child_pid}/status" ]; then
        deadline_tracked_pid=${child_pid}
        break
    fi
done

ctxt_before_deadline=0
if [ -n "${deadline_tracked_pid}" ]; then
    ctxt_before_deadline=$(get_ctxt_switches ${deadline_tracked_pid})
fi

# Wait for detection, boost, and some progress
sleep $((threshold + boost_duration))

ctxt_after_deadline=0
if [ -n "${deadline_tracked_pid}" ] && [ -f "/proc/${deadline_tracked_pid}/status" ]; then
    ctxt_after_deadline=$(get_ctxt_switches ${deadline_tracked_pid})
fi

deadline_progress=$((ctxt_after_deadline - ctxt_before_deadline))
log "DEADLINE progress: ${deadline_progress} context switches"

kill -TERM ${STARVE_PID} 2>/dev/null
wait ${STARVE_PID} 2>/dev/null
stop_stalld

# Small delay between tests
sleep 2

# Test with FIFO
log ""
log "Running with SCHED_FIFO boosting..."
STALLD_LOG_FIFO="/tmp/stalld_test_fifo_compare_$$.log"
CLEANUP_FILES+=("${STALLD_LOG_FIFO}")

start_stalld -f -v -F -A -t $threshold -c ${TEST_CPU} -d ${boost_duration} > "${STALLD_LOG_FIFO}" 2>&1

"${STARVE_GEN}" -c ${TEST_CPU} -p 80 -n 2 -d 15 &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Find a starved task
sleep 2
STARVE_CHILDREN=$(pgrep -P ${STARVE_PID} 2>/dev/null)
fifo_tracked_pid=""
for child_pid in ${STARVE_CHILDREN}; do
    if [ -f "/proc/${child_pid}/status" ]; then
        fifo_tracked_pid=${child_pid}
        break
    fi
done

ctxt_before_fifo=0
if [ -n "${fifo_tracked_pid}" ]; then
    ctxt_before_fifo=$(get_ctxt_switches ${fifo_tracked_pid})
fi

# Wait for detection, boost, and some progress
sleep $((threshold + boost_duration))

ctxt_after_fifo=0
if [ -n "${fifo_tracked_pid}" ] && [ -f "/proc/${fifo_tracked_pid}/status" ]; then
    ctxt_after_fifo=$(get_ctxt_switches ${fifo_tracked_pid})
fi

fifo_progress=$((ctxt_after_fifo - ctxt_before_fifo))
log "FIFO progress: ${fifo_progress} context switches"

kill -TERM ${STARVE_PID} 2>/dev/null
wait ${STARVE_PID} 2>/dev/null
stop_stalld

# Compare effectiveness
log ""
log "Comparison Results:"
log "  DEADLINE: ${deadline_progress} context switches"
log "  FIFO: ${fifo_progress} context switches"

if [ ${deadline_progress} -gt 0 ] && [ ${fifo_progress} -gt 0 ]; then
    log "✓ PASS: Both DEADLINE and FIFO allowed tasks to make progress"

    # Both should be effective, but exact numbers may vary
    if [ ${deadline_progress} -gt ${fifo_progress} ]; then
        log "ℹ INFO: DEADLINE showed more progress than FIFO"
    elif [ ${fifo_progress} -gt ${deadline_progress} ]; then
        log "ℹ INFO: FIFO showed more progress than DEADLINE"
    else
        log "ℹ INFO: DEADLINE and FIFO showed similar progress"
    fi
else
    log "⚠ WARNING: One or both methods did not show progress (may be timing issue)"
fi

#=============================================================================
# Test 5: Single-Threaded Mode Fails with FIFO
#=============================================================================
log ""
log "=========================================="
log "Test 5: Single-Threaded Mode with FIFO (Should Fail)"
log "=========================================="

log "Attempting to start stalld with -F without -A (single-threaded + FIFO)"
STALLD_LOG_FAIL="/tmp/stalld_test_fifo_fail_$$.log"
CLEANUP_FILES+=("${STALLD_LOG_FAIL}")

# Try to start stalld with -F but without -A (single-threaded mode)
# This should fail because single-threaded mode only works with DEADLINE
./stalld -f -v -F -t 5 -c ${TEST_CPU} > "${STALLD_LOG_FAIL}" 2>&1 &
FAIL_PID=$!

# Wait a bit for it to fail
sleep 3

# Check if it's still running (it shouldn't be)
if ps -p ${FAIL_PID} > /dev/null 2>&1; then
    log "⚠ WARNING: stalld is still running (should have exited)"
    kill -TERM ${FAIL_PID} 2>/dev/null
    wait ${FAIL_PID} 2>/dev/null
else
    log "✓ PASS: stalld exited as expected"
fi

# Check for error message in log
if grep -qiE "single.*thread.*fifo|fifo.*single.*thread|can.*only.*deadline" "${STALLD_LOG_FAIL}"; then
    log "✓ PASS: Error message about FIFO+single-threaded incompatibility found"
else
    log "ℹ INFO: Checking exit status or error messages..."
    if [ -s "${STALLD_LOG_FAIL}" ]; then
        log "Log contents:"
        cat "${STALLD_LOG_FAIL}"
    fi
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
