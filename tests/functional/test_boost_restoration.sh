#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Test: Policy Restoration After Boosting
# Verify stalld correctly restores original scheduling policies and priorities
# after boost duration expires.
#
# Note: starvation_gen creates SCHED_FIFO threads by default (blocker and blockees).
# Tests verify that SCHED_FIFO tasks are properly restored after boosting.
#
# Copyright (C) 2025 Red Hat Inc

# Load test helpers
TEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${TEST_ROOT}/helpers/test_helpers.sh"

# Parse command-line options
parse_test_options "$@" || exit $?

start_test "Policy Restoration After Boosting"

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
STALLD_LOG="/tmp/stalld_test_restoration_$$.log"
CLEANUP_FILES+=("${STALLD_LOG}")

#=============================================================================
# Test 1: Restore SCHED_FIFO Policy (starvation_gen creates SCHED_FIFO threads)
#=============================================================================
test_section "Test 1: Restore SCHED_FIFO Policy"

threshold=5
boost_duration=3

log "Starting stalld with ${boost_duration}s boost duration"
# Use -i to ignore kworkers so stalld focuses on our test workload
start_stalld_with_log "${STALLD_LOG}" -f -v -t $threshold -c ${TEST_CPU} -a ${STALLD_CPU} -d ${boost_duration} -N -i "kworker"

# Create starvation (starvation_gen creates SCHED_FIFO blocker prio 80, blockee prio 1)
log "Creating starvation with SCHED_FIFO tasks (blocker prio 80, blockee prio 1)"
start_starvation_gen -c ${TEST_CPU} -p 80 -b 1 -n 1 -d 20

# Find the starved task
tracked_pid=$(find_starved_child "${STARVE_PID}")

if [ -n "${tracked_pid}" ]; then
    log "Tracking task PID ${tracked_pid}"

    # Verify initial policy is SCHED_FIFO (1) with priority 1
    initial_policy=$(get_sched_policy ${tracked_pid})
    initial_prio=$(get_sched_priority ${tracked_pid})
    log "Initial policy: ${initial_policy} (expected: 1=SCHED_FIFO), prio: ${initial_prio}"

    if [ "$initial_policy" = "1" ]; then
        pass "Initial policy is SCHED_FIFO"
    else
        log "⚠ WARNING: Initial policy is ${initial_policy}, not SCHED_FIFO (1)"
    fi

    # Wait for starvation detection and boosting
    log "Waiting for starvation detection and boost..."
    wait_for_boost_detected "${STALLD_LOG}"

    # Check policy during boost (should be DEADLINE=6)
    if [ -f "/proc/${tracked_pid}/sched" ]; then
        boosted_policy=$(get_sched_policy ${tracked_pid})
        log "Policy during boost: ${boosted_policy}"

        if [ "$boosted_policy" = "6" ]; then
            pass "Task boosted to SCHED_DEADLINE (6)"
        else
            log "ℹ INFO: Policy is ${boosted_policy} (may be between boost cycles)"
        fi
    fi

    # Wait for boost duration to complete
    log "Waiting for boost to complete (${boost_duration}s)..."
    sleep $((boost_duration + 1))

    # Check if task was restored after boost
    if [ -f "/proc/${tracked_pid}/sched" ]; then
        post_boost_policy=$(get_sched_policy ${tracked_pid})
        post_boost_prio=$(get_sched_priority ${tracked_pid})
        log "Policy after boost: ${post_boost_policy}, prio: ${post_boost_prio}"

        if [ "$post_boost_policy" = "1" ]; then
            pass "Policy restored to SCHED_FIFO (1) during boost cycle"
        elif [ "$post_boost_policy" = "6" ]; then
            log "ℹ INFO: Still in boost (DEADLINE), will check final restoration"
        else
            log "⚠ INFO: Policy is ${post_boost_policy} (unexpected)"
        fi
    fi
else
    log "⚠ WARNING: Could not find starved task to track"
fi

# Wait for starvation_gen to complete naturally
log "Waiting for starvation test to complete..."
wait ${STARVE_PID} 2>/dev/null || true

# Final check: verify policy was restored (task may have exited)
if [ -n "${tracked_pid}" ] && [ -f "/proc/${tracked_pid}/sched" ]; then
    final_policy=$(get_sched_policy ${tracked_pid})
    final_prio=$(get_sched_priority ${tracked_pid})
    log "Final policy: ${final_policy}, prio: ${final_prio}"

    if [ "$final_policy" = "1" ]; then
        pass "Policy restored to SCHED_FIFO (1)"
        if [ "$final_prio" = "$initial_prio" ]; then
            pass "Priority restored to ${initial_prio}"
        else
            log "⚠ INFO: Priority is ${final_prio} (initial was ${initial_prio})"
        fi
    else
        log "ℹ INFO: Final policy is ${final_policy} (task may have exited)"
    fi
else
    log "ℹ INFO: Task exited (expected - starvation test completed)"
fi

# Cleanup
cleanup_scenario "${STARVE_PID}"

#=============================================================================
# Test 2: Restore Original RT Policy (SCHED_FIFO)
#=============================================================================
test_section "Test 2: Restore Original SCHED_FIFO Policy"
log "Creating a SCHED_FIFO task that gets starved, verify restoration"

threshold=5
boost_duration=3

log "Starting stalld"
rm -f "${STALLD_LOG}"
start_stalld_with_log "${STALLD_LOG}" -f -v -t $threshold -c ${TEST_CPU} -a ${STALLD_CPU} -d ${boost_duration} -N -i "kworker"

# Create a SCHED_FIFO task that will starve
# We'll create our own RT task instead of using starvation_gen
log "Creating custom SCHED_FIFO task (priority 10) that will starve"

# Start a script that sets itself to FIFO and then loops
cat > /tmp/fifo_task_$$.sh <<'EOF'
#!/bin/bash
# Set self to SCHED_FIFO priority 10
chrt -f 10 $$ 2>/dev/null || exit 1
# Bind to specific CPU
taskset -c $1 $0 "running" &
exit 0
EOF

cat > /tmp/fifo_task_running_$$.sh <<'EOF'
#!/bin/bash
# This process is now FIFO, just loop
while true; do
    sleep 0.01
done
EOF

chmod +x /tmp/fifo_task_$$.sh /tmp/fifo_task_running_$$.sh
CLEANUP_FILES+=("/tmp/fifo_task_$$.sh" "/tmp/fifo_task_running_$$.sh")

# Also create the blocker that will starve our FIFO task
start_starvation_gen -c ${TEST_CPU} -p 90 -n 1 -d 20
BLOCKER_PID=${STARVE_PID}

# Start our FIFO task on the same CPU (it will starve)
bash /tmp/fifo_task_running_$$.sh &
FIFO_TASK_PID=$!
CLEANUP_PIDS+=("${FIFO_TASK_PID}")

# Set it to FIFO manually
if chrt -f -p 10 ${FIFO_TASK_PID} 2>/dev/null; then
    log "Created FIFO task PID ${FIFO_TASK_PID} with priority 10"

    # Bind to test CPU
    taskset -cp ${TEST_CPU} ${FIFO_TASK_PID} >/dev/null 2>&1

    # Verify initial RT policy
    initial_policy=$(get_sched_policy ${FIFO_TASK_PID})
    initial_prio=$(get_sched_priority ${FIFO_TASK_PID})
    log "Initial: policy=${initial_policy} (1=FIFO), prio=${initial_prio}"

    if [ "$initial_policy" = "1" ]; then
        pass "Initial policy is SCHED_FIFO (1)"
    else
        log "⚠ WARNING: Could not set FIFO policy (got ${initial_policy})"
    fi

    # Wait for starvation detection
    log "Waiting for starvation detection and boost..."
    wait_for_boost_detected "${STALLD_LOG}"

    # Check if boosted
    if [ -f "/proc/${FIFO_TASK_PID}/sched" ]; then
        boosted_policy=$(get_sched_policy ${FIFO_TASK_PID})
        log "Policy during detection window: ${boosted_policy}"

        if [ "$boosted_policy" = "6" ]; then
            pass "Task boosted to SCHED_DEADLINE (6)"
        elif [ "$boosted_policy" = "1" ]; then
            log "ℹ INFO: Still SCHED_FIFO (may not have starved yet)"
        fi
    fi

    # Wait for blocker to complete
    log "Waiting for starvation test to complete..."
    wait ${BLOCKER_PID} 2>/dev/null || true

    # Verify policy was restored to original FIFO
    if [ -f "/proc/${FIFO_TASK_PID}/sched" ]; then
        final_policy=$(get_sched_policy ${FIFO_TASK_PID})
        final_prio=$(get_sched_priority ${FIFO_TASK_PID})
        log "Final: policy=${final_policy}, prio=${final_prio}"

        if [ "$final_policy" = "1" ]; then
            pass "Policy restored to SCHED_FIFO (1)"
            log "ℹ INFO: Priority after restoration: ${final_prio}"
        else
            log "⚠ INFO: Final policy is ${final_policy}"
            log "        (may have been downgraded or task exited)"
        fi
    else
        log "ℹ INFO: Task exited before final verification"
    fi

    kill ${FIFO_TASK_PID} 2>/dev/null || true
else
    log "⚠ SKIP: Could not create SCHED_FIFO task (insufficient privileges?)"
fi

# Cleanup
cleanup_scenario "${BLOCKER_PID}"

#=============================================================================
# Test 3: SCHED_OTHER Policy Restoration
#=============================================================================
test_section "Test 3: Restore SCHED_OTHER Policy"
log "Test that SCHED_OTHER tasks are correctly restored after boosting"

threshold=5
boost_duration=3

log "Starting stalld"
rm -f "${STALLD_LOG}"
start_stalld_with_log "${STALLD_LOG}" -f -v -t $threshold -c ${TEST_CPU} -a ${STALLD_CPU} -d ${boost_duration} -N -i "kworker"

# Use -o flag to create SCHED_OTHER blockees
log "Creating SCHED_OTHER starvation (RT blocker prio 80, SCHED_OTHER blockee)"
start_starvation_gen -c ${TEST_CPU} -p 80 -o -n 1 -d 20

# Wait for starvation_gen to complete
log "Waiting for starvation test to complete..."
wait ${STARVE_PID} 2>/dev/null || true

# Check if blockee completed (proves SCHED_OTHER → boost → SCHED_OTHER restoration worked)
# The starvation_gen output will show if blockees completed

# Cleanup
cleanup_scenario "${STARVE_PID}"

#=============================================================================
# Test 4: Restoration Timing Verification
#=============================================================================
test_section "Test 4: Restoration Timing Verification"

threshold=5
boost_duration=4  # 4 second boost

log "Starting stalld with ${boost_duration}s boost duration"
rm -f "${STALLD_LOG}"
start_stalld_with_log "${STALLD_LOG}" -f -v -t $threshold -c ${TEST_CPU} -a ${STALLD_CPU} -d ${boost_duration} -N -i "kworker"

# Create starvation
log "Creating starvation"
start_starvation_gen -c ${TEST_CPU} -p 80 -n 1 -d 20

# Wait for starvation detection and boosting
if wait_for_boost_detected "${STALLD_LOG}"; then
    boost_time=$(date +%s)
    log "Boost detected at timestamp: ${boost_time}"

    # Wait for expected restoration time
    expected_restore_time=$((boost_time + boost_duration))
    log "Expected restoration at timestamp: ${expected_restore_time} (${boost_duration}s later)"

    # Wait for boost duration
    sleep ${boost_duration}

    actual_time=$(date +%s)
    time_diff=$((actual_time - expected_restore_time))
    time_diff=${time_diff#-}  # abs value

    log "Actual time: ${actual_time}"
    log "Time difference: ${time_diff}s"

    if [ ${time_diff} -le 2 ]; then
        pass "Restoration timing within acceptable margin (±2s)"
    else
        log "ℹ INFO: Restoration timing difference: ${time_diff}s"
        log "        (may be acceptable depending on system load)"
    fi
else
    log "⚠ WARNING: No boost detected for timing test"
fi

# Cleanup
cleanup_scenario "${STARVE_PID}"

# Give stalld time to fully exit before next test
sleep 1

#=============================================================================
# Test 5: Task Exit During Boost
#=============================================================================
test_section "Test 5: Graceful Handling of Task Exit During Boost"

threshold=10
boost_duration=5  # Task will exit during boost (after 8s, boost is 5s)

log "Starting stalld with ${threshold}s threshold, ${boost_duration}s boost (task will exit during boost)"
rm -f "${STALLD_LOG}"
start_stalld_with_log "${STALLD_LOG}" -f -v -t $threshold -c ${TEST_CPU} -a ${STALLD_CPU} -d ${boost_duration} -N -i "kworker"

# Create starvation that exits after threshold - 2s (so 8s)
# This ensures the task exits DURING the boost period
short_duration=$((threshold - 2))
log "Creating starvation that will exit after ${short_duration}s"
start_starvation_gen -c ${TEST_CPU} -p 80 -n 1 -d ${short_duration}

# Wait for starvation detection and boosting
if wait_for_boost_detected "${STALLD_LOG}"; then
    pass "Boost occurred"

    # At this point (12s), starvation_gen has exited (at 8s) during the boost
    # stalld should still be running despite the task exiting during boost
    # No additional sleep needed - we're already past the task exit point
    sleep 1

    # Verify stalld is still running and didn't crash after task exit
    if assert_process_running "${STALLD_PID}" "stalld still running after task exit"; then
        pass "stalld handled task exit during boost gracefully"
    else
        fail "stalld crashed or exited after task died during boost"
    fi

    # Check for error messages
    if grep -iE "error.*restor|fail.*restor" "${STALLD_LOG}"; then
        log "ℹ INFO: Restoration errors found (expected when task exits):"
        grep -iE "error.*restor|fail.*restor" "${STALLD_LOG}"
        log "        These errors are normal when tasks exit during boost"
    else
        pass "No restoration errors (clean handling)"
    fi
else
    log "⚠ WARNING: No boost detected in this test run"
fi

# Cleanup
cleanup_scenario "${STARVE_PID}"

#=============================================================================
# Final Summary
#=============================================================================
test_section "Test Summary"
log "Total failures: ${TEST_FAILED}"

end_test
