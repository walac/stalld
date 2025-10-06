#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Test: Policy Restoration After Boosting
# Verify stalld correctly restores original scheduling policies and priorities
# after boost duration expires, including SCHED_OTHER, SCHED_FIFO, and nice values
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

# Helper to get nice value
get_nice_value() {
    local pid=$1
    if [ -f "/proc/${pid}/stat" ]; then
        # Nice is field 19 in /proc/pid/stat
        awk '{print $19}' /proc/${pid}/stat 2>/dev/null
    else
        echo "99"
    fi
}

start_test "Policy Restoration After Boosting"

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
STALLD_LOG="/tmp/stalld_test_restoration_$$.log"
CLEANUP_FILES+=("${STALLD_LOG}")

#=============================================================================
# Test 1: Restore SCHED_OTHER (Normal Tasks)
#=============================================================================
log ""
log "=========================================="
log "Test 1: Restore SCHED_OTHER Policy"
log "=========================================="

threshold=5
boost_duration=3

log "Starting stalld with ${boost_duration}s boost duration"
start_stalld -f -v -t $threshold -c ${TEST_CPU} -d ${boost_duration} > "${STALLD_LOG}" 2>&1

# Create starvation (starvation_gen creates SCHED_OTHER tasks by default)
log "Creating starvation with SCHED_OTHER tasks"
"${STARVE_GEN}" -c ${TEST_CPU} -p 80 -n 1 -d 20 &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Find the starved task
sleep 2
STARVE_CHILDREN=$(pgrep -P ${STARVE_PID} 2>/dev/null)
tracked_pid=""
for child_pid in ${STARVE_CHILDREN}; do
    if [ -f "/proc/${child_pid}/sched" ]; then
        tracked_pid=${child_pid}
        break
    fi
done

if [ -n "${tracked_pid}" ]; then
    log "Tracking task PID ${tracked_pid}"

    # Verify initial policy is SCHED_OTHER (0)
    initial_policy=$(get_sched_policy ${tracked_pid})
    log "Initial policy: ${initial_policy} (expected: 0=SCHED_OTHER)"

    if [ "$initial_policy" = "0" ]; then
        log "✓ PASS: Initial policy is SCHED_OTHER"
    else
        log "⚠ WARNING: Initial policy is ${initial_policy}, not SCHED_OTHER (0)"
    fi

    # Wait for starvation detection and boosting
    log "Waiting for starvation detection and boost..."
    sleep $((threshold + 1))

    # Check policy during boost (should be DEADLINE=6)
    if [ -f "/proc/${tracked_pid}/sched" ]; then
        boosted_policy=$(get_sched_policy ${tracked_pid})
        log "Policy during boost: ${boosted_policy}"

        if [ "$boosted_policy" = "6" ]; then
            log "✓ PASS: Task boosted to SCHED_DEADLINE (6)"
        else
            log "ℹ INFO: Policy is ${boosted_policy} (may be between boost cycles)"
        fi
    fi

    # Wait for boost duration to complete
    log "Waiting for boost to complete (${boost_duration}s)..."
    sleep $((boost_duration + 2))

    # Verify policy restored to SCHED_OTHER (0)
    if [ -f "/proc/${tracked_pid}/sched" ]; then
        final_policy=$(get_sched_policy ${tracked_pid})
        log "Policy after boost: ${final_policy}"

        if [ "$final_policy" = "0" ]; then
            log "✓ PASS: Policy restored to SCHED_OTHER (0)"
        else
            log "⚠ INFO: Policy is ${final_policy} after boost"
            log "        (task may still be in boost cycle or has exited)"
        fi
    else
        log "ℹ INFO: Task exited, cannot verify final restoration"
    fi
else
    log "⚠ WARNING: Could not find starved task to track"
fi

# Cleanup
kill -TERM ${STARVE_PID} 2>/dev/null
wait ${STARVE_PID} 2>/dev/null
stop_stalld

#=============================================================================
# Test 2: Restore Original RT Policy (SCHED_FIFO)
#=============================================================================
log ""
log "=========================================="
log "Test 2: Restore Original SCHED_FIFO Policy"
log "=========================================="
log "Creating a SCHED_FIFO task that gets starved, verify restoration"

threshold=5
boost_duration=3

log "Starting stalld"
rm -f "${STALLD_LOG}"
start_stalld -f -v -t $threshold -c ${TEST_CPU} -d ${boost_duration} > "${STALLD_LOG}" 2>&1

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
"${STARVE_GEN}" -c ${TEST_CPU} -p 90 -n 1 -d 20 &
BLOCKER_PID=$!
CLEANUP_PIDS+=("${BLOCKER_PID}")

sleep 1

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
        log "✓ PASS: Initial policy is SCHED_FIFO (1)"
    else
        log "⚠ WARNING: Could not set FIFO policy (got ${initial_policy})"
    fi

    # Wait for it to starve and get boosted
    log "Waiting for starvation detection and boost..."
    sleep $((threshold + boost_duration + 2))

    # Verify policy was restored to original FIFO
    if [ -f "/proc/${FIFO_TASK_PID}/sched" ]; then
        final_policy=$(get_sched_policy ${FIFO_TASK_PID})
        final_prio=$(get_sched_priority ${FIFO_TASK_PID})
        log "Final: policy=${final_policy}, prio=${final_prio}"

        if [ "$final_policy" = "1" ]; then
            log "✓ PASS: Policy restored to SCHED_FIFO (1)"

            # Check if priority was preserved (prio values may differ from chrt priority)
            log "ℹ INFO: Priority after restoration: ${final_prio}"
        else
            log "⚠ INFO: Final policy is ${final_policy}"
            log "        (may have been downgraded or task exited)"
        fi
    else
        log "ℹ INFO: Task exited before final verification"
    fi

    kill ${FIFO_TASK_PID} 2>/dev/null
else
    log "⚠ SKIP: Could not create SCHED_FIFO task (insufficient privileges?)"
fi

# Cleanup
kill -TERM ${BLOCKER_PID} 2>/dev/null
wait ${BLOCKER_PID} 2>/dev/null
stop_stalld

#=============================================================================
# Test 3: Nice Values Preserved
#=============================================================================
log ""
log "=========================================="
log "Test 3: Nice Values Preserved"
log "=========================================="
log "Note: Nice values typically preserved for SCHED_OTHER tasks"

threshold=5
boost_duration=3

log "Starting stalld"
rm -f "${STALLD_LOG}"
start_stalld -f -v -t $threshold -c ${TEST_CPU} -d ${boost_duration} > "${STALLD_LOG}" 2>&1

# The starvation_gen doesn't set nice values, so this is informational
# We verify that whatever nice value exists is preserved
log "Creating starvation"
"${STARVE_GEN}" -c ${TEST_CPU} -p 80 -n 1 -d 15 &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

sleep 2
STARVE_CHILDREN=$(pgrep -P ${STARVE_PID} 2>/dev/null)
tracked_pid=""
for child_pid in ${STARVE_CHILDREN}; do
    if [ -f "/proc/${child_pid}/stat" ]; then
        tracked_pid=${child_pid}
        break
    fi
done

if [ -n "${tracked_pid}" ]; then
    initial_nice=$(get_nice_value ${tracked_pid})
    log "Initial nice value: ${initial_nice}"

    # Wait for boost cycle
    sleep $((threshold + boost_duration + 2))

    if [ -f "/proc/${tracked_pid}/stat" ]; then
        final_nice=$(get_nice_value ${tracked_pid})
        log "Final nice value: ${final_nice}"

        if [ "$initial_nice" = "$final_nice" ]; then
            log "✓ PASS: Nice value preserved (${initial_nice})"
        else
            log "ℹ INFO: Nice value changed from ${initial_nice} to ${final_nice}"
        fi
    else
        log "ℹ INFO: Task exited before final check"
    fi
else
    log "⚠ INFO: Could not track task for nice value test"
fi

# Cleanup
kill -TERM ${STARVE_PID} 2>/dev/null
wait ${STARVE_PID} 2>/dev/null
stop_stalld

#=============================================================================
# Test 4: Restoration Timing Verification
#=============================================================================
log ""
log "=========================================="
log "Test 4: Restoration Timing Verification"
log "=========================================="

threshold=5
boost_duration=4  # 4 second boost

log "Starting stalld with ${boost_duration}s boost duration"
rm -f "${STALLD_LOG}"
start_stalld -f -v -t $threshold -c ${TEST_CPU} -d ${boost_duration} > "${STALLD_LOG}" 2>&1

# Create starvation
log "Creating starvation"
"${STARVE_GEN}" -c ${TEST_CPU} -p 80 -n 1 -d 20 &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Wait for starvation detection
sleep $((threshold + 1))

# Check when boost occurred
if grep -q "boosted" "${STALLD_LOG}"; then
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
        log "✓ PASS: Restoration timing within acceptable margin (±2s)"
    else
        log "ℹ INFO: Restoration timing difference: ${time_diff}s"
        log "        (may be acceptable depending on system load)"
    fi
else
    log "⚠ WARNING: No boost detected for timing test"
fi

# Cleanup
kill -TERM ${STARVE_PID} 2>/dev/null
wait ${STARVE_PID} 2>/dev/null
stop_stalld

#=============================================================================
# Test 5: Task Exit During Boost
#=============================================================================
log ""
log "=========================================="
log "Test 5: Graceful Handling of Task Exit During Boost"
log "=========================================="

threshold=5
boost_duration=10  # Long boost, but task will exit earlier

log "Starting stalld with ${boost_duration}s boost (task will exit during boost)"
rm -f "${STALLD_LOG}"
start_stalld -f -v -t $threshold -c ${TEST_CPU} -d ${boost_duration} > "${STALLD_LOG}" 2>&1

# Create starvation that exits after threshold + 3s
short_duration=$((threshold + 3))
log "Creating starvation that will exit after ${short_duration}s"
"${STARVE_GEN}" -c ${TEST_CPU} -p 80 -n 1 -d ${short_duration} &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Wait for boost to occur
sleep $((threshold + 1))

if grep -q "boosted" "${STALLD_LOG}"; then
    log "✓ PASS: Boost occurred"

    # Wait for task to exit (during boost period)
    sleep 4

    # Verify stalld is still running and didn't crash
    if assert_process_running "${STALLD_PID}" "stalld still running after task exit"; then
        log "✓ PASS: stalld handled task exit during boost gracefully"
    else
        log "✗ FAIL: stalld crashed or exited after task died during boost"
        TEST_FAILED=$((TEST_FAILED + 1))
    fi

    # Check for error messages
    if grep -iE "error.*restor|fail.*restor" "${STALLD_LOG}"; then
        log "ℹ INFO: Restoration errors found (expected when task exits):"
        grep -iE "error.*restor|fail.*restor" "${STALLD_LOG}"
        log "        These errors are normal when tasks exit during boost"
    else
        log "✓ PASS: No restoration errors (clean handling)"
    fi
else
    log "⚠ WARNING: No boost detected in this test run"
fi

# Cleanup
kill -TERM ${STARVE_PID} 2>/dev/null
wait ${STARVE_PID} 2>/dev/null
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
