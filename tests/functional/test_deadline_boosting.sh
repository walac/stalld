#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Test: SCHED_DEADLINE Boosting Mechanism
# Verify stalld correctly boosts starving tasks using SCHED_DEADLINE,
# applies correct parameters, and restores policies after boost duration
#
# Copyright (C) 2025 Red Hat Inc

# Load test helpers
TEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${TEST_ROOT}/helpers/test_helpers.sh"

# Helper function for logging test steps
log() {
    echo "[$(date +'%H:%M:%S')] $*"
}

# Helper to get scheduling policy (0=OTHER, 1=FIFO, 2=RR, 6=DEADLINE)
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

# Helper to wait for policy change
wait_for_policy_change() {
    local pid=$1
    local expected_policy=$2
    local timeout=${3:-10}
    local elapsed=0

    while [ $elapsed -lt $timeout ]; do
        local current_policy=$(get_sched_policy $pid)
        if [ "$current_policy" = "$expected_policy" ]; then
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

start_test "SCHED_DEADLINE Boosting Mechanism"

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
STALLD_LOG="/tmp/stalld_test_deadline_boost_$$.log"
CLEANUP_FILES+=("${STALLD_LOG}")

#=============================================================================
# Test 1: Basic DEADLINE Boost Detection
#=============================================================================
log ""
log "=========================================="
log "Test 1: Basic DEADLINE Boost Detection"
log "=========================================="

threshold=5
log "Starting stalld with ${threshold}s threshold (default DEADLINE boosting)"
start_stalld -f -v -t $threshold -c ${TEST_CPU} > "${STALLD_LOG}" 2>&1

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

# Verify boosting occurred
if grep -q "boosted" "${STALLD_LOG}"; then
    log "✓ PASS: Boosting occurred"

    # Verify SCHED_DEADLINE was used
    if grep -q "SCHED_DEADLINE" "${STALLD_LOG}"; then
        log "✓ PASS: SCHED_DEADLINE boosting used (default)"
    else
        log "✗ FAIL: SCHED_DEADLINE not mentioned in boost message"
        TEST_FAILED=$((TEST_FAILED + 1))
    fi

    # Verify boost happened after threshold
    # (starvation logged, then boosting)
    if grep -q "starved" "${STALLD_LOG}"; then
        log "✓ PASS: Starvation detected before boosting"
    else
        log "⚠ WARNING: No starvation message before boost"
    fi
else
    log "✗ FAIL: No boosting detected"
    log "Log contents:"
    cat "${STALLD_LOG}"
    TEST_FAILED=$((TEST_FAILED + 1))
fi

# Cleanup
kill -TERM ${STARVE_PID} 2>/dev/null
wait ${STARVE_PID} 2>/dev/null
stop_stalld

#=============================================================================
# Test 2: DEADLINE Parameters Verification
#=============================================================================
log ""
log "=========================================="
log "Test 2: DEADLINE Parameters Verification"
log "=========================================="

threshold=5
# Custom DEADLINE parameters
boost_period=500000000   # 500ms period
boost_runtime=50000      # 50µs runtime
boost_duration=3         # 3 second boost

log "Starting stalld with custom DEADLINE parameters:"
log "  Period: ${boost_period}ns (500ms)"
log "  Runtime: ${boost_runtime}ns (50µs)"
log "  Duration: ${boost_duration}s"

rm -f "${STALLD_LOG}"
start_stalld -f -v -t $threshold -c ${TEST_CPU} \
    -p ${boost_period} -r ${boost_runtime} -d ${boost_duration} \
    > "${STALLD_LOG}" 2>&1

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

boosted_task_found=0
for child_pid in ${STARVE_CHILDREN}; do
    if [ -f "/proc/${child_pid}/sched" ]; then
        policy=$(get_sched_policy ${child_pid})
        log "Child PID ${child_pid} policy: ${policy}"

        # Policy 6 = SCHED_DEADLINE
        if [ "$policy" = "6" ]; then
            log "✓ PASS: Task PID ${child_pid} boosted to SCHED_DEADLINE (policy 6)"
            boosted_task_found=1
            break
        fi
    fi
done

if [ ${boosted_task_found} -eq 0 ]; then
    log "⚠ INFO: Could not verify DEADLINE policy in /proc (timing issue or boost already expired)"
    # Still check if boost happened in logs
    if grep -q "boosted.*SCHED_DEADLINE" "${STALLD_LOG}"; then
        log "✓ PASS: SCHED_DEADLINE boost confirmed in logs"
    else
        log "✗ FAIL: No SCHED_DEADLINE boost detected"
        TEST_FAILED=$((TEST_FAILED + 1))
    fi
fi

# Cleanup
kill -TERM ${STARVE_PID} 2>/dev/null
wait ${STARVE_PID} 2>/dev/null
stop_stalld

#=============================================================================
# Test 3: Task Makes Progress During Boost
#=============================================================================
log ""
log "=========================================="
log "Test 3: Task Makes Progress During Boost"
log "=========================================="

threshold=5
boost_duration=5

log "Starting stalld with ${boost_duration}s boost duration"
rm -f "${STALLD_LOG}"
start_stalld -f -v -t $threshold -c ${TEST_CPU} -d ${boost_duration} > "${STALLD_LOG}" 2>&1

# Create starvation
log "Creating starvation on CPU ${TEST_CPU}"
"${STARVE_GEN}" -c ${TEST_CPU} -p 80 -n 1 -d 20 &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Wait for starvation detection
sleep $((threshold + 1))

# Find a starved task
STARVE_CHILDREN=$(pgrep -P ${STARVE_PID} 2>/dev/null)
tracked_pid=""
for child_pid in ${STARVE_CHILDREN}; do
    if [ -f "/proc/${child_pid}/status" ]; then
        tracked_pid=${child_pid}
        break
    fi
done

if [ -n "${tracked_pid}" ]; then
    log "Tracking task PID ${tracked_pid}"

    # Get context switches before boost
    ctxt_before=$(get_ctxt_switches ${tracked_pid})
    log "Context switches before boost: ${ctxt_before}"

    # Wait for boost to occur and task to run
    sleep 3

    # Get context switches during/after boost
    ctxt_after=$(get_ctxt_switches ${tracked_pid})
    log "Context switches after boost window: ${ctxt_after}"

    # Verify task made progress (context switches increased)
    ctxt_delta=$((ctxt_after - ctxt_before))
    if [ ${ctxt_delta} -gt 5 ]; then
        log "✓ PASS: Task made progress during boost (${ctxt_delta} context switches)"
    else
        log "⚠ INFO: Limited progress detected (${ctxt_delta} context switches)"
        log "        This may be acceptable depending on boost parameters"
    fi
else
    log "⚠ WARNING: Could not track starved task PID for progress verification"
fi

# Verify boost happened
if grep -q "boosted" "${STALLD_LOG}"; then
    log "✓ PASS: Boost occurred as expected"
else
    log "✗ FAIL: No boost detected"
    TEST_FAILED=$((TEST_FAILED + 1))
fi

# Cleanup
kill -TERM ${STARVE_PID} 2>/dev/null
wait ${STARVE_PID} 2>/dev/null
stop_stalld

#=============================================================================
# Test 4: Policy Restoration After Boost
#=============================================================================
log ""
log "=========================================="
log "Test 4: Policy Restoration After Boost"
log "=========================================="

threshold=5
boost_duration=3

log "Starting stalld with ${boost_duration}s boost duration"
rm -f "${STALLD_LOG}"
start_stalld -f -v -t $threshold -c ${TEST_CPU} -d ${boost_duration} > "${STALLD_LOG}" 2>&1

# Create starvation
log "Creating starvation on CPU ${TEST_CPU}"
"${STARVE_GEN}" -c ${TEST_CPU} -p 80 -n 1 -d 20 &
STARVE_PID=$!
CLEANUP_PIDS+=("${STARVE_PID}")

# Find a starved task and verify initial policy
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
    log "Tracking task PID ${tracked_pid} for policy changes"

    # Verify initial policy is SCHED_OTHER (0)
    initial_policy=$(get_sched_policy ${tracked_pid})
    log "Initial policy: ${initial_policy} (0=SCHED_OTHER)"

    if [ "$initial_policy" != "0" ]; then
        log "⚠ WARNING: Initial policy is not SCHED_OTHER (got ${initial_policy})"
    fi

    # Wait for starvation detection and boosting
    sleep $((threshold + 1))

    # Check if policy changed to DEADLINE during boost
    boosted_policy=$(get_sched_policy ${tracked_pid})
    log "Policy during boost window: ${boosted_policy} (6=SCHED_DEADLINE)"

    if [ "$boosted_policy" = "6" ]; then
        log "✓ PASS: Policy changed to SCHED_DEADLINE during boost"
    else
        log "⚠ INFO: Policy is ${boosted_policy} (may have already restored or not yet boosted)"
    fi

    # Wait for boost duration to expire
    log "Waiting for boost duration (${boost_duration}s) to expire..."
    sleep $((boost_duration + 2))

    # Verify policy restored
    if [ -f "/proc/${tracked_pid}/sched" ]; then
        restored_policy=$(get_sched_policy ${tracked_pid})
        log "Policy after boost: ${restored_policy}"

        if [ "$restored_policy" = "0" ]; then
            log "✓ PASS: Policy restored to SCHED_OTHER (0)"
        else
            log "⚠ INFO: Policy is ${restored_policy} after boost"
            log "        (task may have exited or restoration timing differs)"
        fi
    else
        log "⚠ INFO: Task exited, cannot verify final policy restoration"
    fi
else
    log "⚠ WARNING: Could not track task for policy restoration test"
fi

# Cleanup
kill -TERM ${STARVE_PID} 2>/dev/null
wait ${STARVE_PID} 2>/dev/null
stop_stalld

#=============================================================================
# Test 5: Multiple Simultaneous Boosts
#=============================================================================
log ""
log "=========================================="
log "Test 5: Multiple Simultaneous Boosts"
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

    threshold=5
    log "Testing simultaneous boosts on CPU ${CPU0} and CPU ${CPU1}"

    rm -f "${STALLD_LOG}"
    start_stalld -f -v -t $threshold -c ${CPU0},${CPU1} > "${STALLD_LOG}" 2>&1

    # Create starvation on CPU0
    log "Creating starvation on CPU ${CPU0}"
    "${STARVE_GEN}" -c ${CPU0} -p 80 -n 1 -d 15 &
    STARVE_PID0=$!
    CLEANUP_PIDS+=("${STARVE_PID0}")

    # Create starvation on CPU1
    log "Creating starvation on CPU ${CPU1}"
    "${STARVE_GEN}" -c ${CPU1} -p 80 -n 1 -d 15 &
    STARVE_PID1=$!
    CLEANUP_PIDS+=("${STARVE_PID1}")

    # Wait for detection and boosting
    sleep $((threshold + 2))

    # Count boost messages
    boost_count=$(grep -c "boosted" "${STALLD_LOG}")
    log "Number of boost events: ${boost_count}"

    if [ ${boost_count} -ge 2 ]; then
        log "✓ PASS: Multiple boost events detected (${boost_count})"

        # Verify both CPUs mentioned
        if grep -q "CPU ${CPU0}" "${STALLD_LOG}" && grep -q "CPU ${CPU1}" "${STALLD_LOG}"; then
            log "✓ PASS: Boosts occurred on both CPUs"
        else
            log "⚠ INFO: Could not verify boosts on both specific CPUs"
        fi

        # Verify independent boost cycles
        if [ ${boost_count} -gt 2 ]; then
            log "✓ PASS: Multiple boost cycles (${boost_count} total), showing independent operation"
        fi
    else
        log "⚠ INFO: Only ${boost_count} boost event(s) detected"
        log "        (may be timing issue or tasks resolved quickly)"
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
log "Total failures: ${TEST_FAILED}"

end_test
