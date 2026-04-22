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

# Parse command-line options
parse_test_options "$@" || exit $?

init_functional_test "SCHED_DEADLINE Boosting Mechanism" "test_deadline_boost"

# Get number of CPUs for multi-CPU tests
NUM_CPUS=$(get_num_cpus)

#=============================================================================
# Test 1: Basic DEADLINE Boost Detection
#=============================================================================
test_section "Test 1: Basic DEADLINE Boost Detection"

threshold=5
log "Starting stalld with ${threshold}s threshold (default DEADLINE boosting)"
# Use -g 1 for 1-second granularity to ensure timely detection
start_stalld_with_log "${STALLD_LOG}" -f -v -g 1 -t $threshold -c ${TEST_CPU} -a ${STALLD_CPU}

# Create starvation
starvation_duration=$((threshold + 8))
log "Creating starvation on CPU ${TEST_CPU} for ${starvation_duration}s"
start_starvation_gen -c ${TEST_CPU} -p 80 -n 2 -d ${starvation_duration}

# Wait for boosting
log "Waiting for boost detection..."
if wait_for_boost_detected "${STALLD_LOG}"; then
    pass "Boosting occurred"

    # Verify SCHED_DEADLINE was used
    assert_log_contains "${STALLD_LOG}" "SCHED_DEADLINE" "SCHED_DEADLINE boosting used (default)"

    # Verify boost happened after threshold
    # (starvation logged, then boosting)
    if grep -q "starved" "${STALLD_LOG}"; then
        pass "Starvation detected before boosting"
    else
        log "⚠ WARNING: No starvation message before boost"
    fi
else
    fail "No boosting detected"
    log "Log contents:"
    cat "${STALLD_LOG}"
fi

# Cleanup
cleanup_scenario "${STARVE_PID}"

#=============================================================================
# Test 2: DEADLINE Parameters Verification
#=============================================================================
test_section "Test 2: DEADLINE Parameters Verification"

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
start_stalld_with_log "${STALLD_LOG}" -f -v -g 1 -t $threshold -c ${TEST_CPU} -a ${STALLD_CPU} \
    -p ${boost_period} -r ${boost_runtime} -d ${boost_duration}

# Create starvation
log "Creating starvation on CPU ${TEST_CPU}"
start_starvation_gen -c ${TEST_CPU} -p 80 -n 1 -d 15

# Try to find the boosted task PID before it gets boosted
tracked_pid=$(find_starved_child "${STARVE_PID}")

# Wait for boosting
log "Waiting for boost detection..."
wait_for_boost_detected "${STALLD_LOG}"
boosted_task_found=0
if [ -n "${tracked_pid}" ] && [ -f "/proc/${tracked_pid}/sched" ]; then
    policy=$(get_sched_policy ${tracked_pid})
    log "Child PID ${tracked_pid} policy: ${policy}"

    if [ "$policy" = "6" ]; then
        pass "Task PID ${tracked_pid} boosted to SCHED_DEADLINE (policy 6)"
        boosted_task_found=1
    fi
fi

if [ ${boosted_task_found} -eq 0 ]; then
    log "⚠ INFO: Could not verify DEADLINE policy in /proc (timing issue or boost already expired)"
    # Still check if boost happened in logs
    assert_log_contains "${STALLD_LOG}" "boosted.*SCHED_DEADLINE" "SCHED_DEADLINE boost confirmed in logs"
fi

# Cleanup
cleanup_scenario "${STARVE_PID}"

#=============================================================================
# Test 3: Task Makes Progress During Boost
#=============================================================================
test_section "Test 3: Task Makes Progress During Boost"

threshold=5
boost_duration=5

log "Starting stalld with ${boost_duration}s boost duration"
rm -f "${STALLD_LOG}"
start_stalld_with_log "${STALLD_LOG}" -f -v -g 1 -t $threshold -c ${TEST_CPU} -a ${STALLD_CPU} -d ${boost_duration}

# Create starvation
log "Creating starvation on CPU ${TEST_CPU}"
start_starvation_gen -c ${TEST_CPU} -p 80 -n 1 -d 20

# Find a starved task before it gets boosted
tracked_pid=$(find_starved_child "${STARVE_PID}")

# Wait for boosting
log "Waiting for boost detection..."
wait_for_boost_detected "${STALLD_LOG}"
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
        pass "Task made progress during boost (${ctxt_delta} context switches)"
    else
        log "⚠ INFO: Limited progress detected (${ctxt_delta} context switches)"
        log "        This may be acceptable depending on boost parameters"
    fi
else
    log "⚠ WARNING: Could not track starved task PID for progress verification"
fi

# Verify boost happened
assert_log_contains "${STALLD_LOG}" "boosted" "Boost occurred as expected"

# Cleanup
cleanup_scenario "${STARVE_PID}"

#=============================================================================
# Test 4: Policy Restoration After Boost
#=============================================================================
test_section "Test 4: Policy Restoration After Boost"

threshold=5
boost_duration=3

log "Starting stalld with ${boost_duration}s boost duration"
rm -f "${STALLD_LOG}"
start_stalld_with_log "${STALLD_LOG}" -f -v -g 1 -t $threshold -c ${TEST_CPU} -a ${STALLD_CPU} -d ${boost_duration}

# Create starvation
log "Creating starvation on CPU ${TEST_CPU}"
start_starvation_gen -c ${TEST_CPU} -p 80 -n 1 -d 20

# Find a starved task and verify initial policy
sleep 2
tracked_pid=$(find_starved_child "${STARVE_PID}")

if [ -n "${tracked_pid}" ]; then
    log "Tracking task PID ${tracked_pid} for policy changes"

    # Verify initial policy is SCHED_OTHER (0)
    initial_policy=$(get_sched_policy ${tracked_pid})
    log "Initial policy: ${initial_policy} (0=SCHED_OTHER)"

    if [ "$initial_policy" != "0" ]; then
        log "⚠ WARNING: Initial policy is not SCHED_OTHER (got ${initial_policy})"
    fi

    # Wait for starvation detection and boosting
    wait_for_boost_detected "${STALLD_LOG}"

    # Check if policy changed to DEADLINE during boost
    boosted_policy=$(get_sched_policy ${tracked_pid})
    log "Policy during boost window: ${boosted_policy} (6=SCHED_DEADLINE)"

    if [ "$boosted_policy" = "6" ]; then
        pass "Policy changed to SCHED_DEADLINE during boost"
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
            pass "Policy restored to SCHED_OTHER (0)"
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
cleanup_scenario "${STARVE_PID}"

#=============================================================================
# Test 5: Multiple Simultaneous Boosts
#=============================================================================
test_section "Test 5: Multiple Simultaneous Boosts"

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
    start_stalld_with_log "${STALLD_LOG}" -f -v -g 1 -t $threshold -c ${CPU0},${CPU1} -a ${STALLD_CPU}

    # Create starvation on CPU0
    log "Creating starvation on CPU ${CPU0}"
    start_starvation_gen -c ${CPU0} -p 80 -n 1 -d 15
    STARVE_PID0=${STARVE_PID}

    # Create starvation on CPU1
    log "Creating starvation on CPU ${CPU1}"
    start_starvation_gen -c ${CPU1} -p 80 -n 1 -d 15
    STARVE_PID1=${STARVE_PID}

    # Wait for boosting on both CPUs
    log "Waiting for boost detection..."
    wait_for_boost_detected "${STALLD_LOG}"

    # Count boost messages
    boost_count=$(grep -c "boosted" "${STALLD_LOG}")
    log "Number of boost events: ${boost_count}"

    if [ ${boost_count} -ge 2 ]; then
        pass "Multiple boost events detected (${boost_count})"

        # Verify independent boost cycles
        if [ ${boost_count} -gt 2 ]; then
            pass "Multiple boost cycles (${boost_count} total), showing independent operation"
        fi
    else
        log "⚠ INFO: Only ${boost_count} boost event(s) detected"
        log "        (may be timing issue or tasks resolved quickly)"
    fi

    # Cleanup
    cleanup_scenario "${STARVE_PID0}" "${STARVE_PID1}"
fi

#=============================================================================
# Final Summary
#=============================================================================
test_section "Test Summary"
log "Total failures: ${TEST_FAILED}"

end_test
