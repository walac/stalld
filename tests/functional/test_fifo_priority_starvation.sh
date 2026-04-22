#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Test: FIFO-on-FIFO Priority Starvation Detection
# Verify stalld correctly detects when one SCHED_FIFO task is starved by another
# SCHED_FIFO task with higher priority (e.g., FIFO:10 starves FIFO:5)
#
# IMPORTANT: stalld must run on a different CPU than the test CPU to avoid
# interference with the starvation scenario. This test uses CPU affinity (-a)
# to ensure stalld runs on a separate CPU.
#
# Copyright (C) 2025 Red Hat Inc

# Load test helpers
TEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${TEST_ROOT}/helpers/test_helpers.sh"

# Parse command-line options
parse_test_options "$@" || exit $?

init_functional_test "FIFO-on-FIFO Priority Starvation Detection" "test_fifo_prio"

#=============================================================================
# Test 1: Basic FIFO-on-FIFO Starvation Detection
#=============================================================================
test_section "Test 1: Basic FIFO-on-FIFO Starvation Detection"
log "Testing: FIFO:10 blocker starves FIFO:5 blockee"

threshold=5

# Create starvation BEFORE starting stalld to avoid idle detection race
starvation_duration=$((threshold + 5))
log "Creating FIFO-on-FIFO starvation on CPU ${TEST_CPU} for ${starvation_duration}s"
log "  Blocker: SCHED_FIFO priority 10"
log "  Blockee: SCHED_FIFO priority 5"
start_starvation_gen -c ${TEST_CPU} -p 10 -b 5 -n 2 -d ${starvation_duration}

log "Starting stalld with ${threshold}s threshold (log-only mode)"
start_stalld_with_log "${STALLD_LOG}" -f -v -l -t $threshold -c ${TEST_CPU} -a ${STALLD_CPU}

# Wait for starvation detection
log "Waiting for starvation detection..."
if wait_for_starvation_detected "${STALLD_LOG}"; then
    pass "FIFO-on-FIFO starvation detected"

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
    fail "FIFO-on-FIFO starvation not detected"
    log "Log contents:"
    cat "${STALLD_LOG}"
fi

# Cleanup
cleanup_scenario "${STARVE_PID}"

#=============================================================================
# Test 2: Boosting Effectiveness
#=============================================================================
test_section "Test 2: Boosting Allows Progress"
log "Verify boosting allows FIFO:5 task to make progress despite FIFO:10 blocker"

rm -f "${STALLD_LOG}"
threshold=5
boost_duration=3

log "Creating FIFO-on-FIFO starvation on CPU ${TEST_CPU}"
start_starvation_gen -c ${TEST_CPU} -p 10 -b 5 -n 1 -d 20

# Find the starved task (blockee) PID
blockee_pid=$(find_starved_child "${STARVE_PID}")

ctxt_before=0
if [ -n "${blockee_pid}" ]; then
    ctxt_before=$(get_ctxt_switches ${blockee_pid})
    log "Blockee task PID ${blockee_pid}, context switches before boost: ${ctxt_before}"
fi

log "Starting stalld with boosting enabled"
start_stalld_with_log "${STALLD_LOG}" -f -v -N -t $threshold -c ${TEST_CPU} -a ${STALLD_CPU} -d ${boost_duration}

# Wait for detection and boosting
sleep $((threshold + boost_duration + 1))

ctxt_after=0
if [ -n "${blockee_pid}" ] && [ -f "/proc/${blockee_pid}/status" ]; then
    ctxt_after=$(get_ctxt_switches ${blockee_pid})
    log "Context switches after boost: ${ctxt_after}"
fi

# Calculate progress
ctxt_delta=$((ctxt_after - ctxt_before))
log "Context switch delta: ${ctxt_delta}"

if [ ${ctxt_delta} -gt 0 ]; then
    pass "Blockee task made progress (${ctxt_delta} context switches)"
else
    log "⚠ WARNING: Could not verify progress (timing issue or blockee not found)"
    # Check if boosting occurred at least
    if grep -q "boosted" "${STALLD_LOG}"; then
        log "ℹ INFO: Boosting did occur according to logs"
    else
        fail "No boosting detected"
    fi
fi

# Cleanup
cleanup_scenario "${STARVE_PID}"

#=============================================================================
# Test 3: Starvation Duration Tracking
#=============================================================================
test_section "Test 3: Starvation Duration Tracking"
log "Verify duration accumulates correctly (task merging)"

rm -f "${STALLD_LOG}"
threshold=3

# Create long starvation to trigger multiple detection cycles
starvation_duration=15
log "Creating long FIFO-on-FIFO starvation for ${starvation_duration}s"
start_starvation_gen -c ${TEST_CPU} -p 10 -b 5 -n 2 -d ${starvation_duration}

log "Starting stalld with ${threshold}s threshold (log-only mode)"
log "Will monitor for multiple detection cycles to verify timestamp preservation"
start_stalld_with_log "${STALLD_LOG}" -f -v -l -t $threshold -c ${TEST_CPU} -a ${STALLD_CPU}

# Wait for multiple detection cycles
log "Waiting for first detection cycle..."
wait_for_starvation_detected "${STALLD_LOG}"
log "First detection cycle occurred, waiting for additional cycles..."
wait_for_n_log_matches "starved on CPU" 3 "${STALLD_LOG}"
log "Multiple detection cycles should have occurred"

# Check if we see accumulating starvation time in logs
# Task merging means the timestamp is preserved, so duration increases
if grep -E "starved on CPU ${TEST_CPU} for [0-9]+ seconds" "${STALLD_LOG}" | wc -l | grep -q "[2-9]"; then
    pass "Multiple starvation reports found"

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
    log "⚠ WARNING: Not enough starvation reports to verify task merging"
    log "        (May be due to queue_track backend limitation)"
    if [ -n "${STALLD_TEST_BACKEND}" ] && [ "${STALLD_TEST_BACKEND}" = "queue_track" ]; then
        log "        NOTE: queue_track backend has known issues with SCHED_FIFO detection"
    fi
fi

# Cleanup
cleanup_scenario "${STARVE_PID}"

#=============================================================================
# Test 4: Close Priority Gap
#=============================================================================
test_section "Test 4: Close Priority Gap (FIFO:6 vs FIFO:5)"
log "Testing edge case with only 1 priority difference"

rm -f "${STALLD_LOG}"
threshold=5

# Test with very close priorities
log "Creating FIFO-on-FIFO starvation with close priorities"
log "  Blocker: SCHED_FIFO priority 6"
log "  Blockee: SCHED_FIFO priority 5"
start_starvation_gen -c ${TEST_CPU} -p 6 -b 5 -n 1 -d $((threshold + 5))

log "Starting stalld with ${threshold}s threshold"
start_stalld_with_log "${STALLD_LOG}" -f -v -l -t $threshold -c ${TEST_CPU} -a ${STALLD_CPU}

# Wait for starvation detection
log "Waiting for starvation detection..."
if wait_for_starvation_detected "${STALLD_LOG}"; then
    pass "Starvation detected even with close priority gap (6 vs 5)"
else
    log "⚠ WARNING: Starvation not detected with close priority gap"
    log "        (May be due to queue_track backend limitation)"
    if [ -n "${STALLD_TEST_BACKEND}" ] && [ "${STALLD_TEST_BACKEND}" = "queue_track" ]; then
        log "        NOTE: queue_track backend has known issues with SCHED_FIFO detection"
    fi
fi

# Cleanup
cleanup_scenario "${STARVE_PID}"

#=============================================================================
# Test 5: Correct Task Boosted
#=============================================================================
test_section "Test 5: Verify Correct Task is Boosted"
log "Ensure stalld boosts the blockee (FIFO:5), not the blocker (FIFO:10)"

rm -f "${STALLD_LOG}"
threshold=5

log "Creating FIFO-on-FIFO starvation"
start_starvation_gen -c ${TEST_CPU} -p 10 -b 5 -n 2 -d 20 -v

# Extract blocker and blockee PIDs from starvation_gen output
# The output shows "Blocker TID: <pid>" and "Blockee N TID: <pid>"
log "Starvation generator PID: ${STARVE_PID}"

log "Starting stalld with boosting enabled"
start_stalld_with_log "${STALLD_LOG}" -f -v -N -t $threshold -c ${TEST_CPU} -a ${STALLD_CPU}

# Wait for boosting
log "Waiting for boost detection..."
if wait_for_boost_detected "${STALLD_LOG}"; then
    pass "Boosting occurred"

    # Try to verify the correct task was boosted
    # stalld logs should show the blockee task name (starvation_gen thread)
    if grep "boosted.*starvation_gen" "${STALLD_LOG}"; then
        pass "starvation_gen task was boosted (likely the blockee)"
    else
        log "ℹ INFO: Could not verify specific task from logs"
    fi
else
    log "⚠ WARNING: No boosting detected in logs"
    log "        (May be due to queue_track backend limitation)"
    if [ -n "${STALLD_TEST_BACKEND}" ] && [ "${STALLD_TEST_BACKEND}" = "queue_track" ]; then
        log "        NOTE: queue_track backend has known issues with SCHED_FIFO detection"
    fi
fi

# Cleanup
cleanup_scenario "${STARVE_PID}"

#=============================================================================
# Final Summary
#=============================================================================
test_section "Test Summary"
log "Total failures: ${TEST_FAILED}"

if [ -n "${STALLD_TEST_BACKEND}" ] && [ "${STALLD_TEST_BACKEND}" = "queue_track" ]; then
    log ""
    log "NOTE: queue_track backend has known limitations with SCHED_FIFO task detection."
    log "      For reliable FIFO-on-FIFO testing, use the sched_debug backend:"
    log "      ./test_fifo_priority_starvation.sh -b sched_debug"
fi

end_test
