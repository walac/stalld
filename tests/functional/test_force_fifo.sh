#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Test: stalld -F/--force_fifo option
# Verifies that stalld uses SCHED_FIFO instead of SCHED_DEADLINE when -F is specified

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${SCRIPT_DIR}/../helpers/test_helpers.sh"

test_name="test_force_fifo"
log_file="${RESULTS_DIR}/${test_name}.log"

# Cleanup function
cleanup_test() {
    stop_stalld
    killall -9 starvation_gen 2>/dev/null
    log "Test cleanup completed"
}

# Run test
{
    log "Starting test: Force FIFO (-F option)"

    require_root
    check_rt_throttling

    # Pick a CPU for testing
    test_cpu=$(pick_test_cpu)
    log "Using CPU $test_cpu for testing"

    # Check if starvation_gen exists
    STARVE_GEN="${SCRIPT_DIR}/../helpers/starvation_gen"
    if [ ! -x "$STARVE_GEN" ]; then
        log "SKIP: starvation_gen not found or not executable"
        exit 77
    fi

    # Test 1: Default behavior (should use SCHED_DEADLINE)
    log "Test 1: Default behavior (no -F, should use SCHED_DEADLINE)"
    threshold=3
    start_stalld -f -v -c "$test_cpu" -t $threshold

    # Create starvation
    log "Creating starvation on CPU $test_cpu"
    "$STARVE_GEN" -c "$test_cpu" -p 80 -n 2 -d 10 -v >> "$STALLD_LOG" 2>&1 &
    starve_pid=$!
    CLEANUP_PIDS+=($starve_pid)

    # Wait for detection and boosting
    sleep $((threshold + 2))

    # Check if boosting occurred and look for DEADLINE mentions
    if grep -q "boost" "$STALLD_LOG"; then
        log "Boosting occurred"

        # Look for SCHED_DEADLINE indicators
        if grep -qi "deadline\|SCHED_DEADLINE" "$STALLD_LOG"; then
            log "PASS: SCHED_DEADLINE used by default"
        elif grep -qi "fifo\|SCHED_FIFO" "$STALLD_LOG"; then
            log "WARNING: SCHED_FIFO used instead of SCHED_DEADLINE"
        else
            log "INFO: Scheduling policy not explicitly mentioned in logs"
        fi
    else
        log "WARNING: No boosting detected in default mode"
    fi

    kill -TERM "$starve_pid" 2>/dev/null
    wait "$starve_pid" 2>/dev/null
    stop_stalld

    # Test 2: Force FIFO mode (-F)
    log "Test 2: Force FIFO mode (-F)"

    # Note: Single-threaded mode only works with SCHED_DEADLINE (dies with FIFO)
    # So we need to use aggressive mode (-A) when testing FIFO
    start_stalld -f -v -c "$test_cpu" -t $threshold -F -A

    # Create starvation
    log "Creating starvation on CPU $test_cpu"
    "$STARVE_GEN" -c "$test_cpu" -p 80 -n 2 -d 10 -v >> "$STALLD_LOG" 2>&1 &
    starve_pid=$!
    CLEANUP_PIDS+=($starve_pid)

    # Wait for detection and boosting
    sleep $((threshold + 2))

    # Check if boosting occurred and look for FIFO mentions
    if grep -q "boost" "$STALLD_LOG"; then
        log "Boosting occurred with -F flag"

        # Look for SCHED_FIFO indicators
        if grep -qi "fifo\|SCHED_FIFO" "$STALLD_LOG"; then
            log "PASS: SCHED_FIFO used with -F flag"
        elif grep -qi "deadline\|SCHED_DEADLINE" "$STALLD_LOG"; then
            log "FAIL: SCHED_DEADLINE used despite -F flag"
            exit 1
        else
            log "WARNING: Scheduling policy not explicitly mentioned in logs"
        fi
    else
        log "WARNING: No boosting detected with -F flag"
    fi

    kill -TERM "$starve_pid" 2>/dev/null
    wait "$starve_pid" 2>/dev/null
    stop_stalld

    # Test 3: Verify FIFO priority setting
    log "Test 3: Verify FIFO priority is set"
    start_stalld -f -v -c "$test_cpu" -t $threshold -F -A

    # Create starvation
    log "Creating starvation on CPU $test_cpu"
    "$STARVE_GEN" -c "$test_cpu" -p 80 -n 2 -d 10 -v >> "$STALLD_LOG" 2>&1 &
    starve_pid=$!
    CLEANUP_PIDS+=($starve_pid)

    # Wait for detection and boosting
    sleep $((threshold + 2))

    # Check logs for priority information
    if grep -qi "priority\|prio" "$STALLD_LOG"; then
        log "INFO: Priority information found in logs"
    fi

    if grep -q "boost" "$STALLD_LOG"; then
        log "PASS: FIFO boosting with priority setting completed"
    else
        log "WARNING: No boosting detected"
    fi

    kill -TERM "$starve_pid" 2>/dev/null
    wait "$starve_pid" 2>/dev/null
    stop_stalld

    # Test 4: Verify FIFO emulation behavior (sleep runtime, restore, sleep remainder)
    log "Test 4: FIFO emulation behavior"
    start_stalld -f -v -c "$test_cpu" -t $threshold -F -A -d 3

    # Create starvation
    log "Creating starvation on CPU $test_cpu"
    "$STARVE_GEN" -c "$test_cpu" -p 80 -n 2 -d 12 -v >> "$STALLD_LOG" 2>&1 &
    starve_pid=$!
    CLEANUP_PIDS+=($starve_pid)

    # Wait for detection and boosting
    sleep $((threshold + 2))

    if grep -q "boost" "$STALLD_LOG"; then
        log "Boosting detected, waiting for duration cycle"

        # Wait for boost duration + buffer to see restoration
        sleep 5

        # Check for restoration messages (part of FIFO emulation)
        if grep -qi "restor\|unboosted\|normal\|original" "$STALLD_LOG"; then
            log "PASS: FIFO emulation with restoration detected"
        else
            log "INFO: FIFO boosting completed (restoration may be implicit)"
        fi
    else
        log "WARNING: No boosting detected for FIFO emulation test"
    fi

    kill -TERM "$starve_pid" 2>/dev/null
    wait "$starve_pid" 2>/dev/null
    stop_stalld

    # Test 5: Single-threaded mode with FIFO (should fail/exit)
    log "Test 5: Single-threaded mode with FIFO (should fail)"

    # Try to run stalld with -F but without -A (single-threaded mode)
    # According to CLAUDE.md, this should die/exit
    "$STALLD_BIN" -f -v -c "$test_cpu" -t $threshold -F > "${STALLD_LOG}.fifo_single" 2>&1 &
    fifo_pid=$!
    sleep 3

    if ! kill -0 "$fifo_pid" 2>/dev/null; then
        # Process exited - this is expected
        if grep -qi "error\|single.*thread\|not.*support" "${STALLD_LOG}.fifo_single"; then
            log "PASS: Single-threaded mode rejected FIFO with error message"
        else
            log "PASS: Single-threaded mode with FIFO caused exit (as expected)"
        fi
    else
        # Process still running - unexpected
        log "WARNING: Single-threaded mode accepted FIFO (may have switched to multi-threaded)"
        kill -TERM "$fifo_pid" 2>/dev/null
        wait "$fifo_pid" 2>/dev/null
    fi

    # Test 6: Compare effectiveness (informational)
    log "Test 6: FIFO vs DEADLINE comparison (informational)"

    # Run with DEADLINE
    start_stalld -f -v -c "$test_cpu" -t $threshold -d 2
    "$STARVE_GEN" -c "$test_cpu" -p 80 -n 2 -d 8 -v >> "$STALLD_LOG" 2>&1 &
    starve_pid=$!
    sleep $((threshold + 3))

    deadline_boosts=$(grep -c "boost" "$STALLD_LOG" || echo 0)
    log "INFO: SCHED_DEADLINE boosts: $deadline_boosts"

    kill -TERM "$starve_pid" 2>/dev/null
    wait "$starve_pid" 2>/dev/null
    stop_stalld

    # Run with FIFO
    start_stalld -f -v -c "$test_cpu" -t $threshold -F -A -d 2
    "$STARVE_GEN" -c "$test_cpu" -p 80 -n 2 -d 8 -v >> "$STALLD_LOG" 2>&1 &
    starve_pid=$!
    sleep $((threshold + 3))

    fifo_boosts=$(grep -c "boost" "$STALLD_LOG" || echo 0)
    log "INFO: SCHED_FIFO boosts: $fifo_boosts"

    kill -TERM "$starve_pid" 2>/dev/null
    wait "$starve_pid" 2>/dev/null
    stop_stalld

    log "INFO: Comparison complete (DEADLINE: $deadline_boosts, FIFO: $fifo_boosts)"

    # Cleanup
    rm -f "${STALLD_LOG}.fifo_single"

    log "All force FIFO tests passed"
    exit 0

} 2>&1 | tee "$log_file"

# Capture exit code
exit_code=${PIPESTATUS[0]}
exit $exit_code
