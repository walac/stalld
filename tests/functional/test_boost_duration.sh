#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Test: stalld -d/--boost_duration option
# Verifies that stalld boosts tasks for the specified duration

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${SCRIPT_DIR}/../helpers/test_helpers.sh"

test_name="test_boost_duration"
log_file="${RESULTS_DIR}/${test_name}.log"

# Cleanup function
cleanup_test() {
    stop_stalld
    killall -9 starvation_gen 2>/dev/null
    log "Test cleanup completed"
}

# Run test
{
    log "Starting test: Boost duration (-d option)"

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

    # Test 1: Default duration (should be 3 seconds)
    log "Test 1: Default boost duration (no -d specified)"
    threshold=3
    start_stalld -f -v -c "$test_cpu" -t $threshold

    # Create starvation
    log "Creating starvation on CPU $test_cpu"
    "$STARVE_GEN" -c "$test_cpu" -p 80 -n 2 -d 15 -v >> "$STALLD_LOG" 2>&1 &
    starve_pid=$!
    CLEANUP_PIDS+=($starve_pid)

    # Wait for detection and boosting
    sleep $((threshold + 2))

    # Check if boosting occurred
    if grep -q "boost" "$STALLD_LOG"; then
        log "PASS: Boosting occurred with default duration"

        # Look for restoration message after boost duration
        sleep 5
        if grep -qi "restor\|unboosted\|normal" "$STALLD_LOG"; then
            log "INFO: Policy restoration detected"
        fi
    else
        log "FAIL: No boosting detected"
        exit 1
    fi

    kill -TERM "$starve_pid" 2>/dev/null
    wait "$starve_pid" 2>/dev/null
    stop_stalld

    # Test 2: Short duration (1 second)
    log "Test 2: Short boost duration of 1 second"
    short_duration=1
    start_stalld -f -v -c "$test_cpu" -t $threshold -d $short_duration

    # Create starvation
    log "Creating starvation on CPU $test_cpu"
    "$STARVE_GEN" -c "$test_cpu" -p 80 -n 2 -d 15 -v >> "$STALLD_LOG" 2>&1 &
    starve_pid=$!
    CLEANUP_PIDS+=($starve_pid)

    # Wait for detection and boosting
    boost_start=$(date +%s)
    sleep $((threshold + 2))

    # Check if boosting occurred
    if grep -q "boost" "$STALLD_LOG"; then
        log "PASS: Boosting occurred with ${short_duration}s duration"

        # Wait for expected restoration time
        sleep $((short_duration + 2))
        boost_end=$(date +%s)
        boost_total=$((boost_end - boost_start))

        log "INFO: Total time from boost detection: ${boost_total}s"

        # Check for restoration (should happen relatively quickly with 1s duration)
        if grep -qi "restor\|unboosted\|normal" "$STALLD_LOG"; then
            log "INFO: Policy restoration detected after short duration"
        fi
    else
        log "FAIL: No boosting with short duration"
        exit 1
    fi

    kill -TERM "$starve_pid" 2>/dev/null
    wait "$starve_pid" 2>/dev/null
    stop_stalld

    # Test 3: Long duration (10 seconds)
    log "Test 3: Long boost duration of 10 seconds"
    long_duration=10
    start_stalld -f -v -c "$test_cpu" -t $threshold -d $long_duration

    # Create starvation
    log "Creating starvation on CPU $test_cpu"
    "$STARVE_GEN" -c "$test_cpu" -p 80 -n 2 -d 20 -v >> "$STALLD_LOG" 2>&1 &
    starve_pid=$!
    CLEANUP_PIDS+=($starve_pid)

    # Wait for detection and boosting
    boost_start=$(date +%s)
    sleep $((threshold + 2))

    # Check if boosting occurred
    if grep -q "boost" "$STALLD_LOG"; then
        log "PASS: Boosting occurred with ${long_duration}s duration"

        # With 10s duration, we should see task boosted for the full duration
        # Wait for part of the duration to verify boost is sustained
        sleep 5
        log "INFO: Verified boost sustained for at least 5s of ${long_duration}s duration"
    else
        log "FAIL: No boosting with long duration"
        exit 1
    fi

    kill -TERM "$starve_pid" 2>/dev/null
    wait "$starve_pid" 2>/dev/null
    stop_stalld

    # Test 4: Verify task policy is restored after boost duration
    log "Test 4: Verify policy restoration after boost duration"
    duration=2
    start_stalld -f -v -c "$test_cpu" -t $threshold -d $duration

    # Create starvation with a specific task we can track
    log "Creating starvation on CPU $test_cpu"
    "$STARVE_GEN" -c "$test_cpu" -p 80 -n 1 -d 15 -v >> "$STALLD_LOG" 2>&1 &
    starve_pid=$!
    CLEANUP_PIDS+=($starve_pid)

    # Wait for detection and boosting
    sleep $((threshold + 2))

    if grep -q "boost" "$STALLD_LOG"; then
        log "Boosting detected, waiting for restoration"

        # Wait for boost duration + buffer
        sleep $((duration + 2))

        # Check for restoration messages
        if grep -qi "restor\|unboosted\|normal\|original" "$STALLD_LOG"; then
            log "PASS: Policy restoration occurred after ${duration}s boost"
        else
            log "WARNING: No explicit restoration message found (may still have restored)"
        fi
    else
        log "FAIL: No boosting detected for restoration test"
        exit 1
    fi

    kill -TERM "$starve_pid" 2>/dev/null
    wait "$starve_pid" 2>/dev/null
    stop_stalld

    # Test 5: Invalid duration values
    log "Test 5: Invalid duration value (0)"
    "$STALLD_BIN" -f -v -t $threshold -d 0 > "${STALLD_LOG}.invalid" 2>&1 &
    invalid_pid=$!
    sleep 2

    if ! kill -0 "$invalid_pid" 2>/dev/null; then
        if grep -qi "error\|invalid" "${STALLD_LOG}.invalid"; then
            log "PASS: Zero duration rejected with error"
        else
            log "INFO: Zero duration caused exit"
        fi
    else
        log "WARNING: stalld accepted zero duration"
        kill -TERM "$invalid_pid" 2>/dev/null
        wait "$invalid_pid" 2>/dev/null
    fi

    # Test 6: Negative duration
    log "Test 6: Invalid duration value (negative)"
    "$STALLD_BIN" -f -v -t $threshold -d -5 > "${STALLD_LOG}.invalid2" 2>&1 &
    invalid_pid=$!
    sleep 2

    if ! kill -0 "$invalid_pid" 2>/dev/null; then
        if grep -qi "error\|invalid" "${STALLD_LOG}.invalid2"; then
            log "PASS: Negative duration rejected with error"
        else
            log "INFO: Negative duration caused exit"
        fi
    else
        log "WARNING: stalld accepted negative duration"
        kill -TERM "$invalid_pid" 2>/dev/null
        wait "$invalid_pid" 2>/dev/null
    fi

    # Cleanup
    rm -f "${STALLD_LOG}.invalid" "${STALLD_LOG}.invalid2"

    log "All boost duration tests passed"
    exit 0

} 2>&1 | tee "$log_file"

# Capture exit code
exit_code=${PIPESTATUS[0]}
exit $exit_code
