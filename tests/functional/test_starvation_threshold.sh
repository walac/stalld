#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Test: stalld -t/--starving_threshold option
# Verifies that stalld detects starvation after the configured threshold

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${SCRIPT_DIR}/../helpers/test_helpers.sh"

test_name="test_starvation_threshold"
log_file="${RESULTS_DIR}/${test_name}.log"

# Cleanup function
cleanup_test() {
    stop_stalld
    killall -9 starvation_gen 2>/dev/null
    log "Test cleanup completed"
}

# Run test
{
    log "Starting test: Starvation threshold (-t option)"

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

    # Test 1: Custom threshold (5 seconds)
    log "Test 1: Custom threshold of 5 seconds"
    threshold=5
    start_stalld -f -v -c "$test_cpu" -t $threshold -l

    # Create starvation that will last 10 seconds
    log "Creating starvation on CPU $test_cpu for 10 seconds"
    "$STARVE_GEN" -c "$test_cpu" -p 80 -n 2 -d 10 -v >> "$STALLD_LOG" 2>&1 &
    starve_pid=$!
    CLEANUP_PIDS+=($starve_pid)

    # Wait for threshold + buffer time
    wait_time=$((threshold + 3))
    log "Waiting ${wait_time}s for detection (threshold: ${threshold}s)"
    sleep "$wait_time"

    # Check if starvation was detected
    if grep -q "starved\|starving" "$STALLD_LOG"; then
        log "PASS: Starvation detected after ${threshold}s threshold"
    else
        log "FAIL: Starvation not detected after ${threshold}s threshold"
        log "Log contents:"
        cat "$STALLD_LOG"
        exit 1
    fi

    # Cleanup
    kill -TERM "$starve_pid" 2>/dev/null
    wait "$starve_pid" 2>/dev/null || true
    stop_stalld

    # Test 2: Verify no detection before threshold
    log "Test 2: Verify no detection before threshold"
    threshold=10
    start_stalld -f -v -c "$test_cpu" -t $threshold -l

    # Create starvation that will last 6 seconds (less than threshold)
    log "Creating short starvation (6s) with threshold of ${threshold}s"
    "$STARVE_GEN" -c "$test_cpu" -p 80 -n 2 -d 6 -v >> "$STALLD_LOG" 2>&1 &
    starve_pid=$!
    CLEANUP_PIDS+=($starve_pid)

    # Wait for starvation duration + small buffer
    sleep 8

    # Check that starvation was NOT detected (it ended before threshold)
    if ! grep -q "starved\|starving" "$STALLD_LOG"; then
        log "PASS: No starvation detected for duration less than threshold"
    else
        log "FAIL: Starvation detected before threshold"
        log "Log contents:"
        cat "$STALLD_LOG"
        exit 1
    fi

    # Cleanup
    kill -TERM "$starve_pid" 2>/dev/null
    wait "$starve_pid" 2>/dev/null || true
    stop_stalld

    # Test 3: Different threshold values (shorter)
    log "Test 3: Shorter threshold (3 seconds)"
    threshold=3
    start_stalld -f -v -c "$test_cpu" -t $threshold -l

    # Create starvation for 8 seconds
    log "Creating starvation for 8s with threshold of ${threshold}s"
    "$STARVE_GEN" -c "$test_cpu" -p 80 -n 2 -d 8 -v >> "$STALLD_LOG" 2>&1 &
    starve_pid=$!
    CLEANUP_PIDS+=($starve_pid)

    # Wait for threshold + buffer
    wait_time=$((threshold + 2))
    sleep "$wait_time"

    # Check if starvation was detected
    if grep -q "starved\|starving" "$STALLD_LOG"; then
        log "PASS: Starvation detected with ${threshold}s threshold"
    else
        log "FAIL: Starvation not detected with ${threshold}s threshold"
        exit 1
    fi

    # Cleanup
    kill -TERM "$starve_pid" 2>/dev/null
    wait "$starve_pid" 2>/dev/null || true
    stop_stalld

    # Test 4: Invalid threshold values
    log "Test 4: Invalid threshold values"

    # Test with zero threshold
    log "Testing with threshold = 0"
    "$STALLD_BIN" -f -v -t 0 -l > "${STALLD_LOG}.invalid" 2>&1 &
    invalid_pid=$!
    sleep 2

    if ! kill -0 "$invalid_pid" 2>/dev/null; then
        if grep -qi "error\|invalid" "${STALLD_LOG}.invalid"; then
            log "PASS: Zero threshold rejected with error"
        else
            log "INFO: Zero threshold caused exit (may have been rejected)"
        fi
    else
        log "WARNING: stalld accepted zero threshold"
        kill -TERM "$invalid_pid" 2>/dev/null
        wait "$invalid_pid" 2>/dev/null || true
    fi

    # Test with negative threshold
    log "Testing with threshold = -5"
    "$STALLD_BIN" -f -v -t -5 -l > "${STALLD_LOG}.invalid2" 2>&1 &
    invalid_pid=$!
    sleep 2

    if ! kill -0 "$invalid_pid" 2>/dev/null; then
        if grep -qi "error\|invalid" "${STALLD_LOG}.invalid2"; then
            log "PASS: Negative threshold rejected with error"
        else
            log "INFO: Negative threshold caused exit"
        fi
    else
        log "WARNING: stalld accepted negative threshold"
        kill -TERM "$invalid_pid" 2>/dev/null
        wait "$invalid_pid" 2>/dev/null || true
    fi

    # Cleanup invalid test logs
    rm -f "${STALLD_LOG}.invalid" "${STALLD_LOG}.invalid2"

    log "All starvation threshold tests passed"
    exit 0

} 2>&1 | tee "$log_file"

# Capture exit code
exit_code=${PIPESTATUS[0]}
exit $exit_code
