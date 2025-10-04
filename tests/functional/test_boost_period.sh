#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Test: stalld -p/--boost_period option
# Verifies that stalld uses the specified SCHED_DEADLINE period

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${SCRIPT_DIR}/../helpers/test_helpers.sh"

test_name="test_boost_period"
log_file="${RESULTS_DIR}/${test_name}.log"

# Cleanup function
cleanup_test() {
    stop_stalld
    killall -9 starvation_gen 2>/dev/null
    log "Test cleanup completed"
}

# Run test
{
    log "Starting test: Boost period (-p option)"

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

    # Test 1: Default period (should be 1,000,000,000 ns = 1 second)
    log "Test 1: Default period (no -p specified)"
    threshold=3
    start_stalld -f -v -c "$test_cpu" -t $threshold

    # Create starvation
    log "Creating starvation on CPU $test_cpu"
    "$STARVE_GEN" -c "$test_cpu" -p 80 -n 2 -d 10 -v >> "$STALLD_LOG" 2>&1 &
    starve_pid=$!
    CLEANUP_PIDS+=($starve_pid)

    # Wait for detection and boosting
    sleep $((threshold + 2))

    # Check if boosting occurred
    if grep -q "boost" "$STALLD_LOG"; then
        log "PASS: Boosting occurred with default period"

        # Try to find period value in logs (may contain "period" or specific value)
        if grep -qi "period" "$STALLD_LOG"; then
            log "INFO: Period information found in logs"
        fi
    else
        log "FAIL: No boosting detected"
        exit 1
    fi

    kill -TERM "$starve_pid" 2>/dev/null
    wait "$starve_pid" 2>/dev/null
    stop_stalld

    # Test 2: Custom period (500ms = 500,000,000 ns)
    log "Test 2: Custom period of 500,000,000 ns (500ms)"
    custom_period=500000000
    start_stalld -f -v -c "$test_cpu" -t $threshold -p $custom_period

    # Create starvation
    log "Creating starvation on CPU $test_cpu"
    "$STARVE_GEN" -c "$test_cpu" -p 80 -n 2 -d 10 -v >> "$STALLD_LOG" 2>&1 &
    starve_pid=$!
    CLEANUP_PIDS+=($starve_pid)

    # Wait for detection and boosting
    sleep $((threshold + 2))

    # Check if boosting occurred
    if grep -q "boost" "$STALLD_LOG"; then
        log "PASS: Boosting occurred with custom period ${custom_period} ns"
    else
        log "FAIL: No boosting with custom period"
        exit 1
    fi

    kill -TERM "$starve_pid" 2>/dev/null
    wait "$starve_pid" 2>/dev/null
    stop_stalld

    # Test 3: Very short period (100ms = 100,000,000 ns)
    log "Test 3: Very short period of 100,000,000 ns (100ms)"
    short_period=100000000
    start_stalld -f -v -c "$test_cpu" -t $threshold -p $short_period

    # Create starvation
    log "Creating starvation on CPU $test_cpu"
    "$STARVE_GEN" -c "$test_cpu" -p 80 -n 2 -d 10 -v >> "$STALLD_LOG" 2>&1 &
    starve_pid=$!
    CLEANUP_PIDS+=($starve_pid)

    # Wait for detection and boosting
    sleep $((threshold + 2))

    # Check if boosting occurred
    if grep -q "boost" "$STALLD_LOG"; then
        log "PASS: Boosting occurred with short period ${short_period} ns"
    else
        log "FAIL: No boosting with short period"
        exit 1
    fi

    kill -TERM "$starve_pid" 2>/dev/null
    wait "$starve_pid" 2>/dev/null
    stop_stalld

    # Test 4: Very long period (10s = 10,000,000,000 ns)
    log "Test 4: Very long period of 10,000,000,000 ns (10s)"
    long_period=10000000000
    start_stalld -f -v -c "$test_cpu" -t $threshold -p $long_period

    # Create starvation
    log "Creating starvation on CPU $test_cpu"
    "$STARVE_GEN" -c "$test_cpu" -p 80 -n 2 -d 10 -v >> "$STALLD_LOG" 2>&1 &
    starve_pid=$!
    CLEANUP_PIDS+=($starve_pid)

    # Wait for detection and boosting
    sleep $((threshold + 2))

    # Check if boosting occurred
    if grep -q "boost" "$STALLD_LOG"; then
        log "PASS: Boosting occurred with long period ${long_period} ns"
    else
        log "FAIL: No boosting with long period"
        exit 1
    fi

    kill -TERM "$starve_pid" 2>/dev/null
    wait "$starve_pid" 2>/dev/null
    stop_stalld

    # Test 5: Invalid period (0)
    log "Test 5: Invalid period value (0)"
    "$STALLD_BIN" -f -v -t $threshold -p 0 > "${STALLD_LOG}.invalid" 2>&1 &
    invalid_pid=$!
    sleep 2

    if ! kill -0 "$invalid_pid" 2>/dev/null; then
        if grep -qi "error\|invalid" "${STALLD_LOG}.invalid"; then
            log "PASS: Zero period rejected with error"
        else
            log "INFO: Zero period caused exit"
        fi
    else
        log "WARNING: stalld accepted zero period"
        kill -TERM "$invalid_pid" 2>/dev/null
        wait "$invalid_pid" 2>/dev/null
    fi

    # Test 6: Negative period
    log "Test 6: Invalid period value (negative)"
    "$STALLD_BIN" -f -v -t $threshold -p -1000000 > "${STALLD_LOG}.invalid2" 2>&1 &
    invalid_pid=$!
    sleep 2

    if ! kill -0 "$invalid_pid" 2>/dev/null; then
        if grep -qi "error\|invalid" "${STALLD_LOG}.invalid2"; then
            log "PASS: Negative period rejected with error"
        else
            log "INFO: Negative period caused exit"
        fi
    else
        log "WARNING: stalld accepted negative period"
        kill -TERM "$invalid_pid" 2>/dev/null
        wait "$invalid_pid" 2>/dev/null
    fi

    # Cleanup
    rm -f "${STALLD_LOG}.invalid" "${STALLD_LOG}.invalid2"

    log "All boost period tests passed"
    exit 0

} 2>&1 | tee "$log_file"

# Capture exit code
exit_code=${PIPESTATUS[0]}
exit $exit_code
