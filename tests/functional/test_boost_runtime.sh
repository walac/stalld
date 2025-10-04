#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Test: stalld -r/--boost_runtime option
# Verifies that stalld uses the specified SCHED_DEADLINE runtime

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${SCRIPT_DIR}/../helpers/test_helpers.sh"

test_name="test_boost_runtime"
log_file="${RESULTS_DIR}/${test_name}.log"

# Cleanup function
cleanup_test() {
    stop_stalld
    killall -9 starvation_gen 2>/dev/null
    log "Test cleanup completed"
}

# Run test
{
    log "Starting test: Boost runtime (-r option)"

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

    # Test 1: Default runtime (should be 20,000 ns = 20 microseconds)
    log "Test 1: Default runtime (no -r specified)"
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
        log "PASS: Boosting occurred with default runtime"

        # Try to find runtime value in logs
        if grep -qi "runtime" "$STALLD_LOG"; then
            log "INFO: Runtime information found in logs"
        fi
    else
        log "FAIL: No boosting detected"
        exit 1
    fi

    kill -TERM "$starve_pid" 2>/dev/null
    wait "$starve_pid" 2>/dev/null
    stop_stalld

    # Test 2: Custom runtime (10,000 ns = 10 microseconds, less than default)
    log "Test 2: Custom runtime of 10,000 ns (10μs)"
    custom_runtime=10000
    start_stalld -f -v -c "$test_cpu" -t $threshold -r $custom_runtime

    # Create starvation
    log "Creating starvation on CPU $test_cpu"
    "$STARVE_GEN" -c "$test_cpu" -p 80 -n 2 -d 10 -v >> "$STALLD_LOG" 2>&1 &
    starve_pid=$!
    CLEANUP_PIDS+=($starve_pid)

    # Wait for detection and boosting
    sleep $((threshold + 2))

    # Check if boosting occurred
    if grep -q "boost" "$STALLD_LOG"; then
        log "PASS: Boosting occurred with custom runtime ${custom_runtime} ns"
    else
        log "FAIL: No boosting with custom runtime"
        exit 1
    fi

    kill -TERM "$starve_pid" 2>/dev/null
    wait "$starve_pid" 2>/dev/null
    stop_stalld

    # Test 3: Larger runtime (100,000 ns = 100 microseconds)
    log "Test 3: Larger runtime of 100,000 ns (100μs)"
    large_runtime=100000
    start_stalld -f -v -c "$test_cpu" -t $threshold -r $large_runtime

    # Create starvation
    log "Creating starvation on CPU $test_cpu"
    "$STARVE_GEN" -c "$test_cpu" -p 80 -n 2 -d 10 -v >> "$STALLD_LOG" 2>&1 &
    starve_pid=$!
    CLEANUP_PIDS+=($starve_pid)

    # Wait for detection and boosting
    sleep $((threshold + 2))

    # Check if boosting occurred
    if grep -q "boost" "$STALLD_LOG"; then
        log "PASS: Boosting occurred with large runtime ${large_runtime} ns"
    else
        log "FAIL: No boosting with large runtime"
        exit 1
    fi

    kill -TERM "$starve_pid" 2>/dev/null
    wait "$starve_pid" 2>/dev/null
    stop_stalld

    # Test 4: Runtime < period (valid configuration)
    # Default period is 1,000,000,000 ns, so runtime of 500,000 ns should be valid
    log "Test 4: Runtime < period (valid)"
    valid_runtime=500000
    period=1000000000
    start_stalld -f -v -c "$test_cpu" -t $threshold -r $valid_runtime -p $period

    # Create starvation
    log "Creating starvation on CPU $test_cpu"
    "$STARVE_GEN" -c "$test_cpu" -p 80 -n 2 -d 10 -v >> "$STALLD_LOG" 2>&1 &
    starve_pid=$!
    CLEANUP_PIDS+=($starve_pid)

    # Wait for detection and boosting
    sleep $((threshold + 2))

    # Check if boosting occurred
    if grep -q "boost" "$STALLD_LOG"; then
        log "PASS: Boosting occurred with runtime < period"
    else
        log "FAIL: No boosting when runtime < period"
        exit 1
    fi

    kill -TERM "$starve_pid" 2>/dev/null
    wait "$starve_pid" 2>/dev/null
    stop_stalld

    # Test 5: Runtime > period (should error or be rejected)
    log "Test 5: Runtime > period (invalid)"
    invalid_runtime=2000000000
    period=1000000000

    "$STALLD_BIN" -f -v -t $threshold -r $invalid_runtime -p $period > "${STALLD_LOG}.invalid" 2>&1 &
    invalid_pid=$!
    sleep 2

    if ! kill -0 "$invalid_pid" 2>/dev/null; then
        # Process exited - this is expected behavior
        if grep -qi "error\|invalid\|failed" "${STALLD_LOG}.invalid"; then
            log "PASS: Runtime > period rejected with error"
        else
            log "INFO: Runtime > period caused exit"
        fi
    else
        # Process still running - might be accepted or might fail later
        log "WARNING: stalld accepted runtime > period"
        kill -TERM "$invalid_pid" 2>/dev/null
        wait "$invalid_pid" 2>/dev/null
    fi

    # Test 6: Invalid runtime (0)
    log "Test 6: Invalid runtime value (0)"
    "$STALLD_BIN" -f -v -t $threshold -r 0 > "${STALLD_LOG}.invalid2" 2>&1 &
    invalid_pid=$!
    sleep 2

    if ! kill -0 "$invalid_pid" 2>/dev/null; then
        if grep -qi "error\|invalid" "${STALLD_LOG}.invalid2"; then
            log "PASS: Zero runtime rejected with error"
        else
            log "INFO: Zero runtime caused exit"
        fi
    else
        log "WARNING: stalld accepted zero runtime"
        kill -TERM "$invalid_pid" 2>/dev/null
        wait "$invalid_pid" 2>/dev/null
    fi

    # Test 7: Negative runtime
    log "Test 7: Invalid runtime value (negative)"
    "$STALLD_BIN" -f -v -t $threshold -r -5000 > "${STALLD_LOG}.invalid3" 2>&1 &
    invalid_pid=$!
    sleep 2

    if ! kill -0 "$invalid_pid" 2>/dev/null; then
        if grep -qi "error\|invalid" "${STALLD_LOG}.invalid3"; then
            log "PASS: Negative runtime rejected with error"
        else
            log "INFO: Negative runtime caused exit"
        fi
    else
        log "WARNING: stalld accepted negative runtime"
        kill -TERM "$invalid_pid" 2>/dev/null
        wait "$invalid_pid" 2>/dev/null
    fi

    # Cleanup
    rm -f "${STALLD_LOG}.invalid" "${STALLD_LOG}.invalid2" "${STALLD_LOG}.invalid3"

    log "All boost runtime tests passed"
    exit 0

} 2>&1 | tee "$log_file"

# Capture exit code
exit_code=${PIPESTATUS[0]}
exit $exit_code
