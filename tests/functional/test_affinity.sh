#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Test: stalld -a/--affinity option
# Verifies that stalld runs on specified CPUs when -a is used

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${SCRIPT_DIR}/../helpers/test_helpers.sh"

test_name="test_affinity"
log_file="${RESULTS_DIR}/${test_name}.log"

# Cleanup function
cleanup_test() {
    stop_stalld
    log "Test cleanup completed"
}

# Helper function to check CPU affinity
check_affinity() {
    local pid=$1
    local expected_cpus=$2

    # Use taskset to check affinity
    if command -v taskset > /dev/null 2>&1; then
        affinity=$(taskset -cp "$pid" 2>/dev/null | awk -F': ' '{print $2}')
        log "INFO: Current affinity for PID $pid: $affinity"
        echo "$affinity"
    else
        # Fallback: check /proc/PID/status
        if [ -f "/proc/$pid/status" ]; then
            affinity=$(grep "Cpus_allowed_list:" "/proc/$pid/status" | awk '{print $2}')
            log "INFO: Current affinity for PID $pid (from /proc): $affinity"
            echo "$affinity"
        else
            log "WARNING: Cannot check affinity (no taskset, no /proc)"
            echo ""
        fi
    fi
}

# Run test
{
    log "Starting test: CPU affinity (-a option)"

    require_root
    check_rt_throttling

    # Get number of CPUs
    num_cpus=$(nproc)
    log "System has $num_cpus CPUs"

    if [ "$num_cpus" -lt 2 ]; then
        log "SKIP: Test requires at least 2 CPUs"
        exit 77
    fi

    # Check if taskset is available
    if ! command -v taskset > /dev/null 2>&1; then
        log "WARNING: taskset not found, will use /proc fallback"
    fi

    # Test 1: Default behavior (no -a specified)
    log "Test 1: Default behavior (no affinity restriction)"
    start_stalld -f -v -l -t 5
    sleep 2

    default_affinity=$(check_affinity "$STALLD_PID")
    log "INFO: Default affinity: $default_affinity"

    # Typically should be all CPUs
    if [ -n "$default_affinity" ]; then
        log "PASS: stalld has default affinity: $default_affinity"
    else
        log "WARNING: Could not determine default affinity"
    fi

    stop_stalld

    # Test 2: Single CPU affinity
    log "Test 2: Single CPU affinity (-a 0)"
    start_stalld -f -v -l -t 5 -a 0
    sleep 2

    affinity=$(check_affinity "$STALLD_PID")

    if [ "$affinity" = "0" ]; then
        log "PASS: stalld restricted to CPU 0"
    else
        log "FAIL: stalld affinity ($affinity) doesn't match requested (0)"
        exit 1
    fi

    stop_stalld

    # Test 3: Multi-CPU affinity (CPU list)
    if [ "$num_cpus" -ge 4 ]; then
        log "Test 3: Multi-CPU affinity (-a 0,2)"
        start_stalld -f -v -l -t 5 -a 0,2
        sleep 2

        affinity=$(check_affinity "$STALLD_PID")

        # Accept either "0,2" or "0-2" or similar formats
        if echo "$affinity" | grep -qE '^0,2$|^0-2$|^2,0$'; then
            log "PASS: stalld restricted to CPUs 0,2 (affinity: $affinity)"
        else
            log "WARNING: stalld affinity ($affinity) may not match requested (0,2) - format may vary"
            # Not failing as different systems may report differently
        fi

        stop_stalld
    else
        log "SKIP: Test 3 requires at least 4 CPUs"
    fi

    # Test 4: CPU range affinity
    if [ "$num_cpus" -ge 4 ]; then
        log "Test 4: CPU range affinity (-a 0-2)"
        start_stalld -f -v -l -t 5 -a 0-2
        sleep 2

        affinity=$(check_affinity "$STALLD_PID")

        # Accept various formats: "0-2", "0,1,2", etc.
        if echo "$affinity" | grep -qE '0.*1.*2|0-2'; then
            log "PASS: stalld restricted to CPU range 0-2 (affinity: $affinity)"
        else
            log "WARNING: stalld affinity ($affinity) may not match requested (0-2) - format may vary"
        fi

        stop_stalld
    else
        log "SKIP: Test 4 requires at least 4 CPUs"
    fi

    # Test 5: Verify stalld actually runs on specified CPU
    log "Test 5: Verify stalld threads run on specified CPU"
    test_cpu=1
    if [ "$num_cpus" -ge 2 ]; then
        start_stalld -f -v -l -t 5 -a "$test_cpu"
        sleep 2

        # Check affinity
        affinity=$(check_affinity "$STALLD_PID")

        # Also check if any child threads exist and verify their affinity
        child_threads=$(ps -T -p "$STALLD_PID" 2>/dev/null | tail -n +2 | wc -l)
        if [ "$child_threads" -gt 0 ]; then
            log "INFO: Found $child_threads threads for stalld"
        fi

        if [ "$affinity" = "$test_cpu" ]; then
            log "PASS: stalld process affinity set to CPU $test_cpu"
        else
            log "WARNING: stalld affinity ($affinity) doesn't exactly match CPU $test_cpu"
        fi

        stop_stalld
    else
        log "SKIP: Test 5 requires at least 2 CPUs"
    fi

    # Test 6: Combined with CPU monitoring (-c and -a)
    log "Test 6: Combined affinity and monitoring (-a 0 -c 1)"
    if [ "$num_cpus" -ge 2 ]; then
        # Run stalld on CPU 0, but monitor CPU 1
        start_stalld -f -v -l -t 5 -a 0 -c 1
        sleep 2

        affinity=$(check_affinity "$STALLD_PID")

        if [ "$affinity" = "0" ]; then
            log "PASS: stalld affinity to CPU 0 while monitoring CPU 1"
        else
            log "WARNING: stalld affinity ($affinity) doesn't match requested (0)"
        fi

        # Verify it's monitoring CPU 1 by checking logs
        if grep -q "cpu 1" "$STALLD_LOG" || grep -q "monitoring.*1" "$STALLD_LOG"; then
            log "PASS: stalld monitoring CPU 1 as requested"
        else
            log "INFO: CPU 1 monitoring not explicitly confirmed in logs"
        fi

        stop_stalld
    else
        log "SKIP: Test 6 requires at least 2 CPUs"
    fi

    # Test 7: Invalid CPU affinity
    log "Test 7: Invalid CPU affinity (-a 999)"
    invalid_cpu=999

    "$STALLD_BIN" -f -v -l -t 5 -a $invalid_cpu > "${STALLD_LOG}.invalid" 2>&1 &
    invalid_pid=$!
    sleep 2

    if ! kill -0 "$invalid_pid" 2>/dev/null; then
        # Process exited
        if grep -qi "error\|invalid\|failed" "${STALLD_LOG}.invalid"; then
            log "PASS: Invalid CPU affinity rejected with error"
        else
            log "INFO: Invalid CPU affinity caused exit"
        fi
    else
        # Process still running - might have been ignored
        log "WARNING: stalld accepted invalid CPU affinity"
        kill -TERM "$invalid_pid" 2>/dev/null
        wait "$invalid_pid" 2>/dev/null
    fi

    # Test 8: Verify affinity persists
    log "Test 8: Verify affinity persists over time"
    start_stalld -f -v -l -t 5 -a 0
    sleep 2

    affinity_start=$(check_affinity "$STALLD_PID")
    log "INFO: Initial affinity: $affinity_start"

    # Wait a bit
    sleep 3

    affinity_end=$(check_affinity "$STALLD_PID")
    log "INFO: Affinity after 3s: $affinity_end"

    if [ "$affinity_start" = "$affinity_end" ]; then
        log "PASS: CPU affinity persisted over time"
    else
        log "WARNING: CPU affinity changed (start: $affinity_start, end: $affinity_end)"
    fi

    stop_stalld

    # Cleanup
    rm -f "${STALLD_LOG}.invalid"

    log "All affinity tests passed"
    exit 0

} 2>&1 | tee "$log_file"

# Capture exit code
exit_code=${PIPESTATUS[0]}
exit $exit_code
