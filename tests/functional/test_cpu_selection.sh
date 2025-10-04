#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Test: stalld -c/--cpu option (CPU selection)
# Verifies that stalld only monitors specified CPUs

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${SCRIPT_DIR}/../helpers/test_helpers.sh"

test_name="test_cpu_selection"
log_file="${RESULTS_DIR}/${test_name}.log"

# Cleanup function
cleanup_test() {
    stop_stalld
    log "Test cleanup completed"
}

# Run test
{
    log "Starting test: CPU selection (-c option)"

    require_root
    check_rt_throttling

    # Get available CPUs
    num_cpus=$(nproc)
    if [ "$num_cpus" -lt 2 ]; then
        log "SKIP: Test requires at least 2 CPUs (found: $num_cpus)"
        exit 77
    fi

    log "System has $num_cpus CPUs"

    # Test 1: Single CPU monitoring
    log "Test 1: Single CPU monitoring (-c 0)"
    start_stalld -f -v -c 0 -l -t 5
    sleep 2

    # Check that stalld mentions CPU 0
    if grep -q "cpu 0" "$STALLD_LOG"; then
        log "PASS: stalld monitoring CPU 0"
    else
        log "FAIL: stalld not monitoring CPU 0"
        exit 1
    fi

    stop_stalld

    # Test 2: CPU list (comma-separated)
    if [ "$num_cpus" -ge 4 ]; then
        log "Test 2: CPU list monitoring (-c 0,2)"
        start_stalld -f -v -c 0,2 -l -t 5
        sleep 2

        # Check for CPU 0 and CPU 2 in output
        cpu0_found=0
        cpu2_found=0
        if grep -q "cpu 0" "$STALLD_LOG"; then
            cpu0_found=1
        fi
        if grep -q "cpu 2" "$STALLD_LOG"; then
            cpu2_found=1
        fi

        if [ "$cpu0_found" -eq 1 ] && [ "$cpu2_found" -eq 1 ]; then
            log "PASS: stalld monitoring CPUs 0 and 2"
        else
            log "FAIL: stalld not monitoring specified CPUs (0: $cpu0_found, 2: $cpu2_found)"
            exit 1
        fi

        stop_stalld
    else
        log "SKIP: Test 2 requires at least 4 CPUs"
    fi

    # Test 3: CPU range
    if [ "$num_cpus" -ge 4 ]; then
        log "Test 3: CPU range monitoring (-c 0-2)"
        start_stalld -f -v -c 0-2 -l -t 5
        sleep 2

        # Check for CPUs 0, 1, 2 in output
        cpu0_found=0
        cpu1_found=0
        cpu2_found=0
        if grep -q "cpu 0" "$STALLD_LOG"; then
            cpu0_found=1
        fi
        if grep -q "cpu 1" "$STALLD_LOG"; then
            cpu1_found=1
        fi
        if grep -q "cpu 2" "$STALLD_LOG"; then
            cpu2_found=1
        fi

        if [ "$cpu0_found" -eq 1 ] && [ "$cpu1_found" -eq 1 ] && [ "$cpu2_found" -eq 1 ]; then
            log "PASS: stalld monitoring CPUs 0-2"
        else
            log "FAIL: stalld not monitoring specified CPU range (0: $cpu0_found, 1: $cpu1_found, 2: $cpu2_found)"
            exit 1
        fi

        stop_stalld
    else
        log "SKIP: Test 3 requires at least 4 CPUs"
    fi

    # Test 4: Combined format (list and range)
    if [ "$num_cpus" -ge 6 ]; then
        log "Test 4: Combined format (-c 0,2-4)"
        start_stalld -f -v -c 0,2-4 -l -t 5
        sleep 2

        # Should monitor CPUs 0, 2, 3, 4
        monitored_cpus=0
        for cpu in 0 2 3 4; do
            if grep -q "cpu $cpu" "$STALLD_LOG"; then
                ((monitored_cpus++))
            fi
        done

        if [ "$monitored_cpus" -eq 4 ]; then
            log "PASS: stalld monitoring combined CPU specification (0,2-4)"
        else
            log "FAIL: stalld not monitoring all specified CPUs (found $monitored_cpus/4)"
            exit 1
        fi

        stop_stalld
    else
        log "SKIP: Test 4 requires at least 6 CPUs"
    fi

    # Test 5: Invalid CPU number (should handle gracefully)
    log "Test 5: Invalid CPU number (-c 999)"
    invalid_cpu=999

    # Run stalld with invalid CPU and capture output
    "$STALLD_BIN" -f -v -c $invalid_cpu -l -t 5 > "${STALLD_LOG}" 2>&1 &
    STALLD_PID=$!

    # Wait a bit to see if it exits or produces error
    sleep 2

    if ! kill -0 "$STALLD_PID" 2>/dev/null; then
        # Process exited - check for error message
        if grep -qi "error\|invalid\|failed" "$STALLD_LOG"; then
            log "PASS: stalld rejected invalid CPU number with error"
        else
            log "PASS: stalld exited when given invalid CPU"
        fi
    else
        # Process still running - it might have ignored the invalid CPU
        log "WARNING: stalld still running with invalid CPU (may have ignored it)"
        kill -TERM "$STALLD_PID" 2>/dev/null
        wait "$STALLD_PID" 2>/dev/null
    fi

    # Test 6: Verify non-selected CPUs are NOT monitored
    if [ "$num_cpus" -ge 2 ]; then
        log "Test 6: Verify non-selected CPUs not monitored (-c 0)"
        start_stalld -f -v -c 0 -l -t 5
        sleep 2

        # Check that CPU 1 is NOT mentioned (or mentioned as "not monitoring")
        if ! grep -q "cpu 1" "$STALLD_LOG" || grep -q "not monitoring.*cpu 1" "$STALLD_LOG"; then
            log "PASS: stalld not monitoring non-selected CPU 1"
        else
            log "FAIL: stalld appears to be monitoring CPU 1 when only CPU 0 selected"
            exit 1
        fi

        stop_stalld
    fi

    log "All CPU selection tests passed"
    exit 0

} 2>&1 | tee "$log_file"

# Capture exit code
exit_code=${PIPESTATUS[0]}
exit $exit_code
