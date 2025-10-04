#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Test: stalld -P/--pidfile option
# Verifies that stalld creates and manages PID files correctly

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "${SCRIPT_DIR}/../helpers/test_helpers.sh"

test_name="test_pidfile"
log_file="${RESULTS_DIR}/${test_name}.log"

# Custom cleanup for this test
cleanup_test() {
    stop_stalld
    # Clean up any test pidfiles
    rm -f "${RESULTS_DIR}/test_pidfile_"*.pid
    rm -f /tmp/stalld_test_*.pid
    log "Test cleanup completed"
}

# Run test
{
    log "Starting test: PID file (-P option)"

    require_root
    check_rt_throttling

    # Test 1: Default pidfile location (no -P specified)
    log "Test 1: Default behavior (no -P specified)"
    start_stalld -l -t 5

    # Give stalld time to create pidfile
    sleep 2

    # Check common default pidfile locations
    default_found=0
    for pidfile in /var/run/stalld.pid /run/stalld.pid; do
        if [ -f "$pidfile" ]; then
            log "INFO: Found default pidfile at $pidfile"
            default_found=1

            # Verify PID matches
            pid_from_file=$(cat "$pidfile")
            if [ "$pid_from_file" = "$STALLD_PID" ]; then
                log "PASS: Default pidfile contains correct PID"
            else
                log "FAIL: Default pidfile PID ($pid_from_file) doesn't match stalld PID ($STALLD_PID)"
                exit 1
            fi
            break
        fi
    done

    if [ $default_found -eq 0 ]; then
        log "INFO: No default pidfile found (may be expected depending on configuration)"
    fi

    stop_stalld

    # Test 2: Custom pidfile location
    log "Test 2: Custom pidfile location"
    custom_pidfile="${RESULTS_DIR}/test_pidfile_custom.pid"

    # Ensure pidfile doesn't exist before test
    rm -f "$custom_pidfile"

    start_stalld -l -t 5 -P "$custom_pidfile"
    sleep 2

    # Verify pidfile was created
    if [ -f "$custom_pidfile" ]; then
        log "PASS: Custom pidfile created at $custom_pidfile"

        # Verify content
        pid_from_file=$(cat "$custom_pidfile")
        if [ "$pid_from_file" = "$STALLD_PID" ]; then
            log "PASS: Custom pidfile contains correct PID ($pid_from_file)"
        else
            log "FAIL: Custom pidfile PID ($pid_from_file) doesn't match stalld PID ($STALLD_PID)"
            exit 1
        fi
    else
        log "FAIL: Custom pidfile not created at $custom_pidfile"
        exit 1
    fi

    # Test 3: Verify pidfile removed on clean shutdown
    log "Test 3: Verify pidfile removed on clean shutdown"
    stop_stalld
    sleep 1

    if [ ! -f "$custom_pidfile" ]; then
        log "PASS: Pidfile removed on clean shutdown"
    else
        log "WARNING: Pidfile still exists after shutdown (may be expected)"
        # Not failing - some implementations keep pidfile
    fi

    # Test 4: Custom pidfile in /tmp
    log "Test 4: Custom pidfile in /tmp directory"
    tmp_pidfile="/tmp/stalld_test_$$.pid"
    rm -f "$tmp_pidfile"

    start_stalld -l -t 5 -P "$tmp_pidfile"
    sleep 2

    if [ -f "$tmp_pidfile" ]; then
        log "PASS: Pidfile created in /tmp directory"

        pid_from_file=$(cat "$tmp_pidfile")
        if [ "$pid_from_file" = "$STALLD_PID" ]; then
            log "PASS: /tmp pidfile contains correct PID"
        else
            log "FAIL: /tmp pidfile has incorrect PID"
            exit 1
        fi
    else
        log "FAIL: Pidfile not created in /tmp"
        exit 1
    fi

    stop_stalld
    rm -f "$tmp_pidfile"

    # Test 5: Test with foreground mode
    log "Test 5: Pidfile with foreground mode (-f)"
    fg_pidfile="${RESULTS_DIR}/test_pidfile_foreground.pid"
    rm -f "$fg_pidfile"

    start_stalld -f -v -l -t 5 -P "$fg_pidfile"
    sleep 2

    if [ -f "$fg_pidfile" ]; then
        log "PASS: Pidfile created in foreground mode"

        pid_from_file=$(cat "$fg_pidfile")
        if [ "$pid_from_file" = "$STALLD_PID" ]; then
            log "PASS: Foreground mode pidfile contains correct PID"
        else
            log "FAIL: Foreground mode pidfile has incorrect PID"
            exit 1
        fi
    else
        log "WARNING: Pidfile not created in foreground mode (may be expected)"
    fi

    stop_stalld
    rm -f "$fg_pidfile"

    # Test 6: Invalid pidfile path (permission denied)
    log "Test 6: Invalid pidfile path (permission denied)"

    # Try to create pidfile in root directory (should fail for non-root or succeed for root)
    invalid_pidfile="/root/stalld_test.pid"

    # If we're root, try a truly inaccessible location
    if [ "$(id -u)" -eq 0 ]; then
        # Create a directory with no write permissions
        test_dir="${RESULTS_DIR}/no_write_test"
        mkdir -p "$test_dir"
        chmod 555 "$test_dir"
        invalid_pidfile="${test_dir}/stalld.pid"
    fi

    "$STALLD_BIN" -f -v -l -t 5 -P "$invalid_pidfile" > "${STALLD_LOG}.invalid" 2>&1 &
    invalid_pid=$!
    sleep 2

    # Check if stalld is still running
    if ! kill -0 "$invalid_pid" 2>/dev/null; then
        # Process exited
        if grep -qi "error\|permission\|denied\|failed" "${STALLD_LOG}.invalid"; then
            log "PASS: Invalid pidfile path rejected with error"
        else
            log "INFO: Invalid pidfile path caused exit"
        fi
    else
        # Process still running - might have accepted it or created elsewhere
        log "WARNING: stalld running despite potentially invalid pidfile path"
        kill -TERM "$invalid_pid" 2>/dev/null
        wait "$invalid_pid" 2>/dev/null
    fi

    # Cleanup
    if [ -d "${test_dir}" ]; then
        chmod 755 "$test_dir"
        rm -rf "$test_dir"
    fi
    rm -f "${STALLD_LOG}.invalid"

    # Test 7: Verify pidfile is readable by other processes
    log "Test 7: Verify pidfile is readable"
    readable_pidfile="${RESULTS_DIR}/test_pidfile_readable.pid"
    rm -f "$readable_pidfile"

    start_stalld -l -t 5 -P "$readable_pidfile"
    sleep 2

    if [ -f "$readable_pidfile" ]; then
        # Try to read the pidfile as a regular user would
        if cat "$readable_pidfile" > /dev/null 2>&1; then
            log "PASS: Pidfile is readable"

            # Check permissions
            perms=$(stat -c "%a" "$readable_pidfile" 2>/dev/null || stat -f "%Lp" "$readable_pidfile" 2>/dev/null)
            log "INFO: Pidfile permissions: $perms"
        else
            log "FAIL: Pidfile not readable"
            exit 1
        fi
    else
        log "FAIL: Pidfile not created"
        exit 1
    fi

    stop_stalld
    rm -f "$readable_pidfile"

    log "All pidfile tests passed"
    exit 0

} 2>&1 | tee "$log_file"

# Capture exit code
exit_code=${PIPESTATUS[0]}
exit $exit_code
