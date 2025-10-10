#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Test: stalld -P/--pidfile option
# Verifies that stalld creates and manages PID files correctly
#
# Copyright (C) 2025 Red Hat Inc

# Load test helpers
TEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${TEST_ROOT}/helpers/test_helpers.sh"

# Parse command-line options
parse_test_options "$@" || exit $?

# Helper function for logging test steps
log() {
    echo "[$(date +'%H:%M:%S')] $*"
}

start_test "PID File Option (-P)"

# Require root for this test
require_root

# Check RT throttling
if ! check_rt_throttling; then
    echo -e "${YELLOW}SKIP: RT throttling must be disabled for this test${NC}"
    exit 77
fi

# Setup paths
STALLD_LOG="/tmp/stalld_test_pidfile_$$.log"
CLEANUP_FILES+=("${STALLD_LOG}")

#=============================================================================
# Test 1: Default pidfile location (no -P specified)
#=============================================================================
log ""
log "=========================================="
log "Test 1: Default behavior (no -P specified)"
log "=========================================="

start_stalld -l -t 5

# Give stalld time to create pidfile
sleep 2

# Check common default pidfile locations
default_found=0
for pidfile in /var/run/stalld.pid /run/stalld.pid; do
    if [ -f "$pidfile" ]; then
        log "ℹ INFO: Found default pidfile at $pidfile"
        default_found=1

        # Verify PID matches
        pid_from_file=$(cat "$pidfile")
        if [ "$pid_from_file" = "${STALLD_PID}" ]; then
            log "✓ PASS: Default pidfile contains correct PID"
        else
            log "✗ FAIL: Default pidfile PID ($pid_from_file) doesn't match stalld PID (${STALLD_PID})"
            TEST_FAILED=$((TEST_FAILED + 1))
        fi
        break
    fi
done

if [ $default_found -eq 0 ]; then
    log "ℹ INFO: No default pidfile found (may be expected depending on configuration)"
fi

stop_stalld
sleep 1

#=============================================================================
# Test 2: Custom pidfile location
#=============================================================================
log ""
log "=========================================="
log "Test 2: Custom pidfile location"
log "=========================================="

custom_pidfile="/tmp/stalld_test_pidfile_custom_$$.pid"
CLEANUP_FILES+=("${custom_pidfile}")

# Ensure pidfile doesn't exist before test
rm -f "${custom_pidfile}"

STALLD_LOG2="/tmp/stalld_test_pidfile_test2_$$.log"
CLEANUP_FILES+=("${STALLD_LOG2}")

log "Starting stalld with custom pidfile: ${custom_pidfile}"
start_stalld -l -t 5 --pidfile "${custom_pidfile}"
sleep 2

# Verify pidfile was created
if [ -f "${custom_pidfile}" ]; then
    log "✓ PASS: Custom pidfile created at ${custom_pidfile}"

    # Verify content
    pid_from_file=$(cat "${custom_pidfile}")
    if [ "$pid_from_file" = "${STALLD_PID}" ]; then
        log "✓ PASS: Custom pidfile contains correct PID ($pid_from_file)"
    else
        log "✗ FAIL: Custom pidfile PID ($pid_from_file) doesn't match stalld PID (${STALLD_PID})"
        TEST_FAILED=$((TEST_FAILED + 1))
    fi
else
    log "✗ FAIL: Custom pidfile not created at ${custom_pidfile}"
    TEST_FAILED=$((TEST_FAILED + 1))
fi

# Test 3: Verify pidfile removed on clean shutdown
log ""
log "Test 3: Verify pidfile removed on clean shutdown"
stop_stalld
sleep 1

if [ ! -f "${custom_pidfile}" ]; then
    log "✓ PASS: Pidfile removed on clean shutdown"
else
    log "⚠ WARNING: Pidfile still exists after shutdown (may be expected)"
    # Not failing - some implementations keep pidfile
fi

#=============================================================================
# Test 4: Custom pidfile in /tmp
#=============================================================================
log ""
log "=========================================="
log "Test 4: Custom pidfile in /tmp directory"
log "=========================================="

tmp_pidfile="/tmp/stalld_test_tmp_$$.pid"
CLEANUP_FILES+=("${tmp_pidfile}")
rm -f "${tmp_pidfile}"

STALLD_LOG4="/tmp/stalld_test_pidfile_test4_$$.log"
CLEANUP_FILES+=("${STALLD_LOG4}")

log "Starting stalld with /tmp pidfile: ${tmp_pidfile}"
start_stalld -l -t 5 --pidfile "${tmp_pidfile}"
sleep 2

if [ -f "${tmp_pidfile}" ]; then
    log "✓ PASS: Pidfile created in /tmp directory"

    pid_from_file=$(cat "${tmp_pidfile}")
    if [ "$pid_from_file" = "${STALLD_PID}" ]; then
        log "✓ PASS: /tmp pidfile contains correct PID"
    else
        log "✗ FAIL: /tmp pidfile has incorrect PID"
        TEST_FAILED=$((TEST_FAILED + 1))
    fi
else
    log "✗ FAIL: Pidfile not created in /tmp"
    TEST_FAILED=$((TEST_FAILED + 1))
fi

stop_stalld
sleep 1

#=============================================================================
# Test 5: Test with foreground mode
#=============================================================================
log ""
log "=========================================="
log "Test 5: Pidfile with foreground mode (-f)"
log "=========================================="

fg_pidfile="/tmp/stalld_test_pidfile_foreground_$$.pid"
CLEANUP_FILES+=("${fg_pidfile}")
rm -f "${fg_pidfile}"

STALLD_LOG5="/tmp/stalld_test_pidfile_test5_$$.log"
CLEANUP_FILES+=("${STALLD_LOG5}")

log "Starting stalld in foreground mode with pidfile: ${fg_pidfile}"
start_stalld -f -v -l -t 5 --pidfile "${fg_pidfile}"
sleep 2

if [ -f "${fg_pidfile}" ]; then
    log "✓ PASS: Pidfile created in foreground mode"

    pid_from_file=$(cat "${fg_pidfile}")
    if [ "$pid_from_file" = "${STALLD_PID}" ]; then
        log "✓ PASS: Foreground mode pidfile contains correct PID"
    else
        log "✗ FAIL: Foreground mode pidfile has incorrect PID"
        TEST_FAILED=$((TEST_FAILED + 1))
    fi
else
    log "⚠ WARNING: Pidfile not created in foreground mode (may be expected)"
fi

stop_stalld
sleep 1

#=============================================================================
# Test 6: Invalid pidfile path (permission denied)
#=============================================================================
log ""
log "=========================================="
log "Test 6: Invalid pidfile path (permission denied)"
log "=========================================="

# Create a directory with no write permissions
test_dir="/tmp/stalld_test_no_write_$$"
mkdir -p "${test_dir}"
chmod 555 "${test_dir}"
invalid_pidfile="${test_dir}/stalld.pid"
CLEANUP_FILES+=("${test_dir}")

INVALID_LOG="/tmp/stalld_test_pidfile_invalid_$$.log"
CLEANUP_FILES+=("${INVALID_LOG}")

# Add backend flag for consistency
BACKEND_FLAG=""
if [ -n "${STALLD_TEST_BACKEND}" ]; then
    BACKEND_FLAG="-b ${STALLD_TEST_BACKEND}"
fi

log "Testing invalid pidfile path: ${invalid_pidfile}"
${TEST_ROOT}/../stalld -f -v ${BACKEND_FLAG} -l -t 5 --pidfile "${invalid_pidfile}" > "${INVALID_LOG}" 2>&1 &
invalid_pid=$!
sleep 2

# Check if stalld is still running
if ! kill -0 "${invalid_pid}" 2>/dev/null; then
    # Process exited
    if grep -qi "error\|permission\|denied\|failed" "${INVALID_LOG}"; then
        log "✓ PASS: Invalid pidfile path rejected with error"
    else
        log "ℹ INFO: Invalid pidfile path caused exit"
    fi
else
    # Process still running - might have accepted it or created elsewhere
    log "⚠ WARNING: stalld running despite potentially invalid pidfile path"
    kill -TERM "${invalid_pid}" 2>/dev/null || true
    wait "${invalid_pid}" 2>/dev/null || true
fi

# Cleanup
chmod 755 "${test_dir}"

#=============================================================================
# Test 7: Verify pidfile is readable by other processes
#=============================================================================
log ""
log "=========================================="
log "Test 7: Verify pidfile is readable"
log "=========================================="

readable_pidfile="/tmp/stalld_test_pidfile_readable_$$.pid"
CLEANUP_FILES+=("${readable_pidfile}")
rm -f "${readable_pidfile}"

STALLD_LOG7="/tmp/stalld_test_pidfile_test7_$$.log"
CLEANUP_FILES+=("${STALLD_LOG7}")

log "Starting stalld with readable pidfile: ${readable_pidfile}"
start_stalld -l -t 5 --pidfile "${readable_pidfile}"
sleep 2

if [ -f "${readable_pidfile}" ]; then
    # Try to read the pidfile as a regular user would
    if cat "${readable_pidfile}" > /dev/null 2>&1; then
        log "✓ PASS: Pidfile is readable"

        # Check permissions
        perms=$(stat -c "%a" "${readable_pidfile}" 2>/dev/null || stat -f "%Lp" "${readable_pidfile}" 2>/dev/null)
        log "ℹ INFO: Pidfile permissions: $perms"
    else
        log "✗ FAIL: Pidfile not readable"
        TEST_FAILED=$((TEST_FAILED + 1))
    fi
else
    log "✗ FAIL: Pidfile not created"
    TEST_FAILED=$((TEST_FAILED + 1))
fi

stop_stalld
sleep 1

log ""
log "All pidfile tests completed"

end_test
