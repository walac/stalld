#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Test: CPU selection (-c/--cpu option)
# Verify stalld only monitors specified CPUs
#
# Copyright (C) 2025 Red Hat Inc

# Load test helpers
TEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${TEST_ROOT}/helpers/test_helpers.sh"

# Parse command-line options
parse_test_options "$@" || exit $?

start_test "CPU Selection (-c option)"

# Setup test environment
setup_test_environment

require_root
check_rt_throttling

# Setup log file for stalld output
STALLD_LOG="/tmp/stalld_cpu_selection_$$.log"
CLEANUP_FILES+=("${STALLD_LOG}")

# Get available CPUs
num_cpus=$(nproc)
if [ "$num_cpus" -lt 2 ]; then
    echo "SKIP: Test requires at least 2 CPUs (found: $num_cpus)"
    exit 77
fi

echo "System has $num_cpus CPUs"

# Test 1: Single CPU monitoring
echo ""
echo "Test 1: Single CPU monitoring (-c 0)"
rm -f "${STALLD_LOG}"
start_stalld_with_log "${STALLD_LOG}" -f -v -c 0 -l -t 5

# Check that stalld mentions CPU 0
if grep -q "cpu 0" "$STALLD_LOG"; then
    pass "stalld monitoring CPU 0"
else
    TEST_FAILED=$((TEST_FAILED + 1))
    echo -e "  ${RED}FAIL${NC}: stalld not monitoring CPU 0"
fi

stop_stalld

# Test 2: CPU list (comma-separated)
if [ "$num_cpus" -ge 4 ]; then
    echo ""
    echo "Test 2: CPU list monitoring (-c 0,2)"
    rm -f "${STALLD_LOG}"
    start_stalld_with_log "${STALLD_LOG}" -f -v -c 0,2 -l -t 5

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
        pass "stalld monitoring CPUs 0 and 2"
    else
        TEST_FAILED=$((TEST_FAILED + 1))
        echo -e "  ${RED}FAIL${NC}: stalld not monitoring specified CPUs (0: $cpu0_found, 2: $cpu2_found)"
    fi

    stop_stalld
else
    echo "SKIP: Test 2 requires at least 4 CPUs"
fi

# Test 3: CPU range
if [ "$num_cpus" -ge 4 ]; then
    echo ""
    echo "Test 3: CPU range monitoring (-c 0-2)"
    rm -f "${STALLD_LOG}"
    start_stalld_with_log "${STALLD_LOG}" -f -v -c 0-2 -l -t 5

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
        pass "stalld monitoring CPUs 0-2"
    else
        TEST_FAILED=$((TEST_FAILED + 1))
        echo -e "  ${RED}FAIL${NC}: stalld not monitoring specified CPU range (0: $cpu0_found, 1: $cpu1_found, 2: $cpu2_found)"
    fi

    stop_stalld
else
    echo "SKIP: Test 3 requires at least 4 CPUs"
fi

# Test 4: Combined format (list and range)
if [ "$num_cpus" -ge 6 ]; then
    echo ""
    echo "Test 4: Combined format (-c 0,2-4)"
    rm -f "${STALLD_LOG}"
    start_stalld_with_log "${STALLD_LOG}" -f -v -c 0,2-4 -l -t 5

    # Should monitor CPUs 0, 2, 3, 4
    monitored_cpus=0
    for cpu in 0 2 3 4; do
        if grep -q "cpu $cpu" "$STALLD_LOG"; then
            ((monitored_cpus++))
        fi
    done

    if [ "$monitored_cpus" -eq 4 ]; then
        pass "stalld monitoring combined CPU specification (0,2-4)"
    else
        TEST_FAILED=$((TEST_FAILED + 1))
        echo -e "  ${RED}FAIL${NC}: stalld not monitoring all specified CPUs (found $monitored_cpus/4)"
    fi

    stop_stalld
else
    echo "SKIP: Test 4 requires at least 6 CPUs"
fi

# Test 5: Invalid CPU number (should handle gracefully)
echo ""
echo "Test 5: Invalid CPU number (-c 999)"
invalid_cpu=999

# Create temporary log file for this specific test
INVALID_LOG="/tmp/stalld_invalid_cpu_$$.log"
CLEANUP_FILES+=("${INVALID_LOG}")

# Run stalld with invalid CPU and capture output
timeout 5 "${TEST_ROOT}/../stalld" -f -v -c $invalid_cpu -l -t 5 > "${INVALID_LOG}" 2>&1
ret=$?

if [ $ret -ne 0 ] && [ $ret -ne 124 ]; then
    pass "stalld rejected invalid CPU number"
else
    log "✗ FAIL: stalld did not reject invalid CPU"
    TEST_FAILED=$((TEST_FAILED + 1))
fi

# Test 6: Verify non-selected CPUs are NOT monitored
if [ "$num_cpus" -ge 2 ]; then
    echo ""
    echo "Test 6: Verify non-selected CPUs not monitored (-c 0)"
    rm -f "${STALLD_LOG}"
    start_stalld_with_log "${STALLD_LOG}" -f -v -c 0 -l -t 5

    # Check that CPU 1 is NOT mentioned (or mentioned as "not monitoring")
    if ! grep -q "cpu 1" "$STALLD_LOG" || grep -q "not monitoring.*cpu 1" "$STALLD_LOG"; then
        pass "stalld not monitoring non-selected CPU 1"
    else
        TEST_FAILED=$((TEST_FAILED + 1))
        echo -e "  ${RED}FAIL${NC}: stalld appears to be monitoring CPU 1 when only CPU 0 selected"
    fi

    stop_stalld
fi

end_test
