#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Test: Log-only mode (-l/--log_only)
# Verify stalld detects starvation but doesn't boost with -l flag
#
# Copyright (C) 2025 Red Hat Inc

# Load test helpers
TEST_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${TEST_ROOT}/helpers/test_helpers.sh"

# Parse command-line options
parse_test_options "$@" || exit $?

start_test "Log-only Mode"

# Require root for this test
require_root

# Check RT throttling
if ! check_rt_throttling; then
	echo -e "${YELLOW}SKIP: RT throttling must be disabled for this test${NC}"
	exit 77  # autotools SKIP exit code
fi

# Pick a CPU for testing
TEST_CPU=$(pick_test_cpu)
echo "Using CPU ${TEST_CPU} for testing"

# Test: stalld with -l should log starvation but not boost

# Create a temp log file for stalld output
LOG_FILE="/tmp/stalld_test_log_only_$$.log"
CLEANUP_FILES+=("${LOG_FILE}")

echo "Creating starvation on CPU ${TEST_CPU} (will run for 15 seconds)"

# Start starvation generator BEFORE stalld to ensure CPU is busy from the start
${TEST_ROOT}/helpers/starvation_gen -c ${TEST_CPU} -p 10 -n 1 -d 15 &
STARVGEN_PID=$!
CLEANUP_PIDS+=("${STARVGEN_PID}")

# Give the starvation generator time to start and monopolize the CPU
sleep 1

# Start stalld in log-only mode with verbose output to capture logs
echo "Starting stalld in log-only mode with 5 second threshold"

# Build stalld command with backend option if specified
STALLD_ARGS="-f -v -l -t 5 -c ${TEST_CPU}"
if [ -n "${STALLD_TEST_BACKEND}" ]; then
	STALLD_ARGS="-b ${STALLD_TEST_BACKEND} ${STALLD_ARGS}"
	echo "Using backend: ${STALLD_TEST_BACKEND}"
fi

${TEST_ROOT}/../stalld ${STALLD_ARGS} > "${LOG_FILE}" 2>&1 &
STALLD_PID=$!
CLEANUP_PIDS+=("${STALLD_PID}")
sleep 2

# Verify stalld is running
if ! assert_process_running "${STALLD_PID}" "stalld should be running"; then
	echo "Failed to start stalld, aborting test"
	echo "Log contents:"
	cat "${LOG_FILE}"
	end_test
	exit 1
fi
echo "stalld started with PID ${STALLD_PID}"

echo "Starvation generator started (PID ${STARVGEN_PID})"
echo "Waiting 7 seconds for starvation detection..."
sleep 7

# Check if stalld detected the starvation (should log it)
if grep -q "starved" "${LOG_FILE}"; then
	assert_equals "1" "1" "stalld detected and logged starvation"
else
	TEST_FAILED=$((TEST_FAILED + 1))
	echo -e "  ${RED}FAIL${NC}: stalld did not detect starvation"
	echo "Log contents:"
	cat "${LOG_FILE}"
fi

# Check that stalld did NOT boost (should not see "boosted" message with -l)
if ! grep -q "boosted" "${LOG_FILE}"; then
	assert_equals "1" "1" "stalld did not boost in log-only mode"
else
	TEST_FAILED=$((TEST_FAILED + 1))
	echo -e "  ${RED}FAIL${NC}: stalld boosted despite -l flag"
	echo "Log contents:"
	cat "${LOG_FILE}"
fi

# Cleanup
kill ${STARVGEN_PID} 2>/dev/null
wait ${STARVGEN_PID} 2>/dev/null
stop_stalld

echo ""
echo "Log file contents:"
echo "=================="
cat "${LOG_FILE}"
echo "=================="

end_test
